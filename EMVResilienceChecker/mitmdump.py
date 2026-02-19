import os
import sys
import json
import shutil
import asyncio
import logging
import subprocess

from androguard.util import set_log
from multiprocessing import Process, Pipe
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy import http
from pprint import pprint as pp
from loguru import logger
from mitmproxy import tcp
from util import adb_action

from constants import MITMDUMP_COLLECTION_DURATION
from constants import ANDROID_SYSTEM_STORE_PATH
from constants import ANDROID_USER_STORE_PATH
from constants import HASHED_MITM_CERT_PATH
from constants import URLS_ON_LAUNCH
from constants import LISTEN_HOST
from constants import PORT
from constants import IP

class MitmCertManager:

    def __init__(self, system_store=False):
        MitmCertManager._check_prereq()

        self.source_path = HASHED_MITM_CERT_PATH 

        if system_store:
            self.target_path = ANDROID_SYSTEM_STORE_PATH
        else:
            self.target_path = ANDROID_USER_STORE_PATH

        self.target_path = os.path.join(self.target_path, os.path.basename(HASHED_MITM_CERT_PATH))

        # maybe add a check so we do not push each time or install global http each time, but the cost of pushing/installing is minimal so it's not really important
           
    @staticmethod
    def get_cert_hash_name(cert_path): 
        """
        USE THIS FUNC TO GET HASHED CERT NAME IN main(), THEN SET IT AS THE CERT PATH IN constants.py
        Returns something like {hash[8:]}.0, which then can be copied in the system and user stores
        """
        result = subprocess.run(["openssl", "x509", "-in", cert_path, "-subject_hash_old", "-noout"], 
                                capture_output=True, 
                                text=True)
        if result.stderr:
            return None
        return f"{result.stdout.strip()}.0"

    @staticmethod
    def _check_prereq():
        if not shutil.which("openssl"):
            raise EnvironmentError("OpenSSL is not installed or not in PATH, cannot setup mitmdump.")

    def push_cert(self):
        return adb_action(["adb", "push", self.source_path, self.target_path], "adb push")

    def remove_cert(self):
        return adb_action(["adb", "shell", "rm", self.target_path], "adb rm")

    def install_global_http(self):
        return adb_action(["adb", "shell", "settings", "put", "global", "http_proxy", IP, str(PORT)], "Installing global http settings")

    def delete_global_http(self):
        status = True
        settings = ["http_proxy", 
                    "global_proxy_pac_url",
                    "global_http_proxy_host",
                    "global_http_proxy_port",
                    "global_http_proxy_exclusion_list"]

        for setting in settings:            
            if not adb_action(["adb", "shell", "settings", "delete", "global", "settings"], "Delete global http settings"):
                status = False
        return status
                                    
class NetworkIntegrityChecker:
    def __init__(self):
        self.servers = {}

    def _fetch_urls_on_launch():
        URLS_ON_LAUNCH.append(server_connection.server.address[0])
        print("Updated URLS_ON_LAUNCH:")
        pp(sorted(URLS_ON_LAUNCH))

    def server_connected(self, server_connection):
        if any(url in server_connection.server.address[0] for url in URLS_ON_LAUNCH):
            return
        logger.debug(f"SERVER CONNECTED: {server_connection}")

        # _fetch_urls_on_launch()

        self.servers[server_connection.server.address[0]] = {"error":server_connection.client.error, "url": server_connection.server.address[0], "type":"connect", "client_tls_established": server_connection.client.tls_established}

    def server_disconnected(self, server_connection):
        if any(url in server_connection.server.address[0] for url in URLS_ON_LAUNCH):
            return
        logger.debug(f"SERVER DISCONNECTED: {server_connection}")
        
        self.servers[server_connection.server.address[0]] = {"error":server_connection.client.error, "url": server_connection.server.address[0], "type":"disconnect", "client_tls_established": server_connection.client.tls_established}
        
        e = server_connection.client.error
        if e:
            logger.debug(f"DISCONNECTION DUE TO ERROR: {e}")
            # self.disconnect_list.append(e)

class MitmDump:
    def __init__(self):                             
        logging.basicConfig(level=logging.ERROR)    # MITMDUMP LOGGING
        self.mitmdump = None
        self.nic = NetworkIntegrityChecker()
        self.test_dict = {
                            "user": {
                                "id": 101,
                                "name": "Alice",
                                "roles": ["admin", "editor"],
                                "preferences": {
                                    "theme": "dark",
                                    "notifications": {
                                        "email": True,
                                        "sms": False
                                    }
                                }
                            },
                            "project": {
                                "name": "Network Analysis",
                                "tools": ["gnirehtet", "mitmproxy", "mitm_dump"],
                                "status": "active"
                            }
                        }

    async def start(self):
        opts = Options(listen_host=LISTEN_HOST, listen_port=int(PORT))

        self.mitmdump = DumpMaster(opts)
        self.mitmdump.addons.add(self.nic)

        try:
            await self.mitmdump.run()
        except KeyboardInterrupt:
            self.stop()
        finally:
            return self.nic.servers

    def stop(self):
        if self.mitmdump:
            self.mitmdump.shutdown()

class PipeWriter:
    def __init__(self, conn):
        self.conn = conn
        self.is_tty = sys.__stdout__.isatty()

    def write(self, msg):
        if msg.strip():             # Avoid sending empty messages
            self.conn.send(msg)     # Send output immediately

    def flush(self):
        pass                        # Required for sys.stdout compatibility

    def isatty(self):                
        return self.is_tty

def worker(conn):
    try: 
        sys.stdout = open(os.devnull, 'w')
        mitmdump = MitmDump()
        async def run_with_timeout():
            return await asyncio.wait_for(mitmdump.start(), timeout=MITMDUMP_COLLECTION_DURATION)        
        asyncio.run(run_with_timeout())
    except Exception as e:
        print(e)
    finally:
        sys.stdout.close()   
        sys.stdout = sys.__stdout__ 
        conn.send(mitmdump.nic.servers) 
        conn.close()

def intercept(init=None, finalize=None):
        if init:
            init()

        logger.info(f"Collecting TLS connection attempts during the first {MITMDUMP_COLLECTION_DURATION}s of app startup...")
        parent_conn, child_conn = Pipe()
        p = Process(target=worker, args=(child_conn,))
        p.start()
        server_conns = parent_conn.recv()  # Blocks until worker sends data or pipe closes
        p.join()

        if finalize:
            finalize()

        # print("Received from child:")
        # pp(server_conns)

        return server_conns

if __name__ == "__main__":

    def test_setup():
        from constants import MITM_CERT_PATH
        m = MitmCertManager(system_store=False)
        result = m.push_cert()
        m.remove_cert()

    def get_cert_hash_name():
        from constants import MITM_CERT_PATH # replace this with your own cert as needed
        hashed_cert_name = m.get_cert_hash_name(MITM_CERT_PATH)
        print(f"Rename the cert to: {hashed_cert_name}")

    # for i in range(2):
    #     start_proxy()
    # test_setup()
    # get_cert_hash_name()


# ==============================================================================================
"""
### **Why Mitmproxy Must Temporarily Disconnect the Client When Connecting to the Server**

Mitmproxy must temporarily pause or disconnect the client during the TLS handshake process to fulfill its role as a man-in-the-middle (MITM) proxy. This behavior stems from the **sequential nature of TLS handshakes** and the **cryptographic requirements** for intercepting HTTPS traffic. Here's a breakdown from a networking perspective:

---

#### **1. TLS Handshake Requires Immediate Certificate Exchange**
- **Client Initiation**: When a client initiates an HTTPS connection, it sends a `ClientHello` message during the TLS handshake, specifying supported protocols and cipher suites.
- **Server Response**: The server responds with a `ServerHello`, its certificate, and other TLS parameters. The client validates the server's certificate before proceeding.

**Mitmproxy's Challenge**:
- To intercept traffic, mitmproxy must present a valid certificate to the client that matches the server’s domain (e.g., `epmobile.app`).
- However, mitmproxy cannot generate this certificate until it knows the server’s certificate details (e.g., Common Name, Subject Alternative Names).

---

#### **2. Upstream Certificate Sniffing**
Mitmproxy uses **upstream certificate sniffing** to dynamically generate valid dummy certificates:
1. **Pause Client Connection**:
   - When the client sends a `CONNECT` request (for explicit proxying) or initiates a TLS handshake (for transparent proxying), mitmproxy pauses the client’s connection.
2. **Connect to the Server**:
   - Mitmproxy establishes a separate TLS connection to the server to retrieve its certificate.
3. **Generate Dummy Certificate**:
   - Using the server’s certificate details, mitmproxy generates a dummy certificate signed by its own Certificate Authority (CA).
4. **Resume Client Handshake**:
   - Mitmproxy resumes the paused client connection and presents the dummy certificate.

**Networking Constraint**:
- The TLS handshake is sequential. The client expects an immediate certificate after sending `ClientHello`. Mitmproxy cannot delay this step without first obtaining the server’s certificate details.

---

#### **3. Managing Two Separate Connections**
- **Client-Side TCP Connection**:
  - Mitmproxy accepts the client’s TCP connection and receives the TLS handshake initiation.
- **Server-Side TCP Connection**:
  - Mitmproxy establishes a new TCP connection to the server to fetch its certificate.
- **Synchronization**:
  - These two connections are independent. Mitmproxy must temporarily halt the client’s handshake until it completes the server-side connection and certificate retrieval.

---

#### **4. Cryptographic Validation**
- **Server Certificate Chain**:
  - The server’s certificate chain (root → intermediate → server) must be validated to generate a trustworthy dummy certificate.
  - Mitmproxy cannot proceed with the client handshake until it confirms the server’s certificate details (e.g., domain name, expiration).

---

#### **5. Preventing Protocol Errors**
If mitmproxy forwarded the client’s TLS handshake directly to the server:
- The client would encrypt data with the server’s public key, which mitmproxy cannot decrypt (lacking the server’s private key).
- This would render mitmproxy unable to inspect or modify traffic, defeating its purpose.

---

### **Summary: The Fundamental Networking Reason**
Mitmproxy must temporarily disconnect the client to:
1. **Fetch the server’s certificate** and generate a valid dummy certificate.
2. **Synchronize two independent TCP connections** (client ↔ proxy and proxy ↔ server).
3. **Adhere to the TLS handshake sequence**, which requires immediate certificate exchange.

Without this pause, mitmproxy could not dynamically generate certificates or decrypt traffic, making interception impossible. This design ensures mitmproxy can inspect and modify HTTPS traffic while maintaining the integrity of the TLS protocol. 

For more details, see [mitmproxy’s documentation on TLS interception](https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/).

Citations:
[1] https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/
[2] https://docs.mitmproxy.org/stable/api/mitmproxy/tls.html
[3] https://docs.mitmproxy.org/stable/concepts-certificates/
[4] https://www.koyeb.com/blog/inspect-tls-encrypted-traffic-using-mitmproxy-and-wireshark
[5] https://github.com/mitmproxy/mitmproxy/discussions/4912
[6] https://github.com/mitmproxy/mitmproxy/discussions/7082
[7] https://stackoverflow.com/questions/75016708/python-3-mitmproxy-set-tls-signature-algorithms-for-server
[8] https://www.youtube.com/watch?v=7BXsaU42yok
[9] https://security.stackexchange.com/questions/149250/is-it-possible-to-mitm-tls-without-maintaining-connection-between-proxy-and-remo
[10] https://www.rapidseedbox.com/blog/mitmproxy

---
Answer from Perplexity: https://www.perplexity.ai/search/python-regex-to-match-strings-g_o8PoxVRjqjMav66kuMzA?1=d&3=d&utm_source=copy_output
"""