import subprocess
import os
import time
import psutil

from util import adb_action
from loguru import logger

from constants import FRIDA_SERVER_ALRDY_RUNNING_ERROR
from constants import FRIDA_SERVER_TAG
from constants import MAX_RESTARTS
from constants import INPUT_PATH

class FridaRunner:

    """Runs Frida Server on Android phone"""

    def __init__(self, server):

        self.server = server

        self.frida_local_path = os.path.join(INPUT_PATH, self.server)
        self.frida_device_path = f"/data/local/tmp/{self.server}"

        if not self._is_server_on_device() and not self._push_frida():
            logger.warning("Could not push Frida to device")
            return

        self.frida_proc = None

        self.curr_restarts = 0

    def start(self):

        if self.frida_proc or self.is_server_started():
            logger.info(f"Our Frida server is already running: {self.server}")
            return

        self.frida_proc = subprocess.Popen(["adb", "shell", "su", "-c", f"/data/local/tmp/{self.server}", "&"],  
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        stdin=subprocess.PIPE)
        time.sleep(0.5)

        if self.frida_proc.poll() is not None:
            stdout, stderr = self.frida_proc.communicate()
            stderr = stderr.decode().strip()
            logger.warning(f"Frida server did not start properly: {stderr}")
            if "Permission denied" in stderr:
                logger.info("*** Possible solutions ***")
                logger.info("Open Magisk, click on Superuser, and enable '[SharedUID] Shell'")
                logger.info("Try running: " + " ".join(["adb", "shell", "su", "-c", "chmod", "+x", self.frida_device_path]))
                exit()
            self.stop()

            if FRIDA_SERVER_ALRDY_RUNNING_ERROR in stderr:
                port = stderr.split(":")[2]
                self.kill_by_port(port)

            if self.curr_restarts < MAX_RESTARTS:
                logger.info("Retrying")
                self.curr_restarts += 1
                self.start()
            else:
                logger.warning("Max retries reached, exiting")

            return 

        logger.info("Frida server started")



    def stop(self):
        if self.frida_proc:
            self.frida_proc.terminate()
            self.frida_proc = None
            logger.info("Frida server terminated")
        else:
            logger.info("We did not start the server, so we will not terminate it")

    def kill_by_port(self, port):
        """Terminate all processes on the device that contains the strings 'frida' or FRIDA_SERVER_TAG ('frdaserver') but for a given port"""
        try:
            result = subprocess.run(["adb", "shell", "netstat", "-antp", "|", "grep", port], capture_output=True, text=True)
            processes = result.stdout.splitlines()
            pids_to_kill = []

            for process in processes:
                if FRIDA_SERVER_TAG in process or "frida" in process:
                    parts = process.split()
                    pid = parts[-1].split("/")[0]
                    pids_to_kill.append(pid)
                else:
                    logger.warning("Port being used by unexpected process")
                    logger.warning(process)

            for pid in pids_to_kill:
                if not adb_action(['adb', 'shell', 'kill', '-9', pid], "Kill pid"):
                    logger.warning(f"Frida server running on pid {pid} was not killed")
                    continue
                logger.info(f"Killed pid {pid}")

        except Exception as e:
            logger.warning(f"Could not kill Frida server(s) by port: {e}")

    def kill_others(self):
        """Terminate all processes on the device that contains the strings 'frida' or FRIDA_SERVER_TAG ('frdaserver')"""
        try:
            result = subprocess.run(["adb", "shell", "ps", "|", "grep", "-E", f"'frida|{FRIDA_SERVER_TAG}'"], capture_output=True, text=True)
            processes = result.stdout.splitlines()
            pids_to_kill = []

            for process in processes:
                if self.server not in process:
                    pid = process.split()[1]
                    pids_to_kill.append(pid)

            for pid in pids_to_kill:
                if not adb_action(['adb', 'shell', 'kill', '-9', pid], "Kill pid"):
                    logger.warning(f"Frida server running on pid {pid} was not killed")
                    continue
                logger.info(f"Killed pid {pid}")

        except Exception as e:
            logger.warning(f"Could not kill Frida server(s): {e}")

    def show_frida_processes(self):
        try:
            result = subprocess.run(["adb", "shell", "su", "-c", "ps", "|", "grep", "-E", f"'frida|{FRIDA_SERVER_TAG}'"], capture_output=True, text=True)
            processes = result.stdout.splitlines()
            for process in processes:
                print(process)

        except Exception as e:
            logger.warning(f"Could not find Frida server(s): {e}")

    def is_server_started(self):
        try:
            result = subprocess.run(["adb", "shell","su", "-c", "ps", "|", "grep", "-E", self.server], capture_output=True, text=True)
            processes = result.stdout.splitlines()
            for process in processes:
                if self.server in process:
                    return True
            return False

        except Exception as e:
            logger.warning(f"Could not find Frida server(s): {e}")
            return False

    def _is_server_on_device(self):
        return subprocess.run(["adb", "shell", "su", "-c", "ls", self.frida_device_path], capture_output=True, text=True).stdout.strip() == self.frida_device_path

    def _push_frida(self):
        return (adb_action(["adb", "push", self.frida_local_path, self.frida_device_path], "Push frida server to device") and \
                adb_action(["adb", "shell", "su", "-c", "chmod", "+x", self.frida_device_path], "chmod frida server"))

         
if __name__ == "__main__":
    
    f = FridaRunner("frdasrvr-16.1.11-arm")
    # f.kill_others()
    # f.start()
    # f.show_frida_processes()
    # time.sleep(3)
    # f.stop()

