import os
import socket


# file paths
INPUT_PATH = "./input"
OUTPUT_PATH = "./output"
APK_PATH = "./apks"
MERGED_APK_PATH = os.path.join(APK_PATH, "merged")
TEE_STDERR_PATH = os.path.join(OUTPUT_PATH, "tee_stderr")
JADX_DECOMPILE_OUTPUT_PATH = os.path.join(OUTPUT_PATH, "decompiled_jadx")
IDENTIFIERS_OUTPUT_PATH = os.path.join(OUTPUT_PATH, "identifiers")
JEB_DECOMPILE_OUTPUT_PATH = os.path.join(OUTPUT_PATH, "decompiled_JEB")
DROIDBOT_OUTPUT_PATH = os.path.join(OUTPUT_PATH, "droidbot")

DEPENDENCIES_PATH = "./dependencies"
JEB_ROOT_PATH = os.path.join(DEPENDENCIES_PATH, "jeb")
JEB_RUN_PATH = os.path.join(JEB_ROOT_PATH, "jeb_linux.sh")
JEB_DECOMPILE_SCRIPT_PATH = os.path.join(JEB_ROOT_PATH, "scripts/samples/DecompileFileByChecker.py")

SIGNER_PATH = os.path.join(DEPENDENCIES_PATH, "uber-apk-signer-1.3.0.jar")

MITM_CERT_PATH = os.path.join(INPUT_PATH, "mitmproxy-ca-cert.cer")
HASHED_MITM_CERT_PATH = os.path.join(INPUT_PATH, "c8750f0d.0")
ANDROID_SYSTEM_STORE_PATH = "/system/etc/security/cacerts/"
ANDROID_USER_STORE_PATH = "/data/misc/user/0/cacerts-added/"

# TEE
TEE_KEYWORDS = {
            "isInsideSecureHardware": "android.security.keystore.KeyInfo",
            "getSecurityLevel": "android.security.keystore.KeyInfo",
            "WrappedKeyEntry": "android.security.keystore.WrappedKeyEntry"
        } # TRUE CONSTANT

PAYMENT_PKGS = [
            "mastercard",
            "visa",
            "stripe",
            "juspay",
            "lyra"
            "tap.checkout",
            "felix",
            "fiserv",
            "worldline",
            "adyen",
            "com.google.android.gms.wallet",
            "com.samsung.android.spayfw",
            "paytm",
            "globalpayments",
            "nexi.xpay",
            # "square" # seems to be terminal side
]

# obfuscation
OBF_KEYWORDS = {
            "String Encryption": "// This method contains decrypted strings",
            "Control-Flow": "// This method was un-flattened",
            "Virtualization": "// This method was un-virtualized",
            "Reflection": "// This method contains unreflected code",
        }

IR = "IR"
SE = "SE"
CF = "CF"
VT = "VT"
RF = "RF"

OBF_ABBREV = {
            "String Encryption": SE,
            "Control-Flow": CF,
            "Virtualization": VT,
            "Reflection": RF,
        }

SHORT_WORDS_THRESHOLD = 2.5

# loguru
LOG_LEVEL = "INFO"
LOG_DIR_PATH = os.path.join(OUTPUT_PATH, "logs")

# rich
LABEL = "TASK"
STYLE = "white"

# apk-mitm
APK_MITM_TAG = "-patched.apk" # TRUE CONSTANT

# network
# The following are URLs of API calls made on device start up (waited over an hour) of AVD Pixel_4_API_29_* and are likely not called by apps.
URLS_ON_LAUNCH = ['accounts.google.com',
                 'android.apis.google.com',
                 'android.clients.google.com',
                 'android.googleapis.com',
                 'clients4.google.com',
                 'cloudconfig.googleapis.com',
                 'cryptauthenrollment.googleapis.com',
                 'deviceintegritytokens-pa.googleapis.com',
                 'firebaseperusertopics-pa.googleapis.com',
                 'footprints-pa.googleapis.com',
                 'g.tenor.com',
                 'googleads.g.doubleclick.net',
                 'gstatic.com',
                 'gvt2.com',
                 'i.ytimg.com',
                 'mail.google.com',
                 'mobiledataplan-pa.googleapis.com',
                 'notifications-pa.googleapis.com',
                 'people-pa.googleapis.com',
                 'play-fe.googleapis.com',
                 'play.googleapis.com',
                 'playatoms-pa.googleapis.com',
                 'securitydomain-pa.googleapis.com',
                 'semanticlocation-pa.googleapis.com',
                 'update.googleapis.com',
                 'userlocation.googleapis.com',
                 'video.google.com',
                 'www.google.com',
                 'www.googleadservices.com',
                 'www.googleapis.com',
                 'youtube.com',
                 'youtubei.googleapis.com'] # TRUE CONSTANT

UNTRUSTED_CERT_ERROR = "The client does not trust the proxy's certificate" # TRUE CONSTANT
POTENTIAL_UNTRUSTED_CERT_ERROR = "this may indicate that the client does not trust the proxy's certificate" # TRUE CONSTANT

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

IP = get_local_ip()
# print(f"IP: {IP}")
PORT = 8080
LISTEN_HOST = "0.0.0.0"

MITMDUMP_COLLECTION_DURATION = 10

# manifest
DEBUGGABLE_ATTRIB = "{http://schemas.android.com/apk/res/android}debuggable" # TRUE CONSTANT

# results 
RUNS_NORMALLY = "RUNS_NORMALLY" # TRUE CONSTANT

HAS_TEE = "HAS_TEE" # TRUE CONSTANT
HAS_ANTI_DEBUG = "HAS_ANTI_DEBUG" # TRUE CONSTANT
HAS_CODE_OBFUSCATION = "HAS_CODE_OBFUSCATION" # TRUE CONSTANT
HAS_ROOT_CHECKING = "HAS_ROOT_CHECKING" # TRUE CONSTANT
HAS_ANTI_HOOKING = "HAS_ANTI_HOOKING" # TRUE CONSTANT
HAS_ANTI_REPACKAGING = "HAS_ANTI_REPACKAGING" # TRUE CONSTANT
HAS_NETWORK_INTEGRITY_CHECKING = "HAS_NETWORK_INTEGRITY_CHECKING" # TRUE CONSTANT

RESULTS_DIR_PATH = os.path.join(OUTPUT_PATH, "results")
RESULTS_FILE_NAME = "results"
RESULTS_FILE_EXT = "xlsx"
RESULTS_APK_PATH_KEY = "APK_path"
RESULTS_APK_NAME_KEY = "APK_name"

# droidbot tasks
ROOT_CHECKING_TASK = HAS_ROOT_CHECKING # TRUE CONSTANT
RUNS_NORMALLY_TASK = "_runs_normally" # TRUE CONSTANT
HAS_CRASHED_TASK = "_has_crashed" # TRUE CONSTANT

# droidbot queries - queries should be designed such that droidbot stops when DroidBotRunner.result is detected as True
def _get_query(instruction):
    return f'''The following text is extracted from a View or Toast. Does the message say or suggest that the app {instruction}? Just say "yes" or "no" and nothing else. If you do not understand the language, say "no".'''
HAS_ROOT_CHECKING_QUERY = _get_query("has detected a rooted device or in general an insecure state") # TRUE CONSTANT
IS_NORMAL_OP_QUERY = _get_query("is not running normally")#_get_query("is not running normally") # TRUE CONSTANT 
HAS_CRASHED_QUERY = _get_query("is crashing or has crashed")#_get_query("is not running normally") # TRUE CONSTANT  

KEEPS_STOPPING = "keeps stopping"

DROIDBOT_TARGETS = {ROOT_CHECKING_TASK: HAS_ROOT_CHECKING_QUERY, RUNS_NORMALLY_TASK: IS_NORMAL_OP_QUERY, HAS_CRASHED_TASK: KEEPS_STOPPING} # TRUE CONSTANT

# classifier
MODEL = "meta-llama/Llama-3.2-3B-Instruct" # try meta-llama/Llama-3.2-1B-Instruct if 3B cannot fit on GPU
RESPONSE_MAP = {"yes": True, "no": False} # TRUE CONSTANT

# adb
ADB_ERROR_TAG = "adb: error: " # TRUE CONSTANT

# Frida
FRIDA_SERVER_ALRDY_RUNNING_ERROR = "Address already in use" # TRUE CONSTANT
FRIDA_SERVER_TAG = "frdasrvr" # You must rename any frida servers to include frdasrvr in the file name # TRUE CONSTANT
MAX_RESTARTS = 2  
HOOK_TIMEOUT = 5
FRIDA_SERVER = "frdasrvr-16.1.11-arm"
HOOK_SUCCESS_TAG = "Hooked onCreate overload with args" # TRUE CONSTANT

# signer for repackaging
KS_FILE = os.path.join(INPUT_PATH, "xample.keystore")
KS_PASSWORD = "" # Put your password here
KS_ALIAS = "" # Put your alias here

# lines
THIN_LINE = "-" * 145
THICK_LINE = "=" * 148

 
 