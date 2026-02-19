# Evaluation tasks =====================================================================

# This runs everytime if one of the four below is 1, but if you want to test this alone, please set it to 1
# Set to -1 if you want to skip it regardless - not recommended unless you already know the app runs normally
CHECK_RUNS_NORMALLY             = -1

# Does NOT require running the APK
HAS_TEE                         = 0
HAS_ANTI_DEBUG                  = 0
HAS_CODE_OBFUSCATION            = 0

# Requires running the APK - make sure you have a rooted device
HAS_ROOT_CHECKING               = 0
HAS_ANTI_HOOKING                = 0
HAS_ANTI_REPACKAGING            = 0
HAS_NETWORK_INTEGRITY_CHECKING  = 0

# Device and app =======================================================================

IS_DEVICE_ROOTED                = 0 # just names file with root or not

UNINSTALL_EXISTING_APP          = 0
UNINSTALL_AFTER_ANALYSIS        = 0

INSTALL_ONLY                    = 0 # These commands will ignore any eval tasks selected above.
START_ONLY                      = 0

# If the main activity cannot be detected automatically, please override it by manually entering into OVERRIDE_MAIN_ACTIVITY
# Also specify OVERRIDE_PACKAGE_NAME, so that it can be run with -d option
# Currently does not support multiple overrides, consider running them individually
OVERRIDE_MAIN_ACTIVITY  = "" #"com.google.android.apps.wallet.main.WalletActivity"
OVERRIDE_PACKAGE_NAME   = "" #"com.google.android.apps.walletnfcrel"

# Logging ==============================================================================

TF_CPP_MIN_LOG_LEVEL = "0"    # "3" = FATAL, "2" = ERROR, "1" = WARNING, "0" = INFO
TRANSFORMERS_NO_TQDM = "0"    # Hide tqdm progress bars

# Obfuscation ==========================================================================
BASE_PACKAGE_ONLY = 0

FILTER_PKGS = 0 # Hide results for packges in HIDE_LIST, but show 5 randomly selected ones from them if none found elsewhere
HIDE_LIST   = ["/android/", "/androidx/", "/kotlin/", "/kotlinx/", "/com/google/", "/com/facebook/", "/com/microsoft/"]

IR_RATIO    = 0.5  # The minumum ratio of renamed identifiers to consider the app to have identifier renaming
IR_ONLY     = 0    # Only check for identifier renaming

# Results ==============================================================================

"""
If 1, it will find the most recent results spreadsheet and skip any APKs already evaluated. 
    Alternatively, you can set it to a specific file (recommended):
    e.g. OMIT_PROCESSED = "results_2025-05-08_201339.xlsx"
It is assumed that the evaluation config above and APK paths did not change.
Only works when -d is used and not -f.

If 0, re-evaluate all APKs.
"""
OMIT_PROCESSED  = 0
SAVE_TO_OMIT_PROCESSED_FILE = OMIT_PROCESSED # saves results to same file as the one used in OMIT_PROCESSED

# Repackaging ==========================================================================

FORCE_REPACK    = 0     # create the repacked app even if it exists
REPACK_ONLY     = 0     # skip testing if it the repacked APK can run normally

# TEE ==================================================================================

# !!!!!! WARNING !!!!!! 
# TEE_GREP is orders of magnitudes faster than TEE_SOOT, but may be slightly less precise
# For 100 apps, TEE_GREP finishes in under 5 minutes, while TEE_SOOT took over 5 hours, with many timing out after 10 minutes

TEE_GREP        = 0     # grep search for TEE related classes and methods in jadx-decompiled code, does not guarantee that the methods found are from the TEE classes, but are likely to be
TEE_SOOT        = 1     # use Soot to check if found methods are actually from TEE related classes