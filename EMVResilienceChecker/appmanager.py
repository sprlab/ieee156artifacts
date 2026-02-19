import os
import time
import glob
import shutil
import subprocess

from androguard.core.apk import APK
from device import Device
from util import run_cmd
from util import wait_until
from loguru import logger

from constants import APK_PATH
from constants import MERGED_APK_PATH
from constants import OUTPUT_PATH
from constants import JEB_RUN_PATH
from constants import APK_MITM_TAG
from constants import JEB_DECOMPILE_SCRIPT_PATH
from constants import JEB_DECOMPILE_OUTPUT_PATH
from constants import JADX_DECOMPILE_OUTPUT_PATH

from config import FORCE_REPACK
from config import OVERRIDE_MAIN_ACTIVITY
from config import OVERRIDE_PACKAGE_NAME

class AppManager:
    """Class for managing APK installation, running, and updates using instance variables"""

    def __init__(self, apk_path, tag=None):
        self.base_apk_dir_path = None
        self.split_apks = None
        self.merged_apk = None
        if not apk_path.endswith(".apk"):
            apks = [apk for apk in os.listdir(apk_path) if apk != "base.apk" and apk != "base-patched.apk"]
            self.split_apks = [os.path.join(apk_path, apk) for apk in apks] if len(apks) > 0 else None
            if self.split_apks:
                self.base_apk_dir_path = apk_path
            merged_apk = os.path.join(MERGED_APK_PATH, os.path.basename(os.path.normpath(apk_path))+".apk")
            if os.path.exists(merged_apk):
                self.merged_apk = merged_apk
            apk_path = os.path.join(apk_path,"base.apk")

        self.apk_path = apk_path                                                    # original chosen apk
        self.apk_mitm_patched_path = self.apk_path.replace(".apk", APK_MITM_TAG)    # apk-mitm always outputs to same folder as input apk, unless we copy them over ourseles
        
        self.apk = APK(apk_path)
        self.package_name = self.apk.get_package()
        self.main_activity = OVERRIDE_MAIN_ACTIVITY if OVERRIDE_MAIN_ACTIVITY and self.package_name == OVERRIDE_PACKAGE_NAME else self.apk.get_main_activity() 
        self.version = self.apk.get_androidversion_name()

        self.output_apk_path = os.path.join(APK_PATH, self.package_name)
        if FORCE_REPACK:
            if os.path.exists(self.output_apk_path):
                shutil.rmtree(self.output_apk_path)
            os.makedirs(self.output_apk_path)
        self.repacked_and_signed_apk_path = os.path.join(self.output_apk_path, f"{ os.path.splitext(os.path.basename(self.apk_path))[0]}-repacked-aligned-signed.apk") # repacked during _has_anti_repackaging
       
        self.tag = tag

        self.decompiled_apk_path_jadx = os.path.join(JADX_DECOMPILE_OUTPUT_PATH, self.package_name)
        self.decompiled_apk_path_jeb = os.path.join(JEB_DECOMPILE_OUTPUT_PATH, self.package_name)

        self.skip_alt_start = False

    def install(self, apk_to_install=None):

        if self.is_installed():
            logger.info("APK already installed. Skipping installation.")
            return True

        if not self.disable_verifier():
            return False

        if not apk_to_install:
            apk_to_install = self.apk_path

            if self.base_apk_dir_path:
                apk_to_install = sorted(glob.glob(f"{self.base_apk_dir_path}/*.apk"))

        result = None
        if isinstance(apk_to_install, str): # single app
            result = run_cmd(['adb', 'install', apk_to_install])
        elif isinstance(apk_to_install, list):
            logger.info("Installing split APK, this may take a few seconds...")
            t = 60
            try:
                result = run_cmd(['adb', 'install-multiple'] + apk_to_install, timeout=t)
            except subprocess.TimeoutExpired:
                logger.warning(f"adb install-multple timed out after {t}s, trying again")
                self.install() # WARNING: although very unlikely, this may cause infinite recursion

        if result.stderr:
            return False
        else:
            logger.info("APK successfully installed.")
            return True

    def is_installed(self):
        result = run_cmd(['adb', 'shell', 'pm', 'list', 'packages', self.package_name])

        return f"package:{self.package_name}" in result.stdout

    def disable_verifier(self):
        result = run_cmd(["adb", "shell", "settings", "put", "global", "package_verifier_enable", "0"])

        if result.stderr:
            return False
        else:
            return True

    def uninstall(self):
        if self.is_installed():
            result = run_cmd(['adb', 'uninstall', self.package_name])

            if result.stderr:
                logger.error(result.stderr)
                return False
            else:
                logger.info("APK successfully uninstalled.")
                return True
        else:
            logger.info("App not installed, skipping uninstall")
            return True

    def auto_update(self, x, y):
        logger.critical("TODO: need to handle case where the app cannot be installed and an alert box is shown")
        Device.tap(x, y)

        old_version = self.version

        def do():       
            return Device.is_button_clickable(Device.get_ui_xml(), "Open")

        if not wait_until(do,timeout=500): 
            return False

        return True

        # Device.pull_apk(self.package_name, self.updated_apk_path)

        # logger.debug(f"Should differ: previous={old_version}, current={self.version}")
        
        # if self.version == old_version:
        #     logger.error("Auto-update was NOT successful. Please try it manually.")
        #     return False

        # logger.success("Auto-update successful.")
        # return True

    def manual_update(self):
        """Handles manual update process"""
        user_input = input("Running manual update. Type 'updated' once app is updated or 'exit' to stop the program: ").strip().lower()

        if user_input == "updated":
            if not self.is_updated():  # user typed updated but app not actually updated
                self.manual_update()
        elif user_input == "exit":
            logger.info("Exiting...")
            exit(0)
        else:
            self.manual_update()

    def update_app_via_play_store(self):
        """Performs app update if needed"""
        center = self.has_update()
        if not center:
            logger.info("No update available.")
            return

        # Let's not allow manual update's for now
        # if not self.auto_update(center[0], center[1]):
        #     self.manual_update()

        return self.auto_update(center[0], center[1]) 

    def has_update(self):
        """
        Checks if app has an update by checking app store button. Either is "Update" (True) or "Open" (False). 
        True: returns center coordinates x,y of button
        False: returns None, None
        """

        app_store_ui = Device.open_in_play_store(self.package_name) # this needs updating

        if not app_store_ui: 
            return None

        return Device.get_center(app_store_ui, "Install") or Device.get_center(app_store_ui, "Update")
       
    def start(self):
        """Start the app using its package name and main activity"""

        Device.tap_home()

        # print('adb', 'shell', 'am', 'start', '-n', f"{self.package_name}/{self.main_activity}")
        run_cmd(['adb', 'shell', 'am', 'start', '-n', f"{self.package_name}/{self.main_activity}"])

    def stop(self):
        """Stop the app using its package name"""

        run_cmd(['adb', 'shell', 'am', 'force-stop', f"{self.package_name}"])
        Device.tap_home()

    def is_running(self):
        """Check if the app is running"""
        """Process may be alive but app may close/minimze"""
        result = run_cmd(["adb", "shell", "pidof", self.package_name])

        if result.stderr:
            logger.error(result.stderr)

        pid = result.stdout.strip()

        if pid:
            logger.info(f"App is running with PID: {pid}")
            return True
        else:
            return False


    def is_app_in_foreground(self):
        result = subprocess.run(
            ["adb", "shell", "dumpsys", "window", "windows"],
            stdout=subprocess.PIPE,
            text=True
        )
        return self.package_name in result.stdout

    def app_launched(self):
        logger.info("Waiting for app to come to foreground...")
        for _ in range(15):
            if self.is_app_in_foreground():
                logger.info("App is in foreground")
                break
            time.sleep(1)
        else:
            logger.warning("App never came to foreground")
            return False

        logger.info("Monitoring if app stays in foreground...")
        time.sleep(5)
        if not self.is_app_in_foreground():
            logger.info("App exited or minimized unexpectedly")
            return False

        logger.info("App seems to be running normally")
        return True

    def get_permissions(self):
        # APK to test with: am.easypay.easywallet.apk
        # BANNED_PERMISSIONS = ["NOTIFICATIONS", "VIBRATE", "google"]
        for permission in self.apk.get_permissions():
            # if not any(b in permission for b in BANNED_PERMISSIONS):
                # print(permission)
            run_cmd(["adb", "shell", "pm", "grant", self.package_name, permission], quiet=True)

    def decompile_jadx(self, timeout=10):
        os.makedirs(self.decompiled_apk_path_jadx)
        try:
            logger.info(f"Decompiling with jadx, this may take up to {timeout} minutes")
            subprocess.run([
                            "jadx", 
                            "-d", self.decompiled_apk_path_jadx, 
                            self.apk_path],
                            timeout = timeout*60
            )
            logger.info(f"Decompiled APK to: {self.decompiled_apk_path_jadx}")
        except subprocess.TimeoutExpired:
            logger.warning(f"Timed out after {timeout} minutes")
            return
        except subprocess.CalledProcessError as e:
            logger.warning(f"jadx failed: {e}")
            return

    def decompile_jeb(self, timeout=120*60):

        logger.warning("This method was NOT tested")

        stdout_file = os.path.join(OUTPUT_PATH, f"{self.package_name}_jeb_stdout.txt")
        stderr_file = os.path.join(OUTPUT_PATH, f"{self.package_name}_jeb_stderr.txt")
     
        if os.path.exists(self.decompiled_apk_path_jeb):
            logger.info(f"\nAlready decompiled with JEB")
            if not ask_to_try_again("Do you want to decompile it again anyways? (y/n): "):
                return
        else:
            os.makedirs(self.decompiled_apk_path_jeb, exist_ok=True)

        logger.info(f"Decompiling with JEB (this may take up to an hour or more for larger apps)")    

        try:

            cmd = f"{JEB_RUN_PATH} -c --srv2 --script={JEB_DECOMPILE_SCRIPT_PATH} -- {self.apk_path} {self.decompiled_apk_path_jeb}"
            # command = [JEB_RUN_PATH, 
            #         "-c", 
            #         "--srv2", 
            #         f"--script={JEB_DECOMPILE_SCRIPT_PATH}", 
            #         "--", 
            #         {self.apk_path},
            #         {self.decompiled_apk_path_jeb}
            #         ]   

            start_time = time.time()

            proc_result = subprocess.run(cmd, 
                                        timeout=timeout,
                                        capture_output=True, 
                                        text=True, 
                                        check=True)

            with open(stdout_file, 'w') as file:
                file.write(proc_result.stdout)

            with open(stderr_file, 'w') as file:
                file.write(proc_result.stderr)

            elapsed_time = time.time() - start_time

            logger.info(f"Total decompilation time: {elapsed_time/60:.2f} min")  
            return True

        except subprocess.TimeoutExpired:
            logger.error(f"Decompilation timed out after {timeout} seconds")
            return False

        except Exception as e:
            logger.error(e)
            logger.warning("Check if you have a JEB license")
            return False
