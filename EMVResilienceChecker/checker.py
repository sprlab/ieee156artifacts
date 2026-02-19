import os
import re
import sys
import json
import time
import frida
import pickle
import config
import shutil
import random
import asyncio
import javalang
import threading
import subprocess
import xml.etree.ElementTree as ET

from appmanager import AppManager
from loguru import logger
from device import Device
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from userinput import ask_to_try_again
from userinput import ask_to_enter_int
from mitmdump import intercept
from mitmdump import MitmCertManager
from pprint import pprint as pp
from util import adb_action
from fridarunner import FridaRunner
from results import Results, Result
# from nltk.corpus import words as nltk_words
from nltk.corpus import brown
from ir_detector import is_renamed

if config.HAS_CODE_OBFUSCATION:
    import nltk
    # nltk.download('words')
    # english_words = set(word.lower() for word in nltk_words.words())
    nltk.download('brown')  
    english_words = set(word.lower() for word in brown.words())

from constants import (
    APK_PATH,
    APK_MITM_TAG,
    DEBUGGABLE_ATTRIB,
    DEPENDENCIES_PATH,
    FRIDA_SERVER,
    HAS_CRASHED_TASK,
    HAS_TEE,
    HAS_ANTI_DEBUG,
    HAS_CODE_OBFUSCATION,
    HAS_ROOT_CHECKING,
    HAS_ANTI_HOOKING,
    HAS_ANTI_REPACKAGING,
    HAS_NETWORK_INTEGRITY_CHECKING,
    RESULTS_DIR_PATH,
    HOOK_SUCCESS_TAG,
    HOOK_TIMEOUT,
    INPUT_PATH,
    IDENTIFIERS_OUTPUT_PATH,
    JADX_DECOMPILE_OUTPUT_PATH,
    KEEPS_STOPPING,
    KS_ALIAS,
    KS_FILE,
    KS_PASSWORD,
    LABEL,
    MITMDUMP_COLLECTION_DURATION,
    OUTPUT_PATH,
    PAYMENT_PKGS,
    POTENTIAL_UNTRUSTED_CERT_ERROR,
    ROOT_CHECKING_TASK,
    RUNS_NORMALLY_TASK,
    RUNS_NORMALLY,
    SIGNER_PATH,
    SHORT_WORDS_THRESHOLD,
    OBF_ABBREV,
    OBF_KEYWORDS,
    TEE_KEYWORDS,
    TEE_STDERR_PATH,
    THICK_LINE,
    THIN_LINE,
    UNTRUSTED_CERT_ERROR
)

def need_to_install_app():
    return config.HAS_ROOT_CHECKING or config.HAS_ANTI_HOOKING or config.HAS_NETWORK_INTEGRITY_CHECKING or config.CHECK_RUNS_NORMALLY==1

def need_to_run_app():
    return config.HAS_ANTI_REPACKAGING or need_to_install_app()

def atleast_one_task():
    return config.HAS_TEE or config.HAS_ANTI_DEBUG or config.HAS_CODE_OBFUSCATION or config.HAS_ROOT_CHECKING or need_to_run_app()

def need_droidbot():
    return config.HAS_ROOT_CHECKING or config.HAS_ANTI_HOOKING or config.HAS_ANTI_REPACKAGING or config.HAS_NETWORK_INTEGRITY_CHECKING or config.CHECK_RUNS_NORMALLY==1

if need_droidbot():
    from droidbotrunner import DroidBotRunner

class Checker:

    """
    TODO: remove shell usage from subprocesses 
    """

    def __init__(self, apk, tag, classifier = None):
        self.app_manager = AppManager(apk, tag)
        self.counter = 1
        self.classifier = classifier
        self.tag = tag
        self.results = Results(self.app_manager, self.tag)
        self.app_runs_normally = True
        self.app_installed = self.app_manager.is_installed()

        if self.need_to_run_app():
            if config.UNINSTALL_EXISTING_APP:
                self.app_manager.uninstall()

            if self.need_to_install_app():
                self.app_installed = self.app_manager.install()

            if self.app_installed:
                self.app_manager.get_permissions()
                if config.CHECK_RUNS_NORMALLY == -1:
                    logger.warning("config.CHECK_RUNS_NORMALLY = -1: program will assume the app runs normally")
                else:
                    self.app_runs_normally = not self._has_app_crashed() 
                    # if not self.app_runs_normally:
                    #     self.app_manager.update_app_via_play_store()
                    #     self.app_runs_normally = not self._has_app_crashed() 

            if self.app_runs_normally:

                logger.info("App is running normally")
        
                if config.HAS_ANTI_HOOKING or config.HAS_NETWORK_INTEGRITY_CHECKING:
                    self.adb_root = Device.adb_root()

                if config.HAS_ANTI_HOOKING:
                    self.frida_script_code = self._get_frida_script_code()

                if config.HAS_NETWORK_INTEGRITY_CHECKING:
                    self.mcm = MitmCertManager(config.IS_DEVICE_ROOTED)

        self.task_map = {
                            self._has_TEE                        : lambda: config.HAS_TEE,
                            self._has_anti_debug                 : lambda: config.HAS_ANTI_DEBUG,
                            self._has_code_obfuscation           : lambda: config.HAS_CODE_OBFUSCATION,
                            self._has_root_checking              : lambda: config.HAS_ROOT_CHECKING              and self.app_runs_normally and config.IS_DEVICE_ROOTED,
                            self._has_anti_hooking               : lambda: config.HAS_ANTI_HOOKING               and self.app_runs_normally and config.IS_DEVICE_ROOTED,
                            self._has_anti_repackaging           : lambda: config.HAS_ANTI_REPACKAGING           and self.app_runs_normally,
                            self._has_network_integrity_checking : lambda: config.HAS_NETWORK_INTEGRITY_CHECKING and self.app_runs_normally and config.IS_DEVICE_ROOTED,
                        }

    def process_apk(self):

        msg = None
        if self.need_to_run_app():
            logger.info("Checks require running app")
            
            self.app_manager.stop()

            if not self.app_runs_normally:
                msg = "App is installed but does not run normally"

                if not self.app_installed:
                    msg = "App was not or cannot be installed"

                logger.warning(f"{msg}, skipping dynamic analysis tasks if selected")
            
            if not config.IS_DEVICE_ROOTED:
                logger.warning("config.IS_DEVICE_ROOTED = 0: skipping dynamic analysis tasks if selected")

        else:
            logger.info("Checks do not require running app")

        if config.CHECK_RUNS_NORMALLY == -1:
            msg = "skipped if app runs normally, assumed true"
        self.results.dict[RUNS_NORMALLY] = Result(self.app_runs_normally, msg if msg else "-")

        if not atleast_one_task():
            logger.warning("No evaluation tasks chosen or can be run, on to next app")
            return

        self._evaluate_all()

        self.app_manager.stop()

        if config.UNINSTALL_AFTER_ANALYSIS:
            self.app_manager.uninstall()

    def _evaluate_all(self):
         for task, flag in self.task_map.items():
            if flag():
                logger.info(THIN_LINE)
                task()

    def _get_frida_script_code(self):
        if self.app_manager.main_activity:
            return """
                    Java.perform(function(){
                        let Main = Java.use('""" + self.app_manager.main_activity + """');
                        Main.onCreate.overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                send('""" + HOOK_SUCCESS_TAG + """: ' + overload.argumentTypes.map(t => t.className).join(', '));
                                // console.log("Hooking main activity was successful");
                                // return overload.apply(this, arguments); // Uncomment this line if you want the app to continue running normally
                                };
                            });
                        });
                """ 
        return None

    @staticmethod
    def need_to_run_app():
        return need_to_run_app()

    @staticmethod
    def need_to_install_app():
        return need_to_install_app()

    @staticmethod
    def need_classifier():
        return config.HAS_ROOT_CHECKING or config.HAS_ANTI_REPACKAGING or config.CHECK_RUNS_NORMALLY==1

    def _has_app_crashed(self):
        """Returns None, or the message that our classifier detected as app crashed, or if the app could not start"""
        # Test with: ae.payby.android.saladin.apk, am.easypay.easywallet.apk, com.cedarplus.gopayz.apk
        logger.info("Checking if app stays opened...")

        self.app_manager.start()
        result = self.app_manager.app_launched()
        self.app_manager.stop()
        if not result:
            return True
        
        logger.info("Checking if gives the 'keeps stopping' error...")
        runner = DroidBotRunner(self.app_manager, HAS_CRASHED_TASK) 
        result = runner.start(min_to_timeout=.5) # If we didn't find anything within a short time, it's likely that the app is running normally 
        self.app_manager.stop()
        if result:
            logger.warning(f"Failure: {result}")
        return result

    def _has_adb_root(self):
        if not self.adb_root:
            logger.warning("Cannot get adb root privilege, skipping _has_network_integrity_checking and _has_anti_hooking")
            return False
        return True

    def _copy_split_apks(self):
        for split_apk in self.app_manager.split_apks:
            if not os.path.exists(os.path.join(self.app_manager.output_apk_path, os.path.basename(split_apk))) or config.FORCE_REPACK:
                if split_apk.endswith(".apk"):
                    shutil.copy(split_apk, self.app_manager.output_apk_path)

    def _search(self, keyword, path):
            cmd = f"grep -rl '{keyword}' {path}"

            result = subprocess.run(cmd,
                                    capture_output=True,
                                    text=True,
                                    shell=True,
                                    )
            return result

    def _has_identifier_renaming(self):

        path = self.app_manager.decompiled_apk_path_jeb

        logger.info("Getting all identifiers, this will take a few minutes...")
        # is_renamed = {}             # Assign a score based on all identifiers in the file: # renamed identifiers / total # of identifiers
        # is_in_base_package = {}     # Boolean
        all_identifiers_in_app = {}

        def _collect_identifiers(path):
            total_files = 0
            num_failed_parsing = 0
            for root, dirs, files in os.walk(path): 
                for f in files:
                    filepath = os.path.join(root, f)

                    if f.endswith(".java"):
                        total_files += 1
                        # is_file_in_base_package = self.app_manager.package_name.replace(".", "/") in root
                        all_identifiers_in_file = _extract_identifiers(filepath)

                        if not all_identifiers_in_file:
                            num_failed_parsing += 1

            if total_files == 0:
                logger.warning(f"Decompilation directory has no files: {path}")
                return None
            else:  
                logger.info(f"{num_failed_parsing} of {total_files} failed parsing by javalang ({num_failed_parsing/total_files})")
                return True

        def _extract_identifiers(filepath):

            all_identifiers_in_file = {
                "classes": set(),
                "methods": set(),
                "fields": set(),
                "variables": set(),
            }

            try:

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    code = file.read()
                tree = javalang.parse.parse(code)

                for path, node in tree.filter(javalang.tree.ClassDeclaration):
                    all_identifiers_in_file["classes"].add(node.name)

                for path, node in tree.filter(javalang.tree.MethodDeclaration):
                    all_identifiers_in_file["methods"].add(node.name)

                for path, node in tree.filter(javalang.tree.FieldDeclaration):
                    for decl in node.declarators:
                        all_identifiers_in_file["fields"].add(decl.name)

                for path, node in tree.filter(javalang.tree.LocalVariableDeclaration):
                    for decl in node.declarators:
                        all_identifiers_in_file["variables"].add(decl.name)

                all_identifiers_in_app[filepath] = all_identifiers_in_file

                return all_identifiers_in_file

            except Exception as e:
                # print(f"Error parsing {filepath}: {e}")
                return None

        if not os.path.exists(IDENTIFIERS_OUTPUT_PATH):
            os.makedirs(IDENTIFIERS_OUTPUT_PATH)  

        identifier_pkl = os.path.join(IDENTIFIERS_OUTPUT_PATH, self.app_manager.package_name+".pkl") # save all ir_ratios as stored in is_renamed so we don't need to reparse
        if os.path.exists(identifier_pkl):
            logger.info(f"Found pickle file (delete it if you want to reparse everything): {identifier_pkl}")
            with open(identifier_pkl, "rb") as f:
                all_identifiers_in_app = pickle.load(f)
        else:
            if not _collect_identifiers(path):
                return
            logger.info(f"Saving identifiers to pickle file: {identifier_pkl}")
            with open(identifier_pkl, "wb") as f:
                pickle.dump(all_identifiers_in_app, f)

            
        def _app_ir_ratio():
            total = 0
            score = 0
            for filepath, all_identifiers_in_file in all_identifiers_in_app.items():
                if config.BASE_PACKAGE_ONLY and not self.app_manager.package_name.replace(".", "/") in filepath:
                    continue
                for category, identifiers in all_identifiers_in_file.items():
                    for identifier in identifiers:
                        total += 1
                        score += is_renamed(identifier)
        
            if total > 0:
                return score / total
            return -1 # "No identifiers found, might be due to parsing issue"

        app_ir_ratio = _app_ir_ratio()

        return app_ir_ratio 

# ================================== Below are the functions for the evaluations of EMV recommended protection mechanisms ==================================

    def _has_TEE(self, min_to_timeout=120):
        logger.info(f"{LABEL} {self.counter}: Checking if TEE is used (this may take up to {min_to_timeout} minutes)...")
        self.counter += 1

        if config.TEE_GREP == config.TEE_SOOT:
            logger.warning("Must pick one of TEE_GREP or TEE_SOOT, but not both")
            exit()

        err = ""
        tee_found = {
            "isInsideSecureHardware": [],
            "getSecurityLevel": [],
            "WrappedKeyEntry": []
        }

        if config.TEE_GREP:
            if not os.path.exists(self.app_manager.decompiled_apk_path_jadx):
                self.app_manager.decompile_jadx()

            search_path = os.path.join(self.app_manager.decompiled_apk_path_jadx, "sources")
            for keyword, class_ in TEE_KEYWORDS.items():
                result_keyword = self._search(keyword, search_path)
                files_with_keyword = set(result_keyword.stdout.split("\n")[:-1])

                result_class = self._search(class_, search_path)
                files_with_class = set(result_class.stdout.split("\n")[:-1])

                result = sorted(files_with_keyword & files_with_class)
                tee_found[keyword] = result

                r = max(result_keyword.returncode, result_keyword.returncode)

                if result:
                    logger.success(f"{keyword}: found")
                    logger.success("Up to 5 examples:")   
                    for line in result[0:5]:
                        logger.success(line)
                elif r == 1:
                    logger.error(f"{keyword}: NOT found")
                elif r == 2:
                    err = err + result.stderr + "\n"
                    logger.error(result.stderr)

        if config.TEE_SOOT:
            try:
                result = subprocess.run(f"java -jar {os.path.join(DEPENDENCIES_PATH,'has_TEE.jar')} {self.app_manager.apk_path} tee",
                                    capture_output=True,
                                    text=True,
                                    shell=True,
                                    # timeout=min_to_timeout*60
                                    )
                err = result.stderr
            except Exception as e:
                m = f"Timed out after {min_to_timeout} minutes"
                logger.error(m)
                self.results.dict[HAS_TEE] = Result("-", m)
                return

            for keyword, class_ in TEE_KEYWORDS.items():
                for output in result.stdout.strip().split("--------------------------------------"):
                    if not output:
                        continue
                    pkg = output.strip().split("\n")[0].replace("Method: <", "").split(":")[0]
                    if keyword in output and (any(p in output for p in PAYMENT_PKGS) or self.app_manager.package_name in output):
                        logger.success(f"TEE usage found: {output}")
                        tee_found[keyword].append(output)

        if any(tee_found.values()):
            self.results.dict[HAS_TEE] = Result(True, json.dumps(tee_found, indent = 4))
        else:
            m1 = "TEE usage NOT found. Note: obfuscation may interfere with detection of TEE."
            m2 = ""
            m3 = ""
            logger.error(m1)
            if err:
                m2 = "This part uses Soot, which may throw errors even if TEE was detected properly."
                logger.warning(m2)
                STDERR_FILE = os.path.join(TEE_STDERR_PATH, f"has_TEE_stderr_{self.app_manager.package_name}_{self.tag}.txt")
                with open(STDERR_FILE, "w") as f:
                    f.write(result.stderr)
                m3 = f"For more info, look for ERROR in {STDERR_FILE}"
                logger.warning(m3)
            self.results.dict[HAS_TEE] = Result(False, " ".join([m1, m2, m3]))  

        logger.info("IMPORTANT note: analyzing an APK pulled from a device may alter results - a positive may become negative (e.g. com.google.android.apps.walletnfcrel.apk)")

    def _has_anti_debug(self):
        """Checks if debuggable flag is set to false, or not set at all, which defaults to false"""
        
        logger.info(f"{LABEL} {self.counter}: Checking if debuggable flag in manifest is set to false...")
        self.counter += 1

        manifest_content = self.app_manager.apk.get_android_manifest_xml()

        tag_found = False

        def recurse(element, level=0):
            nonlocal tag_found
            if tag_found:
                return

            if element.tag == "application":

                tag_found = True

                for attrib in element.attrib:
                    logger.debug(f"{attrib}: {element.attrib[attrib]}")

                attrib_keys = element.attrib.keys() 

                if DEBUGGABLE_ATTRIB in attrib_keys:
                    if element.attrib[DEBUGGABLE_ATTRIB] in (1, "true"):
                        m = "Debuggable flag set to true, but should be false"
                        logger.error(m)
                        self.results.dict[HAS_ANTI_DEBUG] = Result(False, m)
                    else:
                        m = "Debuggable flag manually set to false"
                        logger.success(m)
                        self.results.dict[HAS_ANTI_DEBUG] = Result(True, m)
                else:
                    m = "Debuggable flag not found (defaults to false)"
                    logger.success(m)
                    self.results.dict[HAS_ANTI_DEBUG] = Result(True, m)

            for child in element:
                recurse(child, level + 1)

        try:
            tree = ET.ElementTree(manifest_content)
            recurse(tree.getroot())

        except ET.ParseError as e:
            logger.error("Failed to parse XML:", e)
            logger.error("Could not evaluate debuggable flag for has_anti_debug")
            logger.error("Please check the manifest manually")
            self.results.dict[HAS_ANTI_DEBUG] = Result("-", "Error when parsing manifest")
        
        logger.info("Read more: https://developer.android.com/privacy-and-security/risks/android-debuggable") 

    def _has_code_obfuscation(self): 
        logger.info(f"{LABEL} {self.counter}: Checking for code obfuscation (this may take a few minutes)...")
        self.counter += 1

        if not os.path.exists(self.app_manager.decompiled_apk_path_jeb):
            if not self.app_manager.decompile_jeb():
                config.HAS_CODE_OBFUSCATION
                return 

        logger.info(f"Decompiled APK located at: {self.app_manager.decompiled_apk_path_jeb}")

        search_path = self.app_manager.decompiled_apk_path_jeb
        if config.BASE_PACKAGE_ONLY:
            search_path = os.path.join(self.app_manager.decompiled_apk_path_jeb, 'Bytecode_decompiled', self.app_manager.package_name.replace(".","/"))
        logger.info(f"Search path: {search_path}")

        note = "Searched in base pkg only." if config.BASE_PACKAGE_ONLY else "Searched in entire app."

        if not os.path.exists(search_path):
            m = "Could not find search path, likely due to identifier renaming"
            m = f"{m}. Search path includes base package only" if config.BASE_PACKAGE_ONLY else f"{m}. Search path includes entire APK"
            logger.warning(m)
            for task in self.results.task_names:
                if task.startswith(HAS_CODE_OBFUSCATION):
                    self.results.dict[task] = Result("-", m)
            return

        ir_ratio = self._has_identifier_renaming()
        logger.info(f"Ratio of identifiers renamed: {ir_ratio}")
        self.results.dict[HAS_CODE_OBFUSCATION+"_IR"] = Result(ir_ratio, "\n".join([note, f"ir_ratio: {ir_ratio}, min ratio required for IR to be True: {config.IR_RATIO}"]))
        
        if config.IR_ONLY:
            return

        def filter(results, path):
            """Hide results for certain packages like standard Android ones or those from large companies, but always show something"""
            output = []
            for result in results.split("\n"):
                if not any(term in result for term in config.HIDE_LIST):
                    output.append(result)
            if len(output) == 0:
                return results[0:5]
            return "\n".join(output)

        for type, keyword in OBF_KEYWORDS.items():
            result = self._search(keyword, search_path)

            r = result.returncode
            detected = False

            if r == 0:
                logger.success(f"{type}: found")
                detected = True

                output = "\n".join(result.stdout.split("\n")[:-1])
                
                # Comment this if-block out so that "any where in the app" is actually "any where in the app"
                # if not config.BASE_PACKAGE_ONLY and config.FILTER_PKGS:
                #    output = filter(output, search_path) 

                logger.success("Up to 5 examples:")   
                for line in output.split("\n")[0:5]:
                    logger.success(line)

                comments = "\n".join([note, f"Examples: {output}"])

            elif r == 1:
                logger.error(f"{type}: NOT found")
                comments = "\n".join([note, "None found."])
            elif r == 2:
                logger.error(result.stderr)
                comments = " \n".join([notes, result.stdeer])

            self.results.dict[HAS_CODE_OBFUSCATION+f"_{OBF_ABBREV[type]}"] = Result(detected, comments)

    def _has_root_checking(self):
        logger.info(f"{LABEL} {self.counter}: Checking if app checks for rooted device...")
        self.counter += 1

        if self._has_app_crashed():
            self.results.dict[HAS_ROOT_CHECKING] = Result(True, f"App has crashed")
            return
    
        runner = DroidBotRunner(self.app_manager, ROOT_CHECKING_TASK, self.classifier)
        runner.start()

        if runner.message:
            logger.success(f'''App detected rooted device: "{runner.message}"''')
            self.results.dict[HAS_ROOT_CHECKING] = Result(True, f"Root detected message: {runner.message}")
        else:
            logger.error(f"App did NOT detect rooted device") 
            self.results.dict[HAS_ROOT_CHECKING] = Result(False)

    def _has_anti_hooking(self): # Frida - gadget for non-rooted (if repackaging was successful?) and server for rooted
        logger.info(f"{LABEL} {self.counter}: Checking if the app prevents hooking...")
        self.counter += 1

        if not self.app_manager.main_activity:
            logger.warning("This part requires a main activity but none was found, exiting")
            return

        try: # am.easypay.easywallet.apk closes right away when launched, but we don't get the message, so I guess it prevented the hook? yes, letting the main activity continue normally actually crashes app too

            runner = FridaRunner(FRIDA_SERVER) # make this an input from config 
            runner.kill_others()
            runner.start()

            device = frida.get_usb_device()  # or use frida.get_local_device() for local device
            pid = device.spawn([self.app_manager.package_name])
            process = device.attach(pid)
            script = process.create_script(self.frida_script_code)

            hook_success_event = threading.Event()
            hook_success = False

            def on_message(message, data):
                if message["type"] == "send":
                    msg = message["payload"]
                    if HOOK_SUCCESS_TAG in msg:
                        logger.error("Hook successful - the app does NOT prevent hooking (or failed to do so if it tried)")
                        logger.info(msg)
                        self.results.dict[HAS_ANTI_HOOKING] = Result(False)
                        hook_success_event.set()

            script.on('message', on_message)
            script.load()
            device.resume(pid)

            logger.info("Attempting to hook onCreate of main activity...")
            
            hook_success_event.wait(timeout=HOOK_TIMEOUT)
            
            process.detach()

            if not hook_success_event.is_set():
                process.detach()
                m = f"Hook unsuccessful after trying for {HOOK_TIMEOUT}s - the app either prevented it or there was an unexpected error during hooking"
                logger.success(m)
                self.results.dict[HAS_ANTI_HOOKING] = Result(True, m)

        except KeyboardInterrupt:
            m = "Analysis exited prematurely by user"
            logger.warning(m)
            self.results.dict[HAS_ANTI_HOOKING] = Result("-", m)
        except Exception as e:
            m = f"Unexpected error: {e}"
            logger.warning(m)
            self.results.dict[HAS_ANTI_HOOKING] = Result("-", m)
        finally:
            runner.stop()

    def _has_anti_repackaging(self, timeout=10):
        if config.REPACK_ONLY:
            logger.info(f"{LABEL} {self.counter}: Attempting repackaging only...")
        else:
            logger.info(f"{LABEL} {self.counter}: Checking if app can be repackaged and run...")

        self.counter += 1

        if not config.FORCE_REPACK:
            logger.warning("config.FORCE_REPACK = 0: will skip certain steps if existing files/dirs exist, set config.FORCE_REPACK=1 if errors occur")

        disassembly_output = os.path.join(self.app_manager.output_apk_path, "apktool_disassembly") # -f: Forces the decompilation, overwriting any existing files in the output directory.

        if not os.path.exists(disassembly_output) or config.FORCE_REPACK:

            logger.info("Disassembling with apktool")

            disassembly = subprocess.run([
                                            "apktool", "d",
                                            self.app_manager.apk_path,
                                            "-o", disassembly_output,
                                            "-f"
                                        ],
                                        capture_output=True,
                                        text=True,
                                        timeout=timeout*60
                                        )

            def actual_error_in_disassembly(stderr):
                if not stderr:
                    return False
                return "Exception" in stderr or any(line.startswith("E:") for line in stderr.split("\n"))

            if actual_error_in_disassembly(disassembly.stderr):
                logger.error(f"\n{disassembly.stderr}")
                logger.warning("APK CANNOT be disassembled, so it CANNOT be repackaged, which is a good thing, but...")
                logger.warning("this was likely due to a failure in and does NOT indicate that the app has anti-repackaging abilities itself")
                self.results.dict[HAS_ANTI_REPACKAGING] = Result("-", f"Diassembly error: {disassembly.stderr}")
                return

            nugget = os.path.join(INPUT_PATH, "repackingtest")
            logger.info(f"Inserting a nugget to guarantee a modified APK: {nugget}")
            shutil.copy(nugget, disassembly_output)

        repacked_path = self.app_manager.repacked_and_signed_apk_path.replace("-repacked-aligned-signed", "-repacked")
        if not os.path.isfile(repacked_path) or config.FORCE_REPACK:

            logger.info("Repackaging with apktool")

            build = subprocess.run([
                                        "apktool", "b",
                                        disassembly_output,
                                        "-o", repacked_path
                                    ],
                                    capture_output=True,
                                    text=True,
                                    timeout=timeout*60
                                    )

            def actual_error_in_building(stderr):
                if not stderr:
                    return False
                return "error:" in stderr

            if actual_error_in_building(build.stderr):
                logger.error(f"\n{build.stderr}")
                logger.warning("APK CANNOT be built (i.e. repackaged), which is a good thing, but...")
                logger.warning("this was likely due to a failure in apktool or problem in the APK and does NOT indicate that the app has anti-repackaging abilities itself")
                self.results.dict[HAS_ANTI_REPACKAGING] = Result("-", f"Build error: {build.stderr}")
                return

        if self.app_manager.split_apks:
            self._copy_split_apks()
        
        apks_already_signed = [os.path.join(self.app_manager.output_apk_path, f).replace("-aligned-signed.apk.idsig", ".apk") for f in os.listdir(self.app_manager.output_apk_path) if f.endswith(".idsig")]
        apks_to_sign = [os.path.join(self.app_manager.output_apk_path, f) for f in os.listdir(self.app_manager.output_apk_path) if f.endswith(".apk") and "-aligned-signed" not in f]
        apks_to_sign = set(apks_to_sign) - set(apks_already_signed)

        for apk_to_sign in apks_to_sign:
            if not os.path.exists(apk_to_sign.replace(".apk", "-aligned-signed.apk")) or config.FORCE_REPACK:
                logger.info(f"Signing {apk_to_sign} with {SIGNER_PATH}")

                signed_apk = subprocess.run([
                                                "java", "-jar", SIGNER_PATH,
                                                "--apks", apk_to_sign,
                                                "--ks", KS_FILE,
                                                "--ksPass", KS_PASSWORD,
                                                "--ksKeyPass", KS_PASSWORD,
                                                "--ksAlias", KS_ALIAS,
                                                "--allowResign"
                                            ],
                                            capture_output=True,
                                            text=True,
                                            timeout=timeout*60
                                            )

                if signed_apk.stderr:
                    logger.error(signed_apk.stderr)
                    logger.warning(apk_to_sign)
                    logger.warning("APK CANNOT be signed and thus CANNOT be repackaged, which is a good thing, but...")
                    logger.warning("this was due to a failure in signing the APK and does NOT indicate that the app has anti-repackaging abilities itself")
                    self.results.dict[HAS_ANTI_REPACKAGING] = Result("-", "APK cannot be signed")
                    return

        if not config.REPACK_ONLY:

            apk_to_install = [os.path.join(self.app_manager.output_apk_path, f) for f in os.listdir(self.app_manager.output_apk_path) if f.endswith("-aligned-signed.apk")]

            if not self.app_manager.uninstall():
                m = "Cannot uninstall existing APK"
                logger.warning(m)
                self.results.dict[HAS_ANTI_REPACKAGING] = Result("-", m)
                return

            if not self.app_manager.install(apk_to_install):
                m = "Cannot install repacked and signed APK"
                logger.warning(m)
                self.results.dict[HAS_ANTI_REPACKAGING] = Result("-", m)
                return

            message = self._has_app_crashed() 

            if message:
                m = f'''App is NOT running normally after repacking (has app crashed): "{message}"'''
                logger.error(m)
                self.results.dict[HAS_ANTI_REPACKAGING] = Result(True, m)
            else:
                m = "App is running normally"
                logger.success(m) 
                self.results.dict[HAS_ANTI_REPACKAGING] = Result(False, m)

            if self._has_network_integrity_checking:
                self.app_manager.uninstall()
        else:
            logger.warning("config.REPACK_ONLY = 1: will only repack the app, skipping running app part of testing")

    def _has_network_integrity_checking(self, is_device_rooted = False): 
        logger.info(f"{LABEL} {self.counter}: Checking if app checks for network integrity...")
        self.counter += 1

        if not self.mcm.install_global_http(): # or not self.mcm.push_cert()
            logger.warning("Error setting up device for _has_network_integrity_checking, skipping future evaluations")
            config.HAS_NETWORK_INTEGRITY_CHECKING = False
            return

        def evaluate(self, server_conns):

            results_dict = {}

            if len(server_conns.items()) == 0:
                m = "No server connection attempts detected. Current evaluation method assumes all apps attempts at least one connection at launch. Evaluation for network integrity checking is inconclusive."
                logger.warning(m)
                self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result("-", m)

            num_untrusted_certs = 0
            num_trusted_certs = 0

            for uid, server_conn in server_conns.items():
                type = server_conn["type"]
                error = server_conn["error"]
                url = server_conn["url"]
                client_tls_established = server_conn["client_tls_established"]

                if client_tls_established:
                    logger.error(f"DETECTED TRUSTED CERT (successful TLS connection): {url}")
                    num_trusted_certs += 1
                    results_dict[url] = "trusted"

                else:   
                    if type == "connect":
                        logger.warning(f"Unexpected scenario: TLS connection was not successful but connection is still connected")

                    elif type == "disconnect":
                        if not error:
                            m = f"Unexpected scenario: disconnection with no error and no successful TLS connection"
                            logger.warning(m)
                            results_dict[url] = m
                        elif UNTRUSTED_CERT_ERROR in error:
                            logger.success(f"DETECTED UNTRUSTED CERT (detected cert error msg): {url}")
                            num_untrusted_certs += 1
                            results_dict[url] = "untrusted"
                        elif POTENTIAL_UNTRUSTED_CERT_ERROR in error:
                            logger.warning(f"DETECTED POTENTIALLY UNTRUSTED CERT: {url}")
                            logger.warning(error)
                            num_untrusted_certs += 1
                            results_dict[url] = "untrusted"
                        elif error:
                            logger.info(f"DETECTED TRUSTED CERT (disconnected with non-cert related error): {url}")
                            logger.info(f"Error: {error}")
                            # num_trusted_certs += 1
                            results_dict[url] = f"Error: {error}"
                    
            self.app_manager.stop()
            return num_untrusted_certs, num_trusted_certs, results_dict

        server_conns = intercept(self.app_manager.start())
        num_untrusted_certs, num_trusted_certs, results_dict = evaluate(self, server_conns)
        
        logger.info(f"RESULTS: Detected {num_untrusted_certs} untrusted cert(s) and {num_trusted_certs} trusted cert(s)")

        if num_trusted_certs > 0:
            if num_untrusted_certs > 0:
                logger.warning(f"Manual analysis of why there are both trusted and untrusted certs may be useful")
            elif num_untrusted_certs == 0:
                m = f"All {num_trusted_certs} certs were trusted, indicating that network integrity checks were NOT performed (app blindly trusts system store, no certificate pinning)"
                logger.error(m)
                self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result(False, m)

        if num_untrusted_certs > 0:

            def _patch_split_or_single_apkmitm():

                logger.info(f"Patching single APK with apk-mitm, this may take several minutes...")
                
                result = subprocess.run(["apk-mitm", self.app_manager.apk_path],
                                        capture_output=True,
                                        text=True,
                                        timeout=60*60)

                if result.stderr:
                    m = "Error while patching APK with apk-mitm"
                    logger.warning(m)
                    logger.warning(result.stderr)
                    self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result(True, f"{num_trusted_certs} trusted certs and {num_untrusted_certs} untrusted certs.\n\n{m}: {result.stderr}")
                    return False
                return True

            def _patch_merged_apkmitm():

                logger.info(f"Patching merged APK with apk-mitm, this may take several minutes...")

                result = subprocess.run(["apk-mitm", self.app_manager.merged_apk],
                                    capture_output=True,
                                    text=True,
                                    timeout=60*60)

                if result.stderr:
                    m = "Error while patching merged APK with apk-mitm"
                    logger.warning(m)
                    logger.warning(result.stderr)
                    self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result(True, f"{num_trusted_certs} trusted certs and {num_untrusted_certs} untrusted certs.\n\n{m}: {result.stderr}")
                    return False
                return True

            if self.app_manager.merged_apk: # apk-mitm fails for split APKs, so go straight to merged APK if there is one, if not then ignore the split APK
                apk_to_install = self.app_manager.merged_apk.replace(".apk", APK_MITM_TAG)
                if not os.path.exists(apk_to_install):
                    if not _patch_merged_apkmitm():
                        return
                else: 
                    logger.info("Merged APK already patched with apk-mitm")
            elif not self.app_manager.split_apks: # single APK
                apk_to_install = self.app_manager.apk_mitm_patched_path
                if not os.path.exists(self.app_manager.apk_mitm_patched_path):
                    if not _patch_split_or_single_apkmitm():
                        return
                else: 
                    logger.info("Single APK already patched with apk-mitm")
            else: # split apk and no merged apk
                m = "This split APK does not have a merged APK. Apk-mitm does not work with split APKs based on our observation."
                logger.warning(m)
                self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result("-", f"{num_trusted_certs} trusted certs and {num_untrusted_certs} untrusted certs.\n\n{m}")
                return
            
            if self.app_manager.uninstall() and self.app_manager.install(apk_to_install=apk_to_install):
                server_conns = intercept(self.app_manager.start())
                num_untrusted_certs_post_apkmitm, num_trusted_certs_post_apkmitm, results_post_apkmitm_dict = evaluate(self, server_conns)
            else:
                logger.warning("Exiting due to error")
                return
            
            logger.info(f"FINAL RESULTS: Detected {num_untrusted_certs_post_apkmitm} untrusted certs and {num_trusted_certs_post_apkmitm} trusted certs")

            d_num_trusted_certs = 0
            for url, cert_status in results_dict.items():
                if cert_status == "untrusted":
                    try:
                        cert_status_post_apk_mitm = results_post_apkmitm_dict[url]
                    except:
                        logger.warning(f"url not detected post apkmitm: {url}")
                        continue
                    if cert_status_post_apk_mitm == "trusted":
                        d_num_trusted_certs += 1

            runs_normally_post_apkmitm = self._has_app_crashed()
            if d_num_trusted_certs > 0:
                m = f"apk-mitm gained trust in {d_num_trusted_certs} certs, now have {num_trusted_certs_post_apkmitm} trusted certs and {num_untrusted_certs_post_apkmitm} untrusted certs, previously had {num_trusted_certs} trusted certs and {num_untrusted_certs} untrusted certs. App runs normally post apk-mitm: {runs_normally_post_apkmitm}"
                logger.info(m)
                result = num_untrusted_certs_post_apkmitm != 0
                self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result(result, m)
            else:
                m = f"apk-mitm was NOT able to bypass any of the {num_untrusted_certs} untrusted certs. App runs normally post apk-mitm: {runs_normally_post_apkmitm} "
                logger.info(m)
                self.results.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result(True, m)
        
        if not self.app_manager.uninstall():
            logger.warning("Cannot uninstall app, please manually uninstall")

        if not self.mcm.delete_global_http(): # not self.mcm.remove_cert()
            logger.warning("Error undoing device setup for _has_network_integrity_checking, which will cause problems next time _has_network_integrity_checking is run, skipping future evaluations")
            config.HAS_NETWORK_INTEGRITY_CHECKING = False
            return

# These results look no good, model is too weak. ChatGPT classifies things properly
# com.blombank.next.apk
# App detected rooted device: "NEXT won't run without Google Play services, which are not supported by your device."
# App is NOT running normally after repacking: "NEXT won't run without Google Play services, which are not supported by your device."
if __name__ == "__main__":
    logger.warning("Please run main.py")
