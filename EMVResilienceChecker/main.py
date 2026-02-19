import config 
# make a copy of config.py for records?
from loguru import logger
from checker import atleast_one_task
if not atleast_one_task() and not config.INSTALL_ONLY and not config.START_ONLY:
    logger.warning("No evaluation tasks selected, please check config.py")
    exit()

import os

import argparse
import pandas as pd

from checker import Checker
from androguard.util import set_log
from results import Results
from tqdm import tqdm
from datetime import datetime
from userinput import ask_to_continue

from constants import (
    THICK_LINE, 
    LOG_LEVEL,
    LOG_DIR_PATH,
    RESULTS_DIR_PATH,
    RESULTS_FILE_EXT,
    RESULTS_FILE_NAME,
    RESULTS_APK_PATH_KEY,
    # RESULTS_APK_NAME_KEY,
)

set_log(LOG_LEVEL)

class Main():

    def __init__(self):

        parser = argparse.ArgumentParser(description="Process APKs from a directory or a single file")

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("-d", "--dir", type=str, help="Directory containing APK files")

        parser.add_argument("-s", "--split",  action="store_true", help="Directory containing split APK files")

        group.add_argument("-f", "--file", type=str, help="Single APK file")

        parser.add_argument("-id", "--id", type=str, help="Device ID")

        args = parser.parse_args()

        if not args.file and not args.dir:
            parser.error("Please specify an APK path or a path to a directory of APKs")

        if args.file and args.split:
            parser.error("Do not use -s with -f")
        # if args.split and not args.dir or args.split and not args.file:
        #     parser.error("argument -s/--split requires -d/--dir to be specified")

        self.split = args.split
        self.dir = args.dir
        self.apk = args.file

        if bool(config.OVERRIDE_MAIN_ACTIVITY) ^ bool(config.OVERRIDE_PACKAGE_NAME):
            logger.warning("Please specify both OVERRIDE_MAIN_ACTIVITY and OVERRIDE_PACKAGE_NAME")
            exit()

        self.tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")

        self.most_recent_result_path = None
        self.apks_already_processed = self._get_already_processed()

        self.classifier = None
        if Checker.need_classifier():
            from classifier import Classifier
            self.classifier = Classifier()

    def _get_already_processed(self):
        if config.OMIT_PROCESSED:
            if config.OMIT_PROCESSED == 1:
                most_recent_result = sorted([f for f in os.listdir(RESULTS_DIR_PATH) if self._is_valid_file_name(f)])[-1]

            elif self._is_valid_file_name(config.OMIT_PROCESSED):
                most_recent_result = config.OMIT_PROCESSED
            else:
                logger.warning(f"The selected results file {config.OMIT_PROCESSED} does not have a valid name")  
                logger.warning(f"Please check config.OMIT_PROCESSED in config.py")    
                exit() 

            logger.info(f"Omitting APKs found in {most_recent_result}")
            self.most_recent_result_path = os.path.join(RESULTS_DIR_PATH, most_recent_result)

            df = pd.read_excel(self.most_recent_result_path)
            return df[RESULTS_APK_PATH_KEY].dropna().tolist()
        return []

    def _is_valid_file_name(self, f):
        return f.startswith(RESULTS_FILE_NAME) and f.endswith(RESULTS_FILE_EXT)

    def need_to_run_app():
        # logger.critical("TODO: create a need_classifer() and remove HAS_NIC from the condition")
        return config.HAS_ROOT_CHECKING or config.HAS_ANTI_HOOKING or config.HAS_ANTI_REPACKAGING or config.HAS_NETWORK_INTEGRITY_CHECKING or config.CHECK_RUNS_NORMALLY

    def atleast_one_task():
        return config.HAS_TEE or config.HAS_ANTI_DEBUG or config.HAS_CODE_OBFUSCATION or config.HAS_ROOT_CHECKING or need_to_run_app()

    def _process_apk(self, apk_path):
       
        checker = Checker(apk_path, self.tag, self.classifier)

        def start_only():
            if not checker.app_manager.is_installed():
                logger.warning("App not installed, please install first")
                exit()
            checker.app_manager.start()
            ask_to_continue(timeout=None)


        if config.INSTALL_ONLY:
            checker.app_manager.install()
        if config.START_ONLY:
            start_only()
        if config.INSTALL_ONLY or config.START_ONLY:
            return

        log_file_name = f"{os.path.basename(apk_path).replace('.apk','')}_{checker.app_manager.tag}.log"
        log_path = os.path.join(LOG_DIR_PATH, log_file_name)
        log_file_handler = logger.add(log_path, level=LOG_LEVEL, mode='w')

        if config.SAVE_TO_OMIT_PROCESSED_FILE:
            checker.results.excel_output_path = self.most_recent_result_path

        checker.process_apk()
        checker.results.to_excel() # appending everytime we finish an APK so we don't lose results in case of crash

        logger.info(f"Log saved to {log_path}")
        logger.info(f"Results saved to {checker.results.excel_output_path}")
        logger.remove(log_file_handler)

    def start(self):

        logger.info(f"{len(self.apks_already_processed)} APKs already evaluated")   

        if self.dir:

            logger.info(f"Chosen directory: {self.dir}")

            apk_list = sorted([os.path.join(self.dir,apk) for apk in os.listdir(self.dir)])

            if not self.split:
                apk_list = sorted([apk for apk in apk_list if apk.endswith(".apk")])

            logger.info(f"{len(apk_list)} APKs to evaluate")

            for apk in tqdm(apk_list):

                if config.OMIT_PROCESSED and (os.path.join(apk, "base.apk") in self.apks_already_processed or apk in self.apks_already_processed):
                    logger.info(f"Already processed, omitting: {os.path.basename(apk)}")
                    continue

                logger.info(THICK_LINE)
                logger.info(f"Processing {apk}")
                self._process_apk(apk)

        elif self.apk:

            logger.info(THICK_LINE)
            logger.info(f"Processing {self.apk}")
            self._process_apk(self.apk)

        logger.info("All tasks completed, program exiting")


if __name__ == "__main__":
    m = Main()
    m.start()