import os
import pandas as pd

from dataclasses import dataclass

from constants import (
    IR, SE, RF, CF, VT, 
    HAS_TEE,
    HAS_ANTI_DEBUG,
    HAS_CODE_OBFUSCATION,
    HAS_ROOT_CHECKING,
    HAS_ANTI_HOOKING,
    HAS_ANTI_REPACKAGING,
    HAS_NETWORK_INTEGRITY_CHECKING,
    RESULTS_DIR_PATH,
    RESULTS_FILE_EXT,
    RESULTS_FILE_NAME,
    RESULTS_APK_PATH_KEY,
    RESULTS_APK_NAME_KEY,
    RUNS_NORMALLY
)

from config import IS_DEVICE_ROOTED

@dataclass
class Result:
    result: bool | str = None
    comments: str = "-"

class Results:
    def __init__(self, app_manager, tag):
        self.app_manager = app_manager
        self.apk_path = self.app_manager.apk_path 
        
        self.tag = tag
        if not self.tag:
            from datetime import datetime
            self.tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")

        root_tag = "rooted" if IS_DEVICE_ROOTED else "unrooted"
        self.excel_output_path = os.path.join(RESULTS_DIR_PATH, f"{RESULTS_FILE_NAME}_{self.tag}_{root_tag}.{RESULTS_FILE_EXT}")
        
        self.task_names = [
                            RUNS_NORMALLY, 
                            HAS_TEE, 
                            HAS_ANTI_DEBUG, 
                            HAS_CODE_OBFUSCATION+f"_{IR}",
                            HAS_CODE_OBFUSCATION+f"_{SE}",
                            HAS_CODE_OBFUSCATION+f"_{RF}",
                            HAS_CODE_OBFUSCATION+f"_{CF}",
                            HAS_CODE_OBFUSCATION+f"_{VT}",
                            HAS_ROOT_CHECKING, 
                            HAS_ANTI_HOOKING, 
                            HAS_ANTI_REPACKAGING, 
                            HAS_NETWORK_INTEGRITY_CHECKING
                        ]
        self.dict = {name: None for name in self.task_names}
 
    def _to_row(self) -> dict:
        row = {RESULTS_APK_PATH_KEY: self.apk_path, RESULTS_APK_NAME_KEY: os.path.basename(self.apk_path)}
        for name, result_data in self.dict.items():
            if result_data:
                row[f"{name} results"] = result_data.result
                row[f"comments for {name}"] = result_data.comments
            else:
                row[f"{name} results"] = "-"
                row[f"comments for {name}"] = "-"
        return row

    def to_excel(self):
        row = self._to_row()
        df = pd.DataFrame([row])
        
        if not os.path.exists(self.excel_output_path):
            df.to_excel(self.excel_output_path, index=False)
        else:
            with pd.ExcelWriter(self.excel_output_path, mode='a', if_sheet_exists='overlay', engine='openpyxl') as writer:
                book = writer.book
                sheet = book.active
                startrow = sheet.max_row
                df.to_excel(writer, index=False, header=False, startrow=startrow)

if __name__ == "__main__":

    apk_results = {}

    apk_name = "/home/user/dir/com.example.app.apk"
    r = Results(apk_name, "./results_test.xlsx")

    r.dict[HAS_TEE] = Result(True, "TEE is enabled")
    r.dict[HAS_ANTI_DEBUG] = Result(False, "Debuggable flag found")
    r.dict[HAS_ROOT_CHECKING] = Result(True, "No root indicators found")
    r.dict[HAS_ANTI_HOOKING] = Result(True, "frida is valid")
    r.dict[HAS_CODE_OBFUSCATION] = Result(False, "No obf detected")
    r.dict[HAS_NETWORK_INTEGRITY_CHECKING] = Result(True, "network information found")
    # r.dict["Integrity"] = Result(True, "Integrity check passed")

    apk_results[apk_name] = r

    r.to_excel()
