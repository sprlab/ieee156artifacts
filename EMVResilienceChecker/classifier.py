from loguru import logger
logger.info("Classifier required for analysis, loading classifier...")

from config import (TF_CPP_MIN_LOG_LEVEL, TRANSFORMERS_NO_TQDM)
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = TF_CPP_MIN_LOG_LEVEL    
os.environ["TRANSFORMERS_NO_TQDM"] = TRANSFORMERS_NO_TQDM    


import re
import torch

from transformers import pipeline

from constants import MODEL
from constants import RESPONSE_MAP

class Classifier():

    def __init__(self):

        self.pipe = pipeline("text-generation", 
                            model = MODEL, 
                            torch_dtype=torch.bfloat16, 
                            device_map = "auto",
                            )

    @staticmethod
    def _clean_response(text):
        return re.sub(r"[^a-zA-Z]", "", text).lower()

    @staticmethod
    def show_memory_status():
        allocated = torch.cuda.memory_allocated() / 1024
        reserved = torch.cuda.memory_reserved() / 1024
        print(f"CUDA memory allocated: {allocated:.2f} GB")
        print(f"CUDA memory reserved: {reserved:.2f} GB")

    def classify(self, text, query, max_new_tokens=10):

        if not query:
            logger.warning("Please provide a query")
            return

        messages = [
            {"role": "system", "content": query},
            {"role": "user", "content": text},
        ]

        try:
            outputs = self.pipe(
                messages,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                top_p=1.0
            )

            response = self._clean_response(outputs[0]["generated_text"][-1]["content"])
        except Exception as e:
            logger.warning(f"Error processing text: {text}")
            logger.warning(f"Query: {self.query}")
            logger.warning(f"Exception: {e}")

            response = "error"
        finally:
            return RESPONSE_MAP.get(response, False)
   

if __name__ == "__main__":

    def test1():

        messages_with_labels = {
        "Root access detected.": "yes",
        "Device appears to be rooted.": "yes",
        "Your device is rooted. Some features may not work properly.": "yes",
        "Security warning: Root access found.": "yes",
        "Root access is required to use this app.": "yes",
        "Root access granted.": "yes",
        "Superuser permissions detected.": "yes",
        "Magisk detected on this device.": "yes",
        "SU binary found in system path.": "yes",
        "Xposed Framework detected.": "yes",
        "Root cloak detected.": "yes",
        "Untrusted modifications to system files found.": "yes",
        "This app will not run on rooted devices.": "yes",
        "System partition has been modified.": "yes",
        "Custom recovery detected (e.g., TWRP).": "yes",
        "Security threat detected.": "yes",
        "This app has detected a potential security issue.": "yes",
        "Malware detected on your device.": "yes",
        "Security settings have been altered.": "yes",
        "System integrity compromised.": "yes",
        "Play Protect has blocked this app.": "yes",
        "This device fails SafetyNet checks.": "yes",
        "SELinux is set to permissive mode.": "yes",
        "Unverified bootloader detected.": "yes",
        "Your device is at risk.": "yes",
        "Critical security vulnerability found.": "yes",
        "Security threat detected, Exiting Application.": "yes",
        "Security threat detected": "yes",

        "You have five new emails.": "no",
        "Battery at 80%.": "no",
        "Wi-Fi connected to Home_Network.": "no",
        "Update available for your apps.": "no",
        "No new notifications.": "no",
        "Bluetooth is turned off.": "no",
        "Weather: Sunny, 72°F.": "no",
        "Charging via USB.": "no",
        "Screenshot saved.": "no",
        "Storage space is running low.": "no",
        "Location services are on.": "no",
        "New message from Alice.": "no",
        "Alarm set for 7:00 AM.": "no",
        "App installed successfully.": "no",
        "Connected to car's Bluetooth.": "no",
        "Do Not Disturb is enabled.": "no",
        "Screen time: 3 hours today.": "no",
        "Calendar event at 2 PM.": "no",
        "Dark mode is on.": "no",
        "Auto-rotate enabled.": "no",

        "Installation from unknown sources enabled.": "no",
        "Unauthorized app installation blocked.": "no",
    }
        
        from constants import HAS_ROOT_CHECKING_QUERY

        c = Classifier(HAS_ROOT_CHECKING_QUERY)
        pipe = c.pipe

        wrong = 0

        query = None
        # query = """The following text is extracted from a View or Toast. Does the message say or suggest that the app has detected a rooted device or is in an insecure state? Say "yes" or "no", then explain. If you do not understand the language, say "no"."""

        for text, true_answer in messages_with_labels.items():
            
            local_answer = c.classify(text, query, 10)
            true_answer = RESPONSE_MAP.get(true_answer, False)
            if local_answer != true_answer:
                print()
                print(f"Query: {HAS_ROOT_CHECKING_QUERY}")
                print(f"Text: {text}")
                print(f"Local ans: {local_answer}")
                print(f"True ans: {true_answer}")
                wrong += 1


        print(f"Num wrong: {wrong}")

    def test2():

        messages_with_labels = {
        "Broneeri aeg": "no",
        }

        from constants import IS_NORMAL_OP_QUERY

        c = Classifier(IS_NORMAL_OP_QUERY)
        pipe = c.pipe

        wrong = 0

        query = None
        query = """The following text is extracted from a View or Toast. Does the message say or suggest that the app is not running normally? Say "yes" or "no", then explain. If you do not understand the language, say "no"."""

        for text, true_answer in messages_with_labels.items():
            
            local_answer = c.classify(text, query, 10)
            true_answer = RESPONSE_MAP.get(true_answer, False)
            if local_answer != true_answer:
                print()
                print(f"Query: {query}")
                print(f"Text: {text}")
                print(f"Local ans: {local_answer}")
                print(f"True ans: {true_answer}")
                wrong += 1

        print(f"Num wrong: {wrong}")


    # ====================================================

    test1()
    # test2() 
