import subprocess
import threading
import json
import time
import os
import signal
import numpy as np

from PIL import Image
from util import run_cmd
from loguru import logger
from datetime import datetime

from constants import DROIDBOT_OUTPUT_PATH
from constants import ROOT_CHECKING_TASK
from constants import RUNS_NORMALLY_TASK
from constants import HAS_ROOT_CHECKING_QUERY
from constants import IS_NORMAL_OP_QUERY
from constants import DROIDBOT_TARGETS

class DroidBotRunner:

    """Runs DroidBot to find a message, if any, from the app that causes the classifier return True for the given query."""

    def __init__(self, app_manager, task, classifier=None):
        self.app_manager = app_manager
        self.task = task

        from classifier import Classifier
        self.classifier = classifier
        
        # target can be a query, a (sub)string, or a list of (sub)strings
        # queries should be designed such that droidbot stops when self.message is detected as True
        # if classifier=None, then the query is a single or list of target substrings
        self.target = self._get_target() 
        if not self.classifier and isinstance(self.target, str):
            self.target = [self.target]

        self.message = None # the message input to the classifier that was then classified as True - returns None if no such message exists
        self.temp_message = None # this message does not exit the analysis and will be returned at end

        self.output_dir = os.path.join(DROIDBOT_OUTPUT_PATH, self.app_manager.package_name, f"{self.task}_{self.app_manager.tag}") 
        logger.critical("Maybe don't use packagename in output path, but use actual apk name, which may include tags")

        os.makedirs(self.output_dir, exist_ok=True)
        self.states_dir = os.path.join(self.output_dir, "states")

        self.droidbot_proc = None
        self.already_processed = set()

        self.device_screen_size = self._get_device_screen_size()
        self.stddev_threshold = 10 # This is the threshold in which larger std dev indicates a non-blank screen

        self.seen = set()
        self.states = set()

    def start(self, min_to_timeout=5):

        if self.message:
            logger.warning("This DroidBotRunner instance already found a message. Running it again is prohibited. Exiting.")
            return

        logger.info(f"DroidBot files will be saved to {self.output_dir}")
        logger.critical("TODO: a small logo in the center on a all white background may cause this to return True on accident")
        logger.critical("TODO: sometimes apps draw texts in a canvas pixel-by-pixel like an image, may need to use multimodal model in this case")
        
        self.droidbot_proc = subprocess.Popen(["droidbot",
                                        "-a", self.app_manager.apk_path,
                                        "-o", self.output_dir,
                                        "-policy", "bfs_greedy",
                                        "-keep_app",
                                        # "-is_emulator"
                                        ],   
                                        stdout=subprocess.DEVNULL, # comment these out to show in terminal
                                        stderr=subprocess.DEVNULL, # comment these out to show in terminal
                                        stdin=subprocess.PIPE
                                        )

        monitor_thread = threading.Thread(target=self._monitor_states)
        monitor_thread.start()

        try:
            logger.info(f"Starting DroidBot, this analysis may take up to {min_to_timeout} minute(s)...")
            logger.info(f"Task: {self.target}")
            self.droidbot_proc.wait(timeout=min_to_timeout*60)
        except subprocess.TimeoutExpired:
            logger.info("DroidBot process completed (intentionally timed out)")
        except KeyboardInterrupt:
            logger.warning("Exited by user")
        except FileNotFoundError:
            logger.warning("Please check and manually create state dir as needed")
        except NameError:
            logger.warning("Invalid task")
        except Exception as e:
            logger.warning(f"Unexpected exception: {e}")
        finally:
            if self.droidbot_proc.poll() is None:
                self.droidbot_proc.terminate()
                if self.temp_message and not self.message:
                    self.message = self.temp_message
            logger.info("Waiting for threads to join...")
            monitor_thread.join()
            logger.info("DroidBot and monitor thread have exited")
            logger.info(f"Files saved to {self.output_dir}")
            return self.message

    def _monitor_states(self):
        """
        Monitors state of current UI to check if text contains specific message.
        Two types of JSON files are used to represent state: {self.output_dir}/states/state_{tag}.json and {self.output_dir}/states/toast_{tag}.json.
        Toast JSON files were not output by original DroidBot code, but is now output thru droidbot/adapter/droidbot_app.py.
        """
        def _droidbot_still_running():
            return self.droidbot_proc.poll() is None 

        def _has_unvisited_states():
            return set(self.states) - self.seen != set()

        while _droidbot_still_running() and not os.path.exists(self.states_dir):
            time.sleep(0.5)

        while _droidbot_still_running() or _has_unvisited_states():

            self.states = sorted(set([f for f in os.listdir(self.states_dir) if f.endswith(".json")]))[1:] # Omit first state, which is just the home screen

            for state in self.states:
                if state not in self.seen:

                    json_path = os.path.join(self.states_dir, state)
                    
                    self.seen.add(state)
                    
                    if state.startswith("state"):
                        self._handle_state_json(json_path)
                    elif state.startswith("toast"):
                        self._handle_toast_json(json_path)
                    else:
                        logger.warning(f"Unexpected JSON file: {state}")
                        continue

                    if self.message:
                        self.droidbot_proc.terminate()
                        return

            time.sleep(0.5)

    def _handle_state_json(self, path):
        def work(data):
            for view in data.get("views", []):
                if view["visible"]:
                    text = view.get("text", None)
                    if not text:
                        text = view.get("content_description", None)
                    self._handle_text(text)
                    if self.message:
                        return
                    # logger.debug("Blank sceen checker returns too many false positives, turning off until a better solution is implemented")
                    self._check_for_scrim(view, path)
        self._handle_json(path, work)
        
    def _handle_toast_json(self, path):
        def work(data):
            for text in data.get("text", []):
                print(text)
                self._handle_text(text)
                if self.message:
                    return
        self._handle_json(path, work)

    def _handle_json(self, path, work):
        result = False
 
        try:
            with open(path, "r") as f:
                data = json.load(f)
                work(data)
        except FileNotFoundError:
            logger.warning(f"File not found: {path}")
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parsing error in {path}: {e}")
        # except Exception as e:
        #     logger.warning(f"Unexpected error: {e}")
        
    def _handle_text(self, text):
        if not text:
            return

        text = text.replace("\n", " ").replace("\r", " ")
        
        if text in self.already_processed:
            return

        self.already_processed.add(text)

        if (self.classifier and self.classifier.classify(text, self.target)) \
            or (not self.classifier and any(t in text for t in self.target)): # LLM classification \ basic str search
            self.message = text

    def _check_for_scrim(self, view, path):
        if "scrim" not in view:
            return
            
        view_size = sorted(view["bounds"][1])
        if not self.device_screen_size:
            self.device_screen_size = self._get_device_screen_size()

        if view_size == self.device_screen_size:
            dir_path = os.path.dirname(path)
            base_name = os.path.basename(path)
            tag = base_name.split('_')[1] + "_" + base_name.split('_')[2].split('.')[0]
            target_screenshot = os.path.join(dir_path, f"screen_{tag}.png")
            if not os.path.isfile(target_screenshot):
                target_screenshot = f"{os.path.splitext(target_screenshot)[0]}.jpg"
                if not os.path.isfile(target_screenshot):
                    logger.warning(f"No screenshot found for state: {path}")
                    return

            if target_screenshot not in self.seen:
                self.seen.add(target_screenshot)

                if self._is_all_pixels_equal_color(target_screenshot):
                    self.temp_message = "DroidBotRunner detected a blank screen"

    def _is_all_pixels_equal_color(self, path):
        return DroidBotRunner._img_std(path) < self.stddev_threshold

    @staticmethod
    def _img_std(path, border_fraction=0.1, sample_step_x=None, sample_step_y=None):
        """ 
        Border_fraction is used to remove things like the bottom three buttons on certain android phones, which may introduce a bar that is not relevant to app contents and cause multimodal dist.
        Std dev may not be reliable if the img pixels have a multimodal distribution.
        """
        img = Image.open(path).convert("L")  # Grayscale
        arr = np.array(img)

        h, w = arr.shape
        bh = int(h * border_fraction)
        bw = int(w * border_fraction)

        arr = arr[bh:h-bh, bw:w-bw]

        if sample_step_x and sample_step_y:
            arr = arr[::sample_step_x, ::sample_step_y].flatten() # Take every `sample_step`-th pixel along both axes

        return np.std(arr) # 

    def _get_device_screen_size(self):
        result = run_cmd(["adb", "shell", "wm", "size"])
        if result.stdout:
            w, h = result.stdout.strip().replace("Physical size: ", "").split("x")
            return sorted([int(w), int(h)])
        else:
            return None

    def _get_target(self):
        try:
            return DROIDBOT_TARGETS[self.task]
        except KeyError:
            raise NameError(f"Undefined task: {self.task}")

    @staticmethod
    def _sampled_img_std(path, border_fraction=0.1, sample_size=100): 
        img = Image.open(path).convert("L")  # Convert to grayscale
        arr = np.array(img)
        h, w = arr.shape
        bh = int(h * border_fraction)
        bw = int(w * border_fraction)
        arr = arr[bh:h-bh, bw:w-bw]

        flat = arr.flatten()
        # Randomly sample pixel values
        if sample_size < len(flat):
            sample = np.random.choice(flat, size=sample_size, replace=False)
        else:
            sample = flat
        return np.std(sample) 


if __name__ == "__main__":
    import time

    def benchmark_std_methods(folder):
        images = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".png")]

        print("\n--- _sampled_img_std Results ---")
        logger.warning("Using _sampled_img_std is slow (around 2x)! Recommend using img_std with sample_steps (if needed).")
        start = time.time()
        for img in images:
            std = DroidBotRunner._sampled_img_std(img)
            print(f"{img}: stddev = {std:.2f}")
        print(f"Time taken: {time.time() - start:.4f}s")

        print("\n--- _img_std (sample_step_x=108, sample_step_y=228) Results ---")
        start = time.time()
        for img in images:
            std = DroidBotRunner._img_std(img, sample_step_x=108, sample_step_y=228)
            print(f"{img}: stddev = {std:.2f}")
        print(f"Time taken: {time.time() - start:.4f}s")

        print("\n--- _img_std Results ---")
        start = time.time()
        for img in images:
            std = DroidBotRunner._img_std(img)
            print(f"{img}: stddev = {std:.2f}")
        print(f"Time taken: {time.time() - start:.4f}s")

    


    # Run benchmark
    benchmark_std_methods("test_inputs/img_std")
