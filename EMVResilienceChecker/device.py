import xml.etree.ElementTree as ET

from util import run_cmd
from util import wait_until
from util import adb_action
from loguru import logger



class Device:
    """Class for managing device interactions"""

    """NOTE: consider refactoring with adbutils: https://github.com/openatx/adbutils"""

    @staticmethod
    def take_screenshot():
        return

    @staticmethod 
    def tap(x, y):
        """Tap the sceen at the given centers"""
        run_cmd(['adb', 'shell', 'input', 'tap', str(x), str(y)])

    @staticmethod
    def tap_home():
        """Simulate pressing the Home button."""
        run_cmd(['adb', 'shell', 'input', 'keyevent', '3'])

    @staticmethod
    def get_ui_xml(): # Maybe this should be in Device class
        """Gets the UI components in XML"""

        dump_result = run_cmd(['adb', 'shell', 'uiautomator', 'dump'])
        cat_result = run_cmd(['adb', 'shell', 'cat', '/sdcard/window_dump.xml'])

        return cat_result.stdout

    @staticmethod
    def open_in_play_store(package_name, emulator_id=None):
        """
        Opens the specified Play Store app page on the emulator.

        :param emulator_id: The ID of the emulator (e.g., emulator-5554)
        """

        result = run_cmd(['adb', 'shell', 'am', 'start', '-a', 'android.intent.action.VIEW', '-d', f'"https://play.google.com/store/apps/details?id={package_name}"'])
        logger.info("""This may throw a warning even if the app store is opened: "Activity not started, ..." """) # Let's check if it opened with a different method

        app_store_ui = None
        condition = lambda stdout: "com.android.vending/com.android.vending.AssetBrowserActivity" in stdout or "com.android.vending/com.google.android.finsky.activities.MainActivity" in stdout
        cmd = ['adb', 'shell', 'dumpsys', 'window', '|', 'grep', 'mCurrentFocus']
        app_store_opened = wait_until(condition, cmd)    

        if app_store_opened:
            logger.info("App store opened")
            app_store_ui = Device.get_ui_xml()
        else:
            logger.error("Could not open app in Play Store. Please check manually (e.g. check if you're signed in to Play Store).")
            exit()

        return app_store_ui

    @staticmethod
    def _calc_center(bounds):
        """
        :param bounds: e.g. [720,631][851,686] from XML returend from parse_xml
        """
        x1, y1, x2, y2 = map(int, bounds.replace("[", "").replace("]", ",").split(",")[:-1])
        x = (x1 + x2) // 2
        y = (y1 + y2) // 2
        return (x, y)

    @staticmethod
    def is_button_clickable(xml_string, target=None, debug=False): # TODO: refactor
        """
        Parse XML structure with attributes and text content. Locates center of target component. If no target is specified, then it will print out all the XML.

        :param xml_string: The XML string to parse.
        :param target: desired component
        :param debug: Prints out the XML

        returns center of target bounds as x,y coordinates
        """
        # print(xml_string)
        if not target:
            debug = True
        
        try:
            root = ET.fromstring(xml_string)

            got_button = False
            parent = None
            button_clickable = False

            def recurse(element, level=0):

                nonlocal got_button
                nonlocal parent
                nonlocal button_clickable

                if got_button:
                    return

                indent = "  " * level
                if debug:
                    print(f"{indent}<{element.tag}>")

                d = element.attrib

                if d:

                    if debug:
                        for attr, value in d.items():
                            print(f"{indent}  @{attr} = {value}")

                    if target:
                        try:
                            if d['class'] == "android.widget.TextView" and d['package'] == "com.android.vending" and d['text'] == target: # May need to remove d['package'] == "com.android.vending" since this is for Play store only?
                                
                                got_button = True

                                p = parent.attrib

                                # 'enabled' used to be 'focusable'...seems like these could change at any time...
                                if p['class'] == "android.view.View" and p['package'] == "com.android.vending" and p['enabled'] == "true": # May need to remove d['package'] == "com.android.vending" since this is for Play store only?
                                    button_clickable = True  
                                    logger.debug(f"Button should be clickable: {button_clickable}")

                        except Exception as e:
                            logger.debug(f"Exception: {e}")

                if debug and element.text and element.text.strip():
                    print(f"{indent}  Text: {element.text.strip()}")

                for child in element:
                    parent = element
                    recurse(child, level + 1)

            recurse(root)
            logger.debug(f"Return value check: {button_clickable}")
            return button_clickable

        except ET.ParseError as e:
            logger.error(f"Failed to parse XML: {e}")    

    @staticmethod
    def get_center(xml_string, target=None, debug=False): # TODO: refactor
        """
        Parse XML structure with attributes and text content. Locates center of target component. If no target is specified, then it will print out all the XML.

        :param xml_string: The XML string to parse.
        :param target: desired component
        :param debug: Prints out the XML

        returns center of target bounds as x,y coordinates
        """

        if not target:
            debug = True
        
        try:
            root = ET.fromstring(xml_string)

            center = None

            def recurse(element, level=0):

                nonlocal center 
                if center:
                    return 

                indent = "  " * level
                if debug:
                    print(f"{indent}<{element.tag}>")

                d = element.attrib

                if d:
                    
                    if debug:
                        for attr, value in d.items():
                            print(f"{indent}  @{attr} = {value}")

                    if target:
                        try:
                            if d['class'] == "android.widget.TextView" and d['package'] == "com.android.vending" and d['text'] == target: # May need to remove d['package'] == "com.android.vending" since this is for Play store only?
                                center = Device._calc_center(d['bounds'])
                        except Exception as e:
                            logger.debug(f"Exception: {e}")


                if debug and element.text and element.text.strip():
                    print(f"{indent}  Text: {element.text.strip()}")

                for child in element:
                    recurse(child, level + 1)

            recurse(root)
            logger.debug(f"Center of {target}: {center}")
            return center

        except ET.ParseError as e:
            logger.error(f"Failed to parse XML: {e}")

    @staticmethod
    def pull_apk(package_name, target_location):
        """Pulls APK from device to local machine"""
        apk_paths = run_cmd(["adb", "shell", "pm", "path", package_name]).stdout.replace("package:","").split("\n")
        for apk_path in apk_paths[:-1]:
            logger.debug(f"APK to pull: {apk_path}")
            run_cmd(["adb", "pull", apk_path, target_location])

    @staticmethod
    def adb_root():
        return adb_action(["adb", "root"], "adb root")

    @staticmethod
    def adb_remount():
        return adb_action(["adb", "remount"], "adb remount")


