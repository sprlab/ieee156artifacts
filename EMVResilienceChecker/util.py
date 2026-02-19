import time
import subprocess

from loguru import logger
from userinput import ask_to_try_again

from constants import ADB_ERROR_TAG

def run_cmd(cmd, exit_on_error=False, quiet=False, capture_output=True, timeout=None):
    """
    Helper function to run any shell command with consistent handling. Designed for interaction with adb

    :param cmd: List of command arguments (e.g., ['adb', 'shell', 'ls'])
    :return: CompletedProcess object with stdout and stderr
    """
    result = subprocess.run(cmd,
                            capture_output=True,
                            text=True,
                            # check=True
                            timeout=timeout
                            )

    if result.stderr:
        if result.stderr.startswith("Warning: ") and not quiet:
            logger.warning(cmd)
            logger.warning(result.stderr.strip().replace("Warning: ", ""))
        else:
            if not quiet:
                logger.error(cmd)
                logger.error(result.stderr.strip())
            if exit_on_error:
                exit()
        # ask_to_continue()

    return result

def adb_action(cmd, action_name):
    """
    Incase error was not thrown but the error tag was shown...
    """
    result = run_cmd(cmd)
    if ADB_ERROR_TAG in result.stdout:
        logger.warning(f"{' '.join(cmd)} failed: {result.stdout.replace(ADB_ERROR_TAG, '')}")
        return False
    return True

def wait_until(condition, cmd=None, do=None, timeout=2, increment=1):
    elapsed = 0
    while elapsed<timeout: # elapsed is effectively num attempts and timeout is effectively max attempts allowed
        if cmd:
            result = run_cmd(cmd)   
            if condition(result.stdout):
                return True
        elif do:
            if condition(do()):
                return True
        else:
            if condition():
                return True

        time.sleep(increment)
        elapsed += increment

    WARNING_MSG = "*** Errors may occur if you proceed. Please check the device for more info. ***"
    if cmd:
        logger.warning(f"Condition check timed out for cmd: {cmd}. {WARNING_MSG}")
    else:
        logger.warning(f"Condition check timed out (no cmd): {condition}. {WARNING_MSG}")

    if ask_to_try_again():
        wait_until(condition, cmd, do, timeout, increment)

    return False


