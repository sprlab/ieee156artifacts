from inputimeout import inputimeout, TimeoutOccurred

def _timeout_msg(timeout):
    return f"No input detected in {timeout} seconds. Defaulting to 'no'."

def ask_to_continue(prompt="Do you want to continue? (y to continue or n to exit): ", timeout=10):
    prompt = prompt.strip() + " "
    try:
        choice = inputimeout(prompt=prompt, timeout=timeout).strip().lower()
    except TimeoutOccurred:
        print(_timeout_msg(timeout))
        exit()

    if choice == 'y':
        return
    elif choice == 'n':
        exit()
    else:
        print("""Invalid input. Please enter "y" or "n".""")
        return ask_to_continue(prompt, timeout)


def ask_to_try_again(prompt="Do you want to try again? (y/n): ", timeout=10):
    prompt = prompt.strip() + " "
    while True:
        try:
            choice = inputimeout(prompt=prompt, timeout=timeout).strip().lower()
        except TimeoutOccurred:
            print(_timeout_msg(timeout))
            choice = 'n'

        if choice == 'y':
            return True
        elif choice == 'n':
            return False
        else:
            print("""Invalid input. Please enter "y" or "n".""")

def ask_to_enter_int(prompt="Please enter a number: ", timeout=10):
    prompt = prompt.strip() + " "
    while True:
        try:
            choice = inputimeout(prompt=prompt, timeout=timeout).strip().lower()
        except TimeoutOccurred:
            print(_timeout_msg(timeout))
            exit()

        number = input(f"{prompt}").strip()
        
        if number.isdigit():  # If it's a whole number
            return int(number)
        else:
            print("Input must be an integer.", end=" ")
            return ask_to_enter_int(prompt) 