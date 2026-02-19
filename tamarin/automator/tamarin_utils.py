"""Utility functions for running tamarin-prover and processing results."""

import json
import re
import subprocess
from pathlib import Path
from typing import Callable, FrozenSet

PROJECT_ROOT = Path(__file__).parent.parent
LEAK_RULES_PATH = PROJECT_ROOT / "automator" / "leak_rules.json"
LEAK_RULES_SHORT_PATH = PROJECT_ROOT / "automator" / "leak_rules_short.json"
LEAKS_DIR = PROJECT_ROOT / "leaks"
MAIN_SPTHY_PATH = PROJECT_ROOT / "main.spthy"
RESULTS_DIR = PROJECT_ROOT / "results"
STDOUT_DIR = RESULTS_DIR / "stdout"
STDERR_DIR = RESULTS_DIR / "stderr"

_progress_counter = 0
_progress_callback: Callable[[int, FrozenSet[str], bool | None], None] = None


def load_leak_rules() -> dict[str, str]:
    """Load leak rules from JSON file."""
    with open(LEAK_RULES_PATH, 'r') as f:
        return json.load(f)


def load_leak_short_names() -> dict[str, str]:
    """Load leak short name mappings from JSON file."""
    with open(LEAK_RULES_SHORT_PATH, 'r') as f:
        return json.load(f)


def get_short_name(leak_name: str) -> str:
    """
    Get short name for a leak from leak_rules_short.json.
    
    Args:
        leak_name: Original leak name
    
    Returns:
        Short name from JSON, or original if not found
    """
    short_names = load_leak_short_names()
    return short_names.get(leak_name, leak_name)


def get_leak_filename(leak_names: FrozenSet[str]) -> str:
    """
    Generate a filename from leak names, ordered by JSON key order.
    Uses short names concatenated without separator.
    
    Args:
        leak_names: Set of leak names (e.g., {"AIP", "CVM", "SessionKey"})
    
    Returns:
        Filename like "AipCvmSk.spthy" (ordered by JSON key order, no separator)
    """
    if not leak_names:
        return "NoLeaks.spthy"

    rules = load_leak_rules()
    ordered_leaks = [name for name in rules.keys() if name in leak_names]
    short_names = [get_short_name(name) for name in ordered_leaks]
    return "".join(short_names) + ".spthy"


def generate_leak_file(leak_names: FrozenSet[str], output_path: Path) -> None:
    """
    Generate a .spthy file by copying rules from the JSON file.
    
    Args:
        leak_names: Set of leak names to include (e.g., {"AIP", "ATC", "Token"})
        output_path: Path where the .spthy file should be written
    """
    rules = load_leak_rules()
    
    output_lines = []
    for leak_name in rules.keys():
        if leak_name in leak_names:
            output_lines.append(rules[leak_name])
            output_lines.append('') 
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write('\n'.join(output_lines))
        if output_lines: 
            f.write('\n')


def update_main_spthy_include(main_spthy_path: Path, leak_filename: str, leak_names: FrozenSet[str] = None) -> None:
    """
    Update the #include line and theory name in main.spthy.
    
    Args:
        main_spthy_path: Path to main.spthy
        leak_filename: Name of the leak file (e.g., "CR1.spthy" or "cutset_001.spthy")
        leak_names: Optional set of leak names to use for theory name (e.g., {"AIP", "CVM", "SessionKey"})
    """
    if not main_spthy_path.exists():
        raise FileNotFoundError(f"main.spthy not found: {main_spthy_path}")
    
    with open(main_spthy_path, 'r') as f:
        content = f.read()
    
    pattern = r'#include\s+"leaks/[^"]+"'
    replacement = f'#include "leaks/{leak_filename}"'
    new_content = re.sub(pattern, replacement, content)
    
    if leak_names is not None:
        if not leak_names:
            leak_suffix = "NoLeaks"
        else:
            rules = load_leak_rules()
            ordered_leaks = [name for name in rules.keys() if name in leak_names]
            short_names = [get_short_name(name) for name in ordered_leaks]
            leak_suffix = "".join(short_names)
        theory_pattern = r'^theory\s+leak[\w\d]+'
        theory_replacement = f'theory leak{leak_suffix}'
        new_content = re.sub(theory_pattern, theory_replacement, new_content, flags=re.MULTILINE)
    
    with open(main_spthy_path, 'w') as f:
        f.write(new_content)


def run_tamarin_prover(lemma_name: str = "TestCardCloningResistance") -> tuple[str, str, int]:
    """
    Run tamarin-prover on main.spthy and return stdout, stderr, and return code.
    
    Args:
        lemma_name: Lemma name to prove (e.g., "TestCardCloningResistance")
    
    Returns:
        Tuple of (stdout, stderr, return_code)
    """
    cmd = [
        "tamarin-prover",
        "main.spthy",
        "--derivcheck-timeout=120",
        f"--prove={lemma_name}",
        "-c=50"
    ]

    num_min_timeout = 1
    
    try:
        result = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60*num_min_timeout
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {num_min_timeout} minutes", -1
    except FileNotFoundError:
        return "", "tamarin-prover not found in PATH", -1
    except Exception as e:
        return "", f"Error running tamarin-prover: {str(e)}", -1


def parse_tamarin_result(stdout: str, stderr: str, return_code: int, lemma_name: str) -> bool:
    """
    Parse tamarin-prover output to determine if the security property is falsified.
    
    Returns True if the proof FAILED (security violation found), False if proof succeeded.
    
    Args:
        stdout: Standard output from tamarin-prover
        stderr: Standard error from tamarin-prover
        return_code: Return code from tamarin-prover
        lemma_name: Name of the lemma being tested (e.g., "TestCardCloningResistance")
    
    Returns:
        True if security property is falsified (proof failed/violated), False if verified
    """
 
    lines = stdout.splitlines()
    pattern = rf"{re.escape(lemma_name)}\s+\([^)]+\):\s+(falsified|verified)"
    for line in reversed(lines):
        match = re.search(pattern, line)
        if match:
            result = match.group(1).lower()
            if result == "falsified":
                return True
            elif result == "verified":
                return False
    return False


def set_progress_callback(callback: Callable[[int, FrozenSet[str], bool | None], None]) -> None:
    """Set a callback function to report progress."""
    global _progress_callback
    _progress_callback = callback


def reset_progress_counter() -> None:
    """Reset the progress counter."""
    global _progress_counter
    _progress_counter = 0


def generate_summary_report(lemma_name: str, mincutsets: list[FrozenSet[str]], leak_list: list[str]) -> Path:
    """
    Generate a summary report of found mincutsets and save it to results directory.
    
    Args:
        lemma_name: Name of the lemma tested
        mincutsets: List of minimal cut-sets that violate the property
        leak_list: List of all available leak types
    
    Returns:
        Path to the generated summary report file
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    report_file = RESULTS_DIR / f"summary_{lemma_name}.txt"
    
    with open(report_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write(f"SUMMARY REPORT: {lemma_name}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Lemma tested: {lemma_name}\n")
        f.write(f"Total available leak types: {len(leak_list)}\n")
        f.write(f"Leak types: {', '.join(leak_list)}\n\n")
        
        f.write(f"Found {len(mincutsets)} minimal cut-sets that violate the security property:\n\n")
        
        for idx, mincutset in enumerate(mincutsets, start=1):
            leak_names = sorted(mincutset)
            filename = get_leak_filename(mincutset)
            f.write(f"  {idx}. {', '.join(leak_names)}\n")
            f.write(f"     File: {filename}\n")
            f.write(f"     Leak count: {len(mincutset)}\n\n")
        
        f.write("=" * 80 + "\n")
    
    return report_file


def security_predicate(leak_set: FrozenSet[str], lemma_name: str) -> bool:
    """
    Predicate that tests if a leak combination violates the security property.

    This function:
    1. Generates a leak file for the given cut-set
    2. Updates main.spthy to include that leak file
    3. Runs tamarin-prover to check the security property
    4. Returns True if the property is falsified (proof failed), False otherwise

    Args:
        leak_set: Set of leak names to test
        lemma_name: Name of the lemma to test

    Returns:
        True if security property is falsified, False if property holds
    """
    global _progress_counter, _progress_callback
    
    if _progress_callback:
        _progress_callback(_progress_counter, leak_set, None)
    
    _progress_counter += 1
    
    filename = get_leak_filename(leak_set)
    output_path = LEAKS_DIR / filename

    lemma_stdout_dir = STDOUT_DIR / lemma_name
    lemma_stderr_dir = STDERR_DIR / lemma_name
    lemma_stdout_dir.mkdir(parents=True, exist_ok=True)
    lemma_stderr_dir.mkdir(parents=True, exist_ok=True)

    try:
        
        generate_leak_file(leak_set, output_path)
        update_main_spthy_include(MAIN_SPTHY_PATH, filename, leak_set)

        stdout, stderr, return_code = run_tamarin_prover(lemma_name)

        base_name = filename.replace(".spthy", "")
        stdout_file = lemma_stdout_dir / f"{base_name}.stdout"
        stderr_file = lemma_stderr_dir / f"{base_name}.stderr"

        with open(stdout_file, 'w') as f:
            f.write(stdout)

        if stderr:
            with open(stderr_file, 'w') as f:
                f.write(stderr)

        is_falsified = parse_tamarin_result(stdout, stderr, return_code, lemma_name)
        
        if _progress_callback:
            _progress_callback(_progress_counter - 1, leak_set, is_falsified)

        return is_falsified

    finally:
        if output_path.exists():
            pass

