"""
Main script to generate minimal leak mincutsets and create corresponding .spthy files.

This script:
1. Defines available leak types from automator/leak_rules.json
2. Uses min_cut_set algorithm to find minimal combinations that satisfy a predicate
3. Generates .spthy files in leaks/ directory for each minimal mincutset
4. Optionally updates main.spthy to include a specific leak file
"""

import argparse
import time
from pathlib import Path
from typing import Callable, FrozenSet

from automator.min_cut_set import enumerate_minimal_satisfying_cutsets

RED = '\033[91m'
GREEN = '\033[92m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
YELLOW = '\033[93m'
RESET = '\033[0m'

from automator.tamarin_utils import (
    generate_summary_report,
    get_leak_filename,
    load_leak_rules,
    reset_progress_counter,
    security_predicate,
    set_progress_callback,
)


def apply_test_mode_limit_leaks(leak_rules: dict[str, str], limit: int) -> list[str]:
    """
    [TEST MODE] Limit to first N leaks from JSON file.
    
    Args:
        leak_rules: Dictionary of leak rules
        limit: Number of leaks to use
    
    Returns:
        List of leak names (first N from JSON order)
    """
    all_leaks = list(leak_rules.keys())
    leak_list = all_leaks[:limit]
    print(f"[TEST MODE] Limited to first {limit} leaks from JSON")
    print(f"[TEST MODE] Using leaks: {leak_list}\n")
    return leak_list


def run_analysis(
    lemma_name: str,
    leak_list: list[str],
    predicate: Callable[[FrozenSet[str]], bool] | None = None
) -> list[FrozenSet[str]]:
    """
    Run the main analysis to find minimal mincutsets.
    
    Args:
        lemma_name: Name of the lemma to test
        leak_list: List of leak names to consider
        predicate: Optional custom predicate function. If None, uses default security_predicate.
    
    Returns:
        List of minimal mincutsets that violate the security property
    """
    print(f"{'='*80}")
    print(f"Analysis Configuration")
    print(f"{'='*80}")
    print(f"  Security property (lemma): {lemma_name}")
    print(f"  Available leak types: {len(leak_list)}")
    print(f"  Leaks: {', '.join(leak_list)}")
    
    if leak_list:
        example_set = frozenset(leak_list)
        example_base_name = get_leak_filename(example_set).replace(".spthy", "")
        print(f"  Example filename format: {example_base_name}")
    
    print(f"\n{'='*80}")
    print(f"Starting Search")
    print(f"{'='*80}")
    print(f"Finding min-cut sets that violate '{PURPLE}{lemma_name}{RESET}'.")
    print(f"This will generate .spthy files and run tamarin-prover for each candidate.\n")
    
    reset_progress_counter()
    
    analysis_start_time = time.time()
    
    leak_rules = load_leak_rules()
    json_order = list(leak_rules.keys())
    
    def progress_callback(counter: int, leak_set: FrozenSet[str], result: bool | None) -> None:
        leak_names = [name for name in json_order if name in leak_set]
        base_name = get_leak_filename(leak_set).replace(".spthy", "")

        num = str(counter)
        pad = " " * max(0, 4 - len(num)) 
        prefix = f"  {pad}[{num}] "
        cont = " " * len(prefix)

        stdout_path = Path("results") / "stdout" / lemma_name / f"{base_name}.stdout"
        
        if result is None:
            print(f"{prefix}Test set: {BLUE}{{{', '.join(leak_names)}}}{RESET}")
            print(f"{cont}Stdout: {stdout_path}")
        else:
            if result:
                result_text = f"{RED}FALSIFIED{RESET}"
            else:
                result_text = f"{GREEN}verified{RESET}"
            print(f"{cont}Result: {result_text}\n")
            
            if counter > 0 and counter % 10 == 0:
                elapsed = time.time() - analysis_start_time
                minutes = int(elapsed // 60)
                seconds = int(elapsed % 60)
                
                avg_time_per_test = elapsed / counter
                avg_seconds = int(avg_time_per_test)
                avg_ms = int((avg_time_per_test - avg_seconds) * 1000)
                
                total_combinations = 2 ** len(leak_list)
                
                estimated_total_time = avg_time_per_test * total_combinations
                est_minutes = int(estimated_total_time // 60)
                est_seconds = int(estimated_total_time % 60)
                est_hours = int(est_minutes // 60)
                est_minutes = est_minutes % 60
                
                elapsed_str = f"{minutes}m {seconds}s"
                avg_str = f"{avg_seconds}s {avg_ms}ms" if avg_ms > 0 else f"{avg_seconds}s"
                
                if est_hours > 0:
                    est_str = f"{est_hours}h {est_minutes}m {est_seconds}s"
                elif est_minutes > 0:
                    est_str = f"{est_minutes}m {est_seconds}s"
                else:
                    est_str = f"{est_seconds}s"
                
                print(f"[Progress] {counter} tests completed | Elapsed: {elapsed_str} | Avg: {avg_str}/test")
                print(f"          Estimated time for {total_combinations} combinations: {est_str}\n")
    
    set_progress_callback(progress_callback)
    
    if predicate is None:
        def predicate(leak_set: FrozenSet[str]) -> bool:
            return security_predicate(leak_set, lemma_name)

    predicate_cache: dict[FrozenSet[str], bool] = {}

    def memoized_predicate(leak_set: FrozenSet[str]) -> bool:
        if leak_set in predicate_cache:
            cached_res = predicate_cache[leak_set]
            leak_names = [name for name in json_order if name in leak_set]
            cached_text = f"{RED}FALSIFIED{RESET}" if cached_res else f"{GREEN}verified{RESET}"
            print(f"      {YELLOW}[Cache hit]{RESET} {BLUE}{{{', '.join(leak_names)}}}{RESET} -> {cached_text}\n")
            return cached_res
        res = predicate(leak_set)
        predicate_cache[leak_set] = res
        return res
    
    def shrink_callback(stage: str, original_set: FrozenSet[str], minimal_set: FrozenSet[str] | None) -> None:
        if stage == "start":
            leak_names = [name for name in json_order if name in original_set]
            print(f"  [Shrinking] Found falsifying set with {len(original_set)} leaks: {', '.join(leak_names)}")
            print("  [Shrinking] Attempting to find minimal subset...\n")
            return

        if stage == "done" and minimal_set is not None:
            leak_names = [name for name in json_order if name in minimal_set]
            filename = get_leak_filename(minimal_set)
            stdout_path = Path("results") / "stdout" / lemma_name / f"{filename.replace('.spthy', '')}.stdout"
            print(f"  [Shrinking] Complete -> minimal set size {len(minimal_set)}: {', '.join(leak_names)}")
            print(f"              Stdout: {stdout_path}\n")
            return
    
    minimal_mincutsets = enumerate_minimal_satisfying_cutsets(
        leak_list,
        memoized_predicate,
        shrink_callback,
    )
    
    return minimal_mincutsets


def display_results(lemma_name: str, minimal_mincutsets: list[FrozenSet[str]], leak_list: list[str]) -> None:
    """
    Display found mincutsets and generate summary report.
    
    Args:
        lemma_name: Name of the lemma tested
        minimal_mincutsets: List of found minimal mincutsets
        leak_list: List of all leak types considered
    """
    print(f"\n{'='*80}")
    print(f"Results Summary")
    print(f"{'='*80}")
    print(f"Found {len(minimal_mincutsets)} minimal mincutset(s) that violate '{lemma_name}':\n")
    
    if minimal_mincutsets:
        json_order = list(load_leak_rules().keys())
        for idx, mincutset in enumerate(minimal_mincutsets, start=1):
            leak_names = [name for name in json_order if name in mincutset]
            filename = get_leak_filename(mincutset)

            base_name = filename.replace(".spthy", "")
            stdout_path = Path("results") / "stdout" / lemma_name / f"{base_name}.stdout"

            print(f"  [{idx}] {', '.join(leak_names)}")
            print(f"      Size: {len(mincutset)} leak(s)")
            print(f"      Stdout: {stdout_path}\n")
        
        report_file = generate_summary_report(lemma_name, minimal_mincutsets, leak_list)
        print(f"  Summary report: {report_file}")
    else:
        print(f"  No minimal mincutsets found - security property holds for all leak combinations.")


if __name__ == "__main__":
    start_time = time.time()
    
    parser = argparse.ArgumentParser(description="Find minimal leak mincutsets that violate a security property")
    parser.add_argument(
        "lemma",
        help="Name of the lemma to test (e.g., TestCardCloningResistance, TestSimultaneousAuthentication)"
    )

    parser.add_argument(
        "--test-limit-leaks",
        type=int,
        metavar="N",
        help="[TEST MODE] Limit to first N leaks from JSON file (e.g., --test-limit-leaks 6)"
    )
    
    parser.add_argument(
        "--test-min-size",
        type=int,
        metavar="N",
        help="[TEST MODE] Start testing from sets of size N (skip smaller sets, e.g., --test-min-size 6)"
    )
    args = parser.parse_args()
    
    lemma_name = args.lemma
    leak_rules = load_leak_rules()
    
    if args.test_limit_leaks:
        leak_list = apply_test_mode_limit_leaks(leak_rules, args.test_limit_leaks)
    else:
        leak_list = list(leak_rules.keys())
    
    if args.test_min_size:
        print(f"[TEST MODE] Starting from sets of size {args.test_min_size} (skipping smaller sets)\n")
        def filtered_predicate(leak_set: FrozenSet[str]) -> bool:
            if len(leak_set) < args.test_min_size:
                return False
            return security_predicate(leak_set, lemma_name)
        predicate = filtered_predicate
    else:
        predicate = None  

    minimal_mincutsets = run_analysis(lemma_name, leak_list, predicate)
    
    display_results(lemma_name, minimal_mincutsets, leak_list)
    
    elapsed_time = time.time() - start_time
    print(f"\n{'='*80}")
    print(f"Total execution time: {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
    print(f"{'='*80}")