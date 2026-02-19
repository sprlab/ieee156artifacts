from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

RED = '\033[91m'
GREEN = '\033[92m'
RESET = '\033[0m'


Label = object  # can use str/int/etc.
Predicate = Callable[[FrozenSet[Label]], bool]


@dataclass
class Node:
    """A tiny trie node for storing seen minimal sets (as sorted tuples)."""
    children: dict
    terminal: bool = False

    def __init__(self) -> None:
        self.children = {}
        self.terminal = False


class SetTrie:
    """
    Trie over sorted label tuples.
    Supports:
      - insert(s)
      - contains(s)
      - has_subset_of(s): True iff some inserted set t is a subset of s.
    """
    def __init__(self) -> None:
        self.root = Node()

    @staticmethod
    def _as_tuple(s: FrozenSet[Label], order_index: dict) -> Tuple[Label, ...]:
        return tuple(sorted(s, key=lambda x: order_index[x]))

    def insert(self, s: FrozenSet[Label], order_index: dict) -> None:
        t = self._as_tuple(s, order_index)
        cur = self.root
        for x in t:
            cur = cur.children.setdefault(x, Node())
        cur.terminal = True

    def contains(self, s: FrozenSet[Label], order_index: dict) -> bool:
        t = self._as_tuple(s, order_index)
        cur = self.root
        for x in t:
            nxt = cur.children.get(x)
            if nxt is None:
                return False
            cur = nxt
        return cur.terminal

    def has_subset_of(self, s: FrozenSet[Label], order_index: dict) -> bool:
        """
        Returns True if there exists an inserted set t such that t ⊆ s.
        Because trie edges are ordered, we can walk s's ordered tuple and
        choose to match or skip elements (subsequence test).
        """
        seq = self._as_tuple(s, order_index)

        def dfs(node: Node, i: int) -> bool:
            if node.terminal:
                return True
            if i >= len(seq):
                return False
            if dfs(node, i + 1):
                return True
            child = node.children.get(seq[i])
            if child is not None and dfs(child, i + 1):
                return True
            return False

        return dfs(self.root, 0)


def shrink_to_minimal(
    S: FrozenSet[Label],
    P: Predicate,
    shrink_callback: Optional[Callable[[str, FrozenSet[Label], FrozenSet[Label] | None], None]] = None
) -> FrozenSet[Label]:
    """
    SHRINKTOMINIMAL(S, P(.)):
      M <- S
      for all x in S do
        M' <- M \\ {x}
        if P(M') then M <- M'
      return M
    """
    if shrink_callback:
        shrink_callback("start", S, None)
    
    M = set(S)
    # iterate over a snapshot of S (original pseudocode does "for all x in S")
    for x in S:
        M2 = frozenset(M - {x})
        if P(M2):
            M.remove(x)
    M_final = frozenset(M)
    if shrink_callback:
        shrink_callback("done", S, M_final)
    return M_final


def enumerate_minimal_satisfying_cutsets(
    L: Sequence[Label],
    P: Predicate,
    shrink_callback: Optional[Callable[[str, FrozenSet[Label], FrozenSet[Label] | None], None]] = None,
) -> List[FrozenSet[Label]]:
    """
    Algorithm 1: Minimal Satisfying Cut-set Enumeration for a Monotone Predicate

    Input:
      - fixed-order indexable label set L = [l1, ..., ln]
      - monotone predicate P over sets of labels

    Output:
      - all minimal cut-sets s ⊆ L such that P(s) == True
    """
    order_index = {lab: i for i, lab in enumerate(L)}  
    result: List[FrozenSet[Label]] = []
    seen = SetTrie()

    print(f"\n[Initial check] Testing with all {len(L)} elements...")
    if not P(frozenset(L)):
        print(f"[Initial check] Entire set does not satisfy predicate - no solutions exist")
        return result

    print(f"[Initial check] Entire set satisfies predicate - proceeding with search\n")
    n = len(L)

    def DFS(S: FrozenSet[Label], nxtLblIdx: int, depth_limit: int) -> None:
        
        if seen.contains(S, order_index) or len(S) > depth_limit:
            return

        if P(S):
            s_min = shrink_to_minimal(S, P, shrink_callback)
            if not seen.has_subset_of(s_min, order_index):
                seen.insert(s_min, order_index)
                result.append(s_min)
            return   

        for i in range(nxtLblIdx, n):
            if len(S) + 1 > depth_limit:
                break
            DFS(frozenset(set(S) | {L[i]}), i + 1, depth_limit)

    print(f"[Search] Exploring sets of increasing size (1 to {n})...\n")
    for depth in range(1, n + 1):
        DFS(frozenset(), 0, depth)
        if depth < n:
            print(f"[Search] Completed size {depth}, found {len(result)} minimal set(s) so far\n")

    print(f"\n[Search] Complete - explored all sizes up to {n}")
    return result


if __name__ == "__main__":
    L = ["a", "b", "c", "d", "e"]

    def P(S: FrozenSet[str]) -> bool:
        return (len(S.intersection({"a", "b"})) >= 1) and (len(S.intersection({"c", "d"})) >= 1)

    mins = enumerate_minimal_satisfying_cutsets(L, P)
    for s in mins:
        print(sorted(s))
