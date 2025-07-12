# src/analyze_vulnerabilities/data_slicer.py
#!/usr/bin/env python3
"""
data_slicer.py — intra‑procedural data‑dependence slicer (LLVM‑IR)
=================================================================
* llvmlite 0.39.x対応版（LLVM 14用）
"""
from __future__ import annotations
import re
import sys
from pathlib import Path
from collections import defaultdict

import llvmlite.binding as llvm
import networkx as nx

# LLVM初期化
llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()

# ---------------------------------------------------------------------------
# ヘルパー関数
# ---------------------------------------------------------------------------

def load_module(path: Path) -> llvm.ModuleRef:
    """Parse .ll to ModuleRef"""
    try:
        return llvm.parse_assembly(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise RuntimeError(f"Failed to parse LLVM IR from {path}: {e}")


def get_function(mod: llvm.ModuleRef, name: str):
    """Get function by name from module"""
    for f in mod.functions:
        if f.name == name:
            return f
    return None


# ---------- CFG構築 ----------

def build_cfg(func) -> nx.DiGraph:
    """Build control flow graph from function"""
    g = nx.DiGraph()
    
    # llvmlite 0.39.xではblock.terminatorではなくblocks自体が持つ属性を使用
    for bb in func.blocks:
        g.add_node(bb)
        
        # llvmlite 0.39.xの場合、successorsは基本ブロック自体の属性
        if hasattr(bb, 'successors'):
            for succ in bb.successors:
                if hasattr(succ, 'name'):
                    g.add_edge(bb, succ)
        else:
            # 手動でterminator命令を解析
            instructions = list(bb.instructions)
            if instructions:
                last_inst = instructions[-1]
                # terminator命令のオペランドから後続ブロックを取得
                if hasattr(last_inst, 'opcode'):
                    if last_inst.opcode in ['br', 'switch']:
                        for op in last_inst.operands:
                            if hasattr(op, 'is_block') and op.is_block:
                                g.add_edge(bb, op)
                            elif hasattr(op, 'name') and op.name.startswith('%'):
                                # ブロックへの参照の可能性
                                for target_bb in func.blocks:
                                    if target_bb.name == op.name.lstrip('%'):
                                        g.add_edge(bb, target_bb)
                                        break
                            
    return g


# ---------- defs / uses収集 ----------

def collect_defs_uses(func):
    """Collect definitions and uses for each instruction"""
    defs, uses = {}, {}
    
    for bb in func.blocks:
        for inst in bb.instructions:
            d, u = set(), set()
            
            # SSA定義（左辺値）
            if hasattr(inst, 'name') and inst.name:
                d.add(inst.name)
                
            # オペランド（右辺値）
            for op in inst.operands:
                if hasattr(op, 'name') and op.name:
                    u.add(op.name)
                    
            defs[inst] = d
            uses[inst] = u
            
    return defs, uses


# ---------- Reaching Definitions解析 ----------

def reaching_defs(cfg, defs):
    """Compute reaching definitions using dataflow analysis"""
    gen, kill = {}, {}
    
    # 各基本ブロックのgen/kill集合を計算
    for bb in cfg.nodes:
        g, k = set(), set()
        for inst in bb.instructions:
            # 同じ変数の再定義を考慮
            for d in defs[inst]:
                k.add(d)  # 以前の定義をkill
            g |= defs[inst]  # 新しい定義をgen
        gen[bb], kill[bb] = g, k
        
    # データフロー方程式を反復解法
    IN, OUT = defaultdict(set), defaultdict(set)
    
    # ワークリストアルゴリズム
    worklist = list(cfg.nodes)
    
    while worklist:
        bb = worklist.pop(0)
        
        # IN[bb] = ∪(OUT[pred] for pred in predecessors)
        IN_new = set()
        for pred in cfg.predecessors(bb):
            IN_new |= OUT[pred]
            
        # OUT[bb] = gen[bb] ∪ (IN[bb] - kill[bb])
        OUT_new = gen[bb] | (IN_new - kill[bb])
        
        if IN_new != IN[bb] or OUT_new != OUT[bb]:
            IN[bb] = IN_new
            OUT[bb] = OUT_new
            # 後続ノードを再処理対象に追加
            for succ in cfg.successors(bb):
                if succ not in worklist:
                    worklist.append(succ)
                    
    return IN, OUT


# ---------- Backward slice計算 ----------

def backward_slice(func, taint_vars: set[str]):
    """Compute backward slice from tainted variables"""
    try:
        cfg = build_cfg(func)
        defs, uses = collect_defs_uses(func)
        IN, OUT = reaching_defs(cfg, defs)
        
        slice_instrs = set()
        worklist = []
        
        # 初期化: taint変数を使用する命令を収集
        for bb in func.blocks:
            for inst in bb.instructions:
                if uses[inst] & taint_vars:
                    slice_instrs.add(inst)
                    worklist.append((inst, uses[inst] & taint_vars))
                    
        # 依存関係を逆向きに辿る
        visited = set()
        
        while worklist:
            inst, needed_vars = worklist.pop()
            
            if (inst, tuple(sorted(needed_vars))) in visited:
                continue
            visited.add((inst, tuple(sorted(needed_vars))))
            
            bb = inst.parent
            
            # このブロックに到達する定義を調べる
            reaching = IN[bb]
            
            # ブロック内で必要な変数を定義する命令を探す
            for other_inst in bb.instructions:
                if other_inst == inst:
                    break  # inst以前の命令のみ対象
                defined = defs[other_inst]
                if defined & needed_vars:
                    if other_inst not in slice_instrs:
                        slice_instrs.add(other_inst)
                        worklist.append((other_inst, uses[other_inst]))
                        
            # 先行ブロックから到達する定義を探す
            for pred in cfg.predecessors(bb):
                for pred_inst in pred.instructions:
                    if defs[pred_inst] & needed_vars:
                        if pred_inst not in slice_instrs:
                            slice_instrs.add(pred_inst)
                            worklist.append((pred_inst, uses[pred_inst]))
                            
        return slice_instrs
        
    except Exception as e:
        # エラーが発生した場合は空のスライスを返す
        print(f"Warning: Slicing failed for {func.name}: {e}", file=sys.stderr)
        return set()


# ---------- DWARF行番号取得 ----------

# DILocationのパターン
_dilocation_patterns = [
    re.compile(r'!DILocation\([^)]*line:\s*(\d+)'),
    re.compile(r'line:\s*(\d+)'),
]

_dbg_id_re = re.compile(r'!dbg\s+!(\d+)')


def get_line(mod: llvm.ModuleRef, inst) -> int | None:
    """Get source line number from instruction debug info"""
    inst_str = str(inst)
    
    # !dbg !NNを探す
    m = _dbg_id_re.search(inst_str)
    if not m:
        return None
        
    dbg_id = int(m.group(1))
    
    try:
        # メタデータの取得方法はllvmliteのバージョンによって異なる
        if hasattr(mod, 'get_metadata'):
            md_str = str(mod.get_metadata(dbg_id))
        else:
            # 古いバージョンの場合
            md_str = ""
            
        # 各パターンで行番号を探す
        for pattern in _dilocation_patterns:
            m2 = pattern.search(md_str)
            if m2:
                return int(m2.group(1))
                
    except Exception:
        # メタデータ取得エラーは無視
        pass
        
    return None


# ---------- Public API ----------

def slice_lines(mod: llvm.ModuleRef, func_name: str, vars_csv: str) -> set[int]:
    """
    Compute sliced line numbers for given function and tainted variables
    
    Args:
        mod: LLVM module
        func_name: Target function name
        vars_csv: Comma-separated tainted variable names
        
    Returns:
        Set of line numbers in the slice
    """
    func = get_function(mod, func_name)
    if func is None:
        raise RuntimeError(f"Function '{func_name}' not found in module")
        
    taint_vars = {v.strip() for v in vars_csv.split(',') if v.strip()}
    if not taint_vars:
        return set()
        
    try:
        sliced = backward_slice(func, taint_vars)
        lines = {get_line(mod, inst) for inst in sliced}
        return {line for line in lines if line is not None}
    except Exception as e:
        # スライシング失敗時は空集合を返す（フォールバック）
        print(f"Warning: Slicing failed for {func_name}: {e}", file=sys.stderr)
        return set()


# ---------- CLI ----------
if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: data_slicer.py <file.ll> <func> <vars,comma>")
        sys.exit(1)
        
    try:
        mod = load_module(Path(sys.argv[1]))
        lines = slice_lines(mod, sys.argv[2], sys.argv[3])
        for ln in sorted(lines):
            print(ln)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)