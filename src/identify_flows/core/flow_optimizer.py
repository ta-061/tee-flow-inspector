#!/usr/bin/env python3
"""
core/flow_optimizer.py - 候補フローの最適化と重複除去（最終修正版）
同一シンク・同一行のparam_indexをマージ
サブチェイン判定を改善（異なる行番号のフローは保持）
"""

from typing import List, Dict, Any, Set, Tuple, Union
from collections import defaultdict


class FlowOptimizer:
    """候補フローの最適化器"""
    
    def __init__(self, verbose: bool = False):
        """
        Args:
            verbose: 詳細出力フラグ
        """
        self.verbose = verbose
    
    def optimize(self, flows: List[Dict]) -> List[Dict]:
        """
        候補フローを最適化
        
        Args:
            flows: 候補フローのリスト
        
        Returns:
            最適化されたフローのリスト
        """
        if self.verbose:
            print(f"[FlowOptimizer] Optimizing {len(flows)} flows...")
            print(f"  Initial flows:")
            for flow in flows:
                vd = flow['vd']
                chain = flow.get('chains', {}).get('function_chain', [])
                print(f"    - {vd['sink']}@{vd['line']} chain: {' -> '.join(chain)}")
        
        # Step 1: 同一シンク・同一チェインのparam_indexをマージ
        flows = self._merge_param_indices(flows)
        
        # Step 2: 重複を除去
        flows = self._remove_duplicates(flows)
        
        # Step 3: サブチェインを除去（ただし行番号が異なる場合は保持）
        flows = self._remove_subchains(flows)
        
        # Step 4: 同一関数内の同じシンク呼び出しをマージ（行番号の配列化）
        flows = self._merge_same_function_sinks(flows)
        
        # Step 5: パラメータインデックスを整理
        flows = self._organize_param_indices(flows)
        
        if self.verbose:
            print(f"[FlowOptimizer] Optimized to {len(flows)} flows")
            print(f"  Final flows:")
            for flow in flows:
                vd = flow['vd']
                chain = flow.get('chains', {}).get('function_chain', [])
                print(f"    - {vd['sink']}@{vd['line']} chain: {' -> '.join(chain)}")
        
        return flows
    
    def _merge_param_indices(self, flows: List[Dict]) -> List[Dict]:
        """
        同一シンク・同一チェインの異なるparam_indexを持つフローをマージ
        
        Args:
            flows: フローのリスト
        
        Returns:
            マージされたフローのリスト
        """
        # グループ化のキー: (file, line, sink, function_chain, source_func)
        groups = defaultdict(list)
        
        for flow in flows:
            vd = flow['vd']
            chains = flow.get('chains', {})
            
            # lineが配列の場合も考慮
            line = vd.get('line')
            if isinstance(line, list):
                line_key = tuple(sorted(line))
            else:
                line_key = line
            
            chain_tuple = tuple(chains.get('function_chain', []))
            call_lines_tuple = self._serialize_call_lines_for_key(
                chains.get('function_call_line', [])
            )
            
            key = (
                vd['file'],
                line_key,
                vd['sink'],
                chain_tuple,
                call_lines_tuple,
                flow.get('source_func', '')
            )
            groups[key].append(flow)
        
        # グループをマージ
        merged = []
        for key, group_flows in groups.items():
            if len(group_flows) == 1:
                merged.append(group_flows[0])
            else:
                # 複数のparam_indexを持つフローをマージ
                merged_flow = self._merge_param_index_group(group_flows)
                if self.verbose:
                    indices = [f['vd']['param_index'] for f in group_flows]
                    print(f"  Merged param_indices {indices} for {group_flows[0]['vd']['sink']} at line {group_flows[0]['vd']['line']}")
                merged.append(merged_flow)
        
        return merged
    
    def _merge_param_index_group(self, flows: List[Dict]) -> Dict:
        """
        同じグループの異なるparam_indexを持つフローをマージ
        
        Args:
            flows: マージするフローのリスト
        
        Returns:
            マージされたフロー（単一のparam_indexを保持）
        """
        # ベースフローをコピー（最小のparam_indexを持つものを選択）
        flows_sorted = sorted(flows, key=lambda f: f['vd']['param_index'])
        merged = flows_sorted[0].copy()
        merged['vd'] = flows_sorted[0]['vd'].copy()
        merged['chains'] = flows_sorted[0]['chains'].copy()
        
        # すべてのparam_indexを収集
        all_indices = []
        for flow in flows:
            idx = flow['vd']['param_index']
            if idx not in all_indices:
                all_indices.append(idx)
            # param_indicesも考慮
            if 'param_indices' in flow['vd']:
                for idx in flow['vd']['param_indices']:
                    if idx not in all_indices:
                        all_indices.append(idx)
        
        # param_indicesを更新（ソート済み）
        merged['vd']['param_indices'] = sorted(all_indices)
        # param_indexは最小値を保持
        merged['vd']['param_index'] = min(all_indices)
        
        return merged
    
    def _serialize_call_lines_for_key(self, call_lines: List[Any]) -> Tuple:
        """
        呼び出し行リストをキー用にシリアライズ
        
        Args:
            call_lines: 行番号のリスト（配列を含む可能性）
        
        Returns:
            タプル形式のキー
        """
        result = []
        for item in call_lines:
            if isinstance(item, list):
                result.append(tuple(sorted(item)))
            else:
                result.append(item)
        return tuple(result)
    
    def _remove_duplicates(self, flows: List[Dict]) -> List[Dict]:
        """
        完全に重複するフローを除去
        
        Args:
            flows: フローのリスト
        
        Returns:
            重複を除去したリスト
        """
        unique_flows = []
        seen = set()
        
        for flow in flows:
            key = self._get_flow_key(flow)
            
            if key not in seen:
                seen.add(key)
                unique_flows.append(flow)
        
        if self.verbose and len(flows) != len(unique_flows):
            print(f"  Removed {len(flows) - len(unique_flows)} duplicate flows")
        
        return unique_flows
    
    def _get_flow_key(self, flow: Dict) -> Tuple:
        """
        フローのユニークキーを生成
        
        Args:
            flow: フロー辞書
        
        Returns:
            ユニークキーのタプル
        """
        vd = flow['vd']
        chains = flow.get('chains', {})
        
        # lineとfunction_call_lineを正規化
        line = vd.get('line')
        if isinstance(line, list):
            line_str = str(sorted(line))
        else:
            line_str = str(line)
        
        # param_indicesをキーに含める
        param_indices = tuple(sorted(vd.get('param_indices', [vd['param_index']])))
        
        call_lines_str = self._serialize_call_lines(chains.get('function_call_line', []))
        
        key = (
            vd['file'],
            line_str,
            vd['sink'],
            param_indices,  # 全てのparam_indicesを含める
            tuple(chains.get('function_chain', [])),
            call_lines_str,
            flow.get('source_func', '')
        )
        
        return key
    
    def _serialize_call_lines(self, call_lines: List[Any]) -> str:
        """
        呼び出し行リストをシリアライズ
        
        Args:
            call_lines: 行番号のリスト（配列を含む可能性）
        
        Returns:
            シリアライズされた文字列
        """
        parts = []
        for item in call_lines:
            if isinstance(item, list):
                parts.append(f"[{','.join(map(str, sorted(item)))}]")
            else:
                parts.append(str(item))
        return '|'.join(parts)
    
    def _remove_subchains(self, flows: List[Dict]) -> List[Dict]:
        """
        サブチェインを除去
        重要: 異なる行番号のフローは保持する（95,96行目と65行目は別扱い）
        
        Args:
            flows: フローのリスト
        
        Returns:
            サブチェインを除去したリスト
        """
        filtered = []
        removed_count = 0
        
        for i, flow in enumerate(flows):
            is_subchain = False
            chain = flow.get('chains', {}).get('function_chain', [])
            vd = flow['vd']
            
            if not chain:
                filtered.append(flow)
                continue
            
            # この行番号を取得（配列の場合は最初の要素）
            flow_line = vd['line']
            if isinstance(flow_line, list):
                flow_line_set = set(flow_line)
            else:
                flow_line_set = {flow_line}
            
            for j, other_flow in enumerate(flows):
                if i == j:
                    continue
                
                other_chain = other_flow.get('chains', {}).get('function_chain', [])
                other_vd = other_flow['vd']
                
                # 他のフローの行番号を取得
                other_line = other_vd['line']
                if isinstance(other_line, list):
                    other_line_set = set(other_line)
                else:
                    other_line_set = {other_line}
                
                # 異なる行番号の場合はサブチェインとして扱わない
                if flow_line_set != other_line_set:
                    continue
                
                # 同じシンク、同じファイル、同じ行番号の場合のみサブチェインを確認
                if (vd['file'] == other_vd['file'] and
                    vd['sink'] == other_vd['sink'] and
                    len(chain) < len(other_chain) and
                    self._is_subsequence(chain, other_chain)):
                    is_subchain = True
                    removed_count += 1
                    if self.verbose:
                        print(f"  Removing subchain: {' -> '.join(chain)} (line {flow_line}) is subchain of {' -> '.join(other_chain)} (line {other_line})")
                    break
            
            if not is_subchain:
                filtered.append(flow)
        
        if self.verbose and removed_count > 0:
            print(f"  Removed {removed_count} subchains")
        
        return filtered
    
    def _is_subsequence(self, short: List, long: List) -> bool:
        """
        shortがlongのサブシーケンスかどうかを判定
        
        Args:
            short, long: リスト
        
        Returns:
            サブシーケンスの場合True
        """
        if len(short) > len(long):
            return False
        
        # 完全一致をチェック（末尾が一致）
        if len(long) >= len(short):
            # longの末尾がshortと一致するか確認
            if long[-len(short):] == short:
                return True
        
        return False
    
    def _merge_same_function_sinks(self, flows: List[Dict]) -> List[Dict]:
        """
        同一関数内の同じシンク呼び出しをマージ（行番号を配列化）
        95, 96行目のような別々の行のシンクをマージ
        
        重要: 同じfunction_chainかつ同じ含有関数のフローのみマージする
        """
        # グループ化のキー: (file, sink, param_indices, function_chain_tuple, containing_func_from_chain)
        groups = defaultdict(list)
        
        if self.verbose:
            print(f"  Merging same function sinks...")
        
        for flow in flows:
            vd = flow['vd']
            chains = flow.get('chains', {})
            chain = chains.get('function_chain', [])
            
            # param_indicesをソートしてタプル化
            param_indices_tuple = tuple(sorted(vd.get('param_indices', [vd['param_index']])))
            
            # function_chainをタプル化（完全に同じチェインのみマージ）
            chain_tuple = tuple(chain)
            
            # シンクを含む関数を特定（チェインの最後から2番目）
            containing_func = None
            if len(chain) >= 2:
                # チェインがシンク関数で終わる場合、その前の関数が含有関数
                if chain[-1] == vd['sink']:
                    containing_func = chain[-2] if len(chain) >= 2 else None
                else:
                    containing_func = chain[-1]
            
            key = (
                vd['file'],
                vd['sink'],
                param_indices_tuple,
                chain_tuple,  # 完全なチェインで識別
                containing_func  # 含有関数も考慮
            )
            
            groups[key].append(flow)
            
            if self.verbose:
                print(f"    Grouping: {vd['sink']}@{vd['line']} in {containing_func} with chain {' -> '.join(chain)}")
        
        # グループをマージ
        merged = []
        for key, group_flows in groups.items():
            if len(group_flows) == 1:
                merged.append(group_flows[0])
            else:
                # 複数のフローをマージ（行番号を配列化）
                lines = []
                for f in group_flows:
                    line = f['vd']['line']
                    if isinstance(line, list):
                        lines.extend(line)
                    else:
                        lines.append(line)
                
                # 同じ含有関数内の呼び出しのみマージ
                chain = group_flows[0].get('chains', {}).get('function_chain', [])
                containing_func = key[4]  # keyから含有関数を取得
                
                if self.verbose:
                    print(f"    Merging {len(group_flows)} flows at lines {sorted(set(lines))} in {containing_func} with chain: {' -> '.join(chain)}")
                
                merged_flow = self._merge_flow_group_with_lines(group_flows)
                merged.append(merged_flow)
        
        return merged
    
    def _merge_flow_group_with_lines(self, flows: List[Dict]) -> Dict:
        """
        同じグループのフローをマージ（行番号を配列化）
        
        Args:
            flows: マージするフローのリスト
        
        Returns:
            マージされたフロー
        """
        # ベースフローをコピー
        merged = flows[0].copy()
        merged['vd'] = flows[0]['vd'].copy()
        merged['chains'] = flows[0]['chains'].copy()
        
        # すべての行番号を収集
        all_lines = []
        for flow in flows:
            line = flow['vd']['line']
            if isinstance(line, list):
                all_lines.extend(line)
            else:
                all_lines.append(line)
        
        # 重複を除去してソート
        unique_lines = sorted(set(all_lines))
        
        # 行番号を更新（複数の場合は配列、単一の場合は数値）
        if len(unique_lines) == 1:
            merged['vd']['line'] = unique_lines[0]
        else:
            merged['vd']['line'] = unique_lines
        
        # function_call_lineもマージ
        all_call_lines = []
        for flow in flows:
            chains = flow.get('chains', {})
            call_lines = chains.get('function_call_line', [])
            if call_lines:
                all_call_lines.append(call_lines)
        
        if all_call_lines:
            merged_call_lines = self._merge_call_line_lists_with_last(all_call_lines, unique_lines)
            merged['chains']['function_call_line'] = merged_call_lines
        
        return merged
    
    def _merge_call_line_lists_with_last(self, line_lists: List[List], 
                                         sink_lines: List[int]) -> List[Union[int, List[int]]]:
        """
        複数の呼び出し行リストをマージし、最後の要素をsink_linesで置き換え
        
        Args:
            line_lists: 行番号リストのリスト
            sink_lines: シンクの行番号リスト
        
        Returns:
            マージされたリスト
        """
        if not line_lists:
            return []
        
        if len(line_lists) == 1 and len(sink_lines) == 1:
            return line_lists[0]
        
        # 最長のリストの長さを取得
        max_len = max(len(lst) for lst in line_lists)
        merged = []
        
        # 最後の要素以外をマージ
        for i in range(max_len - 1):
            lines_at_pos = set()
            for lst in line_lists:
                if i < len(lst):
                    if isinstance(lst[i], list):
                        lines_at_pos.update(lst[i])
                    else:
                        lines_at_pos.add(lst[i])
            
            lines_sorted = sorted(lines_at_pos)
            if len(lines_sorted) == 1:
                merged.append(lines_sorted[0])
            else:
                merged.append(lines_sorted)
        
        # 最後の要素はsink_linesで置き換え
        if len(sink_lines) == 1:
            merged.append(sink_lines[0])
        else:
            merged.append(sink_lines)
        
        return merged
    
    def _organize_param_indices(self, flows: List[Dict]) -> List[Dict]:
        """
        param_indicesを整理
        
        Args:
            flows: フローのリスト
        
        Returns:
            整理されたフローのリスト
        """
        for flow in flows:
            vd = flow['vd']
            
            # param_indicesが存在しない場合は作成
            if 'param_indices' not in vd:
                vd['param_indices'] = [vd['param_index']]
            
            # param_indicesをソート
            vd['param_indices'] = sorted(set(vd['param_indices']))
        
        return flows