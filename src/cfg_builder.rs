use crate::sbf_disasm::{DisassemblyResult, Instruction};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BasicBlock {
    pub start_offset: usize,
    pub end_offset: usize,
    pub instruction_offsets: Vec<usize>,
    pub successors: Vec<usize>,
    pub predecessors: Vec<usize>,
    pub is_entry: bool,
    pub has_exit: bool,
    pub call_count: usize,
    pub invoke_syscall_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlFlowGraph {
    pub entry_block: usize,
    pub blocks: Vec<BasicBlock>,
    pub block_by_offset: HashMap<usize, usize>,
}

pub fn build_cfg(disasm: &DisassemblyResult) -> ControlFlowGraph {
    if disasm.instructions.is_empty() {
        return ControlFlowGraph {
            entry_block: 0,
            blocks: Vec::new(),
            block_by_offset: HashMap::new(),
        };
    }

    let leaders = compute_leaders(disasm);
    let mut leader_list: Vec<usize> = leaders.into_iter().collect();
    leader_list.sort_unstable();

    let mut blocks = Vec::new();
    let mut block_by_offset = HashMap::new();

    for (idx, &start) in leader_list.iter().enumerate() {
        let end = leader_list
            .get(idx + 1)
            .copied()
            .unwrap_or(usize::MAX);
        let mut instruction_offsets = Vec::new();
        let mut has_exit = false;
        let mut call_count = 0usize;
        let mut invoke_syscall_count = 0usize;
        let mut _terminator: Option<&Instruction> = None;

        for insn in &disasm.instructions {
            if insn.offset < start {
                continue;
            }
            if insn.offset >= end {
                break;
            }
            instruction_offsets.push(insn.offset);
            if insn.is_exit {
                has_exit = true;
            }
            if insn.is_call {
                call_count += 1;
                if insn
                    .syscall_name
                    .as_deref()
                    .is_some_and(|name| name.contains("invoke"))
                {
                    invoke_syscall_count += 1;
                }
            }
            _terminator = Some(insn);
        }

        let block_end = instruction_offsets.last().copied().unwrap_or(start);
        blocks.push(BasicBlock {
            start_offset: start,
            end_offset: block_end,
            instruction_offsets,
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_entry: start == disasm.entry_offset,
            has_exit,
            call_count,
            invoke_syscall_count,
        });
        block_by_offset.insert(start, idx);
    }

    for idx in 0..blocks.len() {
        let start = blocks[idx].start_offset;
        let terminator = disasm
            .instructions
            .iter()
            .filter(|insn| insn.offset >= start && insn.offset <= blocks[idx].end_offset)
            .last();

        if let Some(term) = terminator {
            if term.is_exit {
                continue;
            }
            if term.is_branch {
                if let Some(target) = term.branch_target {
                    if let Some(&succ) = block_by_offset.get(&target) {
                        blocks[idx].successors.push(succ);
                    }
                }
                if term.mnemonic != "ja" {
                    let fallthrough = term.offset + term.size;
                    if let Some(&succ) = block_by_offset.get(&fallthrough) {
                        if !blocks[idx].successors.contains(&succ) {
                            blocks[idx].successors.push(succ);
                        }
                    }
                }
            } else if term.is_call {
                let fallthrough = term.offset + term.size;
                if let Some(&succ) = block_by_offset.get(&fallthrough) {
                    blocks[idx].successors.push(succ);
                }
            } else {
                let fallthrough = term.offset + term.size;
                if let Some(&succ) = block_by_offset.get(&fallthrough) {
                    blocks[idx].successors.push(succ);
                }
            }
        }
    }

    for idx in 0..blocks.len() {
        let succs = blocks[idx].successors.clone();
        for succ in succs {
            blocks[succ].predecessors.push(idx);
        }
    }

    let entry_block = *block_by_offset
        .get(&disasm.entry_offset)
        .unwrap_or(&0);

    ControlFlowGraph {
        entry_block,
        blocks,
        block_by_offset,
    }
}

fn compute_leaders(disasm: &DisassemblyResult) -> HashSet<usize> {
    let mut leaders = HashSet::new();
    leaders.insert(disasm.entry_offset);

    for insn in &disasm.instructions {
        if insn.is_branch {
            if let Some(target) = insn.branch_target {
                leaders.insert(target);
            }
            if insn.mnemonic != "ja" {
                leaders.insert(insn.offset + insn.size);
            }
        } else if insn.is_call || insn.is_exit {
            let next = insn.offset + insn.size;
            leaders.insert(next);
        }
    }

    leaders
}

pub fn reachable_blocks(cfg: &ControlFlowGraph) -> HashSet<usize> {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(cfg.entry_block);
    seen.insert(cfg.entry_block);

    while let Some(block) = queue.pop_front() {
        for &succ in &cfg.blocks[block].successors {
            if seen.insert(succ) {
                queue.push_back(succ);
            }
        }
    }

    seen
}

pub fn unreachable_block_offsets(cfg: &ControlFlowGraph) -> Vec<usize> {
    let reachable = reachable_blocks(cfg);
    cfg.blocks
        .iter()
        .enumerate()
        .filter_map(|(idx, block)| {
            if reachable.contains(&idx) {
                None
            } else {
                Some(block.start_offset)
            }
        })
        .collect()
}

pub fn invoke_heavy_blocks(cfg: &ControlFlowGraph, threshold: usize) -> Vec<usize> {
    cfg.blocks
        .iter()
        .filter(|block| block.invoke_syscall_count >= threshold)
        .map(|block| block.start_offset)
        .collect()
}

pub fn cfg_summary(cfg: &ControlFlowGraph) -> String {
    let reachable = reachable_blocks(cfg);
    let mut lines = Vec::new();
    lines.push(format!("blocks: {}", cfg.blocks.len()));
    lines.push(format!("reachable: {}", reachable.len()));
    lines.push(format!(
        "unreachable: {}",
        cfg.blocks.len().saturating_sub(reachable.len())
    ));

    for (idx, block) in cfg.blocks.iter().enumerate() {
        let succs: Vec<String> = block
            .successors
            .iter()
            .map(|s| format!("0x{:x}", cfg.blocks[*s].start_offset))
            .collect();
        lines.push(format!(
            "block#{idx} [0x{:x}..0x{:x}] calls={} invoke={} -> [{}]",
            block.start_offset,
            block.end_offset,
            block.call_count,
            block.invoke_syscall_count,
            succs.join(", ")
        ));
    }

    lines.join("\n")
}

pub fn dominator_frontier_roots(cfg: &ControlFlowGraph) -> BTreeSet<usize> {
    let mut roots = BTreeSet::new();
    for block in &cfg.blocks {
        if block.predecessors.len() > 1 {
            roots.insert(block.start_offset);
        }
    }
    roots
}
