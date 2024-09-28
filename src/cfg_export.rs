//! Control flow graph export formats for visualization and downstream tooling.

use crate::cfg_builder::ControlFlowGraph;
use serde::Serialize;

/// Supported export formats for CFG serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CfgExportFormat {
    Dot,
    Json,
}

/// JSON friendly graph representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgGraphDocument {
    pub entry_block: usize,
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgNode {
    pub id: usize,
    pub start_offset: usize,
    pub end_offset: usize,
    pub instruction_count: usize,
    pub is_entry: bool,
    pub has_exit: bool,
    pub call_count: usize,
    pub invoke_syscall_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub kind: CfgEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CfgEdgeKind {
    Fallthrough,
    Branch,
    Unconditional,
}

/// Convert internal CFG into a portable graph document.
pub fn to_graph_document(cfg: &ControlFlowGraph) -> CfgGraphDocument {
    let nodes: Vec<CfgNode> = cfg
        .blocks
        .iter()
        .enumerate()
        .map(|(id, block)| CfgNode {
            id,
            start_offset: block.start_offset,
            end_offset: block.end_offset,
            instruction_count: block.instruction_offsets.len(),
            is_entry: block.is_entry,
            has_exit: block.has_exit,
            call_count: block.call_count,
            invoke_syscall_count: block.invoke_syscall_count,
        })
        .collect();

    let mut edges = Vec::new();
    for (from_idx, block) in cfg.blocks.iter().enumerate() {
        for &to_idx in &block.successors {
            let kind = if block.has_exit {
                CfgEdgeKind::Unconditional
            } else if block.successors.len() > 1 {
                CfgEdgeKind::Branch
            } else {
                CfgEdgeKind::Fallthrough
            };
            edges.push(CfgEdge {
                from: from_idx,
                to: to_idx,
                kind,
            });
        }
    }

    CfgGraphDocument {
        entry_block: cfg.entry_block,
        nodes,
        edges,
    }
}

/// Export CFG to Graphviz DOT syntax.
pub fn export_dot(cfg: &ControlFlowGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph sbf_cfg {\n");
    out.push_str("  rankdir=TB;\n");
    out.push_str("  node [shape=box, fontname=\"Courier\"];\n\n");

    for (idx, block) in cfg.blocks.iter().enumerate() {
        let label = format!(
            "block{}\\n0x{:x}..0x{:x}\\ninsns={}\\ncalls={}",
            idx,
            block.start_offset,
            block.end_offset,
            block.instruction_offsets.len(),
            block.call_count
        );
        let style = if block.is_entry {
            ", style=filled, fillcolor=lightyellow"
        } else if block.has_exit {
            ", style=filled, fillcolor=lightblue"
        } else if block.invoke_syscall_count > 0 {
            ", style=filled, fillcolor=mistyrose"
        } else {
            ""
        };
        out.push_str(&format!(
            "  b{idx} [label=\"{label}\"{style}];\n",
        ));
    }

    out.push('\n');
    for (from_idx, block) in cfg.blocks.iter().enumerate() {
        for &to_idx in &block.successors {
            out.push_str(&format!("  b{from_idx} -> b{to_idx};\n"));
        }
    }

    out.push_str("}\n");
    out
}

/// Export CFG as pretty printed JSON.
pub fn export_json(cfg: &ControlFlowGraph) -> Result<String, serde_json::Error> {
    let doc = to_graph_document(cfg);
    serde_json::to_string_pretty(&doc)
}

/// Export CFG in the requested format.
pub fn export_cfg(cfg: &ControlFlowGraph, format: CfgExportFormat) -> Result<String, String> {
    match format {
        CfgExportFormat::Dot => Ok(export_dot(cfg)),
        CfgExportFormat::Json => export_json(cfg).map_err(|e| e.to_string()),
    }
}

/// Compute graph metrics useful for complexity scoring.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CfgMetrics {
    pub block_count: usize,
    pub edge_count: usize,
    pub entry_block: usize,
    pub max_out_degree: usize,
    pub merge_points: usize,
    pub exit_blocks: usize,
    pub invoke_blocks: usize,
}

pub fn compute_metrics(cfg: &ControlFlowGraph) -> CfgMetrics {
    let edge_count: usize = cfg.blocks.iter().map(|b| b.successors.len()).sum();
    let max_out_degree = cfg
        .blocks
        .iter()
        .map(|b| b.successors.len())
        .max()
        .unwrap_or(0);
    let merge_points = cfg
        .blocks
        .iter()
        .filter(|b| b.predecessors.len() > 1)
        .count();
    let exit_blocks = cfg.blocks.iter().filter(|b| b.has_exit).count();
    let invoke_blocks = cfg
        .blocks
        .iter()
        .filter(|b| b.invoke_syscall_count > 0)
        .count();

    CfgMetrics {
        block_count: cfg.blocks.len(),
        edge_count,
        entry_block: cfg.entry_block,
        max_out_degree,
        merge_points,
        exit_blocks,
        invoke_blocks,
    }
}
