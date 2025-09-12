#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallInfo {
    pub id: u32,
    pub name: &'static str,
    pub description: &'static str,
}

pub fn syscall_table() -> &'static [SyscallInfo] {
    static TABLE: &[SyscallInfo] = &[
        SyscallInfo { id: 0, name: "abort", description: "Abort execution with error code" },
        SyscallInfo { id: 1, name: "sol_panic_", description: "Log panic message and abort" },
        SyscallInfo { id: 2, name: "sol_log_", description: "Print UTF-8 log line" },
        SyscallInfo { id: 3, name: "sol_log_64_", description: "Print five u64 values" },
        SyscallInfo { id: 4, name: "sol_log_compute_units_", description: "Log remaining compute units" },
        SyscallInfo { id: 5, name: "sol_log_pubkey", description: "Log public key bytes" },
        SyscallInfo { id: 6, name: "sol_create_program_address", description: "Derive program address" },
        SyscallInfo { id: 7, name: "sol_try_find_program_address", description: "Try derive PDA with bump" },
        SyscallInfo { id: 8, name: "sol_sha256", description: "Compute SHA256 hash" },
        SyscallInfo { id: 9, name: "sol_keccak256", description: "Compute Keccak256 hash" },
        SyscallInfo { id: 10, name: "sol_secp256k1_recover", description: "Recover secp256k1 pubkey" },
        SyscallInfo { id: 11, name: "sol_get_clock_sysvar", description: "Read Clock sysvar" },
        SyscallInfo { id: 12, name: "sol_get_epoch_schedule_sysvar", description: "Read EpochSchedule sysvar" },
        SyscallInfo { id: 13, name: "sol_get_fees_sysvar", description: "Read deprecated Fees sysvar" },
        SyscallInfo { id: 14, name: "sol_get_rent_sysvar", description: "Read Rent sysvar" },
        SyscallInfo { id: 15, name: "sol_memcpy_", description: "Memcpy between VM regions" },
        SyscallInfo { id: 16, name: "sol_memmove_", description: "Memmove between VM regions" },
        SyscallInfo { id: 17, name: "sol_memcmp_", description: "Compare VM memory regions" },
        SyscallInfo { id: 18, name: "sol_memset_", description: "Fill VM memory region" },
        SyscallInfo { id: 19, name: "sol_invoke_signed_c", description: "Cross program invoke with seeds" },
        SyscallInfo { id: 20, name: "sol_invoke_signed_rust", description: "Rust ABI cross program invoke" },
        SyscallInfo { id: 21, name: "sol_alloc_free_", description: "Heap allocate or free" },
        SyscallInfo { id: 22, name: "sol_set_return_data", description: "Set return data buffer" },
        SyscallInfo { id: 23, name: "sol_get_return_data", description: "Read return data buffer" },
        SyscallInfo { id: 24, name: "sol_log_data", description: "Log structured data records" },
        SyscallInfo { id: 25, name: "sol_get_processed_sibling_instruction", description: "Read sibling instruction metadata" },
        SyscallInfo { id: 26, name: "sol_get_stack_height", description: "Read current CPI stack height" },
        SyscallInfo { id: 27, name: "sol_remaining_compute_units", description: "Read remaining compute meter" },
        SyscallInfo { id: 28, name: "sol_alt_bn128_group_op", description: "Alt BN128 curve operation" },
        SyscallInfo { id: 29, name: "sol_get_epoch_rewards_sysvar", description: "Read EpochRewards sysvar" },
        SyscallInfo { id: 30, name: "sol_get_last_restart_slot", description: "Read last restart slot sysvar" },
        SyscallInfo { id: 31, name: "sol_big_mod_exp", description: "Big integer modular exponentiation" },
        SyscallInfo { id: 32, name: "sol_poseidon", description: "Poseidon hash syscall" },
        SyscallInfo { id: 33, name: "sol_curve_validate_point", description: "Validate curve point" },
        SyscallInfo { id: 34, name: "sol_get_sysvar", description: "Generic sysvar fetch" },
    ];
    TABLE
}

pub fn resolve_syscall(id: u32) -> Option<&'static SyscallInfo> {
    syscall_table().iter().find(|entry| entry.id == id)
}

pub fn is_invoke_syscall(id: u32) -> bool {
    matches!(
        id,
        19 | 20
    )
}

pub fn syscall_name(id: u32) -> &'static str {
    resolve_syscall(id)
        .map(|entry| entry.name)
        .unwrap_or("unknown_syscall")
}

pub fn format_syscall_table() -> String {
    syscall_table()
        .iter()
        .map(|entry| format!("{:>3}  {:<40} {}", entry.id, entry.name, entry.description))
        .collect::<Vec<_>>()
        .join("\n")
}
