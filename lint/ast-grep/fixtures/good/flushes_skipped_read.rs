fn report() -> bool {
    rbitcoin_store::durability::flushes_skipped()
}

fn skip_flushes_in_this_process_count() -> u64 {
    0
}
