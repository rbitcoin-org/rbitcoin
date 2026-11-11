fn open_for_test() {
    rbitcoin_store::testutil::skip_flushes_in_this_process();
}

fn store_setter() {
    crate::durability::skip_in_this_process();
}

fn renamed() {
    use rbitcoin_store::testutil::skip_flushes_in_this_process as off;
    off();
}

#[cfg(test)]
mod tests {
    use rbitcoin_store::testutil::skip_flushes_in_this_process;

    fn rig() {
        skip_flushes_in_this_process();
    }
}
