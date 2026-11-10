use rbitcoin_store::durability::Durable as _;

fn persist(f: &std::fs::File) -> std::io::Result<()> {
    f.durable_sync_all()?;
    f.durable_sync_data()
}

#[cfg(test)]
mod tests {
    fn crash_rig(f: &std::fs::File) {
        f.sync_all().unwrap();
    }
}
