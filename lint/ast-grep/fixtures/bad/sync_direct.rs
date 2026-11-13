fn persist(f: &std::fs::File) -> std::io::Result<()> {
    f.sync_all()?;
    f.sync_data()?;
    std::fs::File::sync_all(f)?;
    std::fs::File::sync_data(f)
}
