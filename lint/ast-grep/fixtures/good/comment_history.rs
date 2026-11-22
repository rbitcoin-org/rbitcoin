/// Last mock time. Used to age mempool entries.
fn mock_time() {}

/// The flag byte is used to rank a remembered address.
fn flags() {}

// Used to pipeline header sync.
fn pipeline() {}

/// A peer that no longer holds the request.
fn released() {}

fn text() -> &'static str {
    "this used to be a mutant"
}
