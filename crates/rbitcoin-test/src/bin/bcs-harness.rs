//! bitcoin-consensus-spec conformance harness (`conformance/PROTOCOL.md`
//! version 1): one JSON request per stdin line, one response per stdout line.
//!
//! Every answer comes from the functions block connect calls:
//! `ScriptCheckJob` and `script::verify_input` with the request's consensus
//! flags and every policy flag off; Core `CheckTransaction` from
//! `check_tx_shape`, `reject_duplicate_outpoints`,
//! `check_coinbase_script_sig` and `reject_null_prevouts`; the legacy
//! sighash as `sighash_for_script` takes it (`strip_op_codeseparator`, then
//! rust-bitcoin's `legacy_signature_hash`); `crypto::tap_signature_hash`;
//! `p2tr::verify_control_commitment`; and BIP340 through `crypto::SECP`.
//!
//! Proof of work is what header checks call: `Target::from_compact`,
//! `header::pow_hash_meets_target`, `header::next_work_bits` and
//! `rbitcoin_net::chain::header_work_bits`. `pow_compact`'s `negative` and
//! `overflow` are Core's `SetCompact` conditions, computed here from `bits`:
//! rbitcoin's decode has no such flags, and what it makes of those `bits`
//! shows in `target`, `work` and `pow_check`. `signet_check` is
//! `validate_signet_block_solution`, as block confirm calls it.
//! `network_params` reads `ChainParams::for_network`, `magic_for_params` and
//! the default port, and finds a network's script flag exceptions by asking
//! `ScriptVerifyFlags::for_block` about each exception hash rbitcoin knows.
//! Chain operations are `scripts/consensus-spec/chain_harness.py`.

use std::cell::OnceCell;
use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::str::FromStr;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::script::Script;
use bitcoin::secp256k1::{schnorr, Message, XOnlyPublicKey};
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, ScriptBuf, TapLeafHash, Target, Transaction, TxOut,
};
use rbitcoin_consensus::block::{self, InputIndex, ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::header::{self, PeriodFirst};
use rbitcoin_consensus::script::{self, crypto, interpreter, p2tr};
use rbitcoin_consensus::{
    block_reject_reason, ChainParams, ConsensusError, OutPointSet, TxPrecompute,
};
use rbitcoin_primitives::Network;
use serde_json::{json, Value};

const OPS: &[&str] = &[
    "info",
    "script_verify",
    "tx_check",
    "sighash_legacy",
    "sighash_taproot",
    "taproot_commitment_verify",
    "schnorr_verify",
    "pow_compact",
    "pow_check",
    "pow_next_work",
    "signet_check",
    "network_params",
];

/// `ok: false` with a PROTOCOL.md error code.
type Fail = (&'static str, String);
type Resp = Result<Value, Fail>;

fn bad(msg: impl Into<String>) -> Fail {
    ("bad_request", msg.into())
}

fn internal(msg: impl Into<String>) -> Fail {
    ("internal", msg.into())
}

fn field<'a>(req: &'a Value, name: &str) -> Result<&'a Value, Fail> {
    req.get(name)
        .ok_or_else(|| bad(format!("missing field {name}")))
}

fn hex_field(req: &Value, name: &str) -> Result<Vec<u8>, Fail> {
    let s = field(req, name)?
        .as_str()
        .ok_or_else(|| bad(format!("{name} is not a string")))?;
    Vec::<u8>::from_hex(s).map_err(|e| bad(format!("{name}: {e}")))
}

fn opt_hex_field(req: &Value, name: &str) -> Result<Option<Vec<u8>>, Fail> {
    match req.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => hex_field(req, name).map(Some),
    }
}

fn int_field(req: &Value, name: &str) -> Result<i64, Fail> {
    field(req, name)?
        .as_i64()
        .ok_or_else(|| bad(format!("{name} is not an integer")))
}

fn tx_field(req: &Value) -> Result<Transaction, Fail> {
    deserialize(&hex_field(req, "tx")?).map_err(|e| internal(format!("tx does not decode: {e}")))
}

fn index_field(req: &Value, tx: &Transaction) -> Result<usize, Fail> {
    usize::try_from(int_field(req, "index")?)
        .ok()
        .filter(|&i| i < tx.input.len())
        .ok_or_else(|| bad("index is not an input of tx"))
}

fn spent_outputs(req: &Value, tx: &Transaction) -> Result<Vec<TxOut>, Fail> {
    let arr = field(req, "spent_outputs")?
        .as_array()
        .ok_or_else(|| bad("spent_outputs is not an array"))?;
    if arr.len() != tx.input.len() {
        return Err(bad("spent_outputs does not have one entry per input"));
    }
    arr.iter()
        .map(|o| {
            // Test amounts may be negative; the wire value is the same 64 bits.
            let sat = int_field(o, "amount")? as u64;
            Ok(TxOut {
                value: Amount::from_sat(sat),
                script_pubkey: ScriptBuf::from_bytes(hex_field(o, "script_pubkey")?),
            })
        })
        .collect()
}

fn consensus_flags(v: &Value) -> Result<ScriptVerifyFlags, Fail> {
    // Every flag off, then the ones the request names. A struct literal, as
    // the Core JSON fixtures use, so a flag added to `ScriptVerifyFlags` has
    // to be placed here before this builds, and a changed default in a
    // constructor cannot turn a policy flag on.
    let mut f = ScriptVerifyFlags {
        bip65_active: false,
        bip112_active: false,
        bip66_active: false,
        bip16_active: false,
        taproot_active: false,
        minimal_if: false,
        nullfail: false,
        low_s: false,
        strictenc: false,
        null_dummy: false,
        minimal_data: false,
        witness_pubkeytype: false,
        witness_active: false,
        discourage_upgradable_witness: false,
        const_scriptcode: false,
        cleanstack: false,
    };
    for name in v.as_array().ok_or_else(|| bad("flags is not an array"))? {
        match name.as_str() {
            Some("P2SH") => f.bip16_active = true,
            Some("DERSIG") => f.bip66_active = true,
            Some("NULLDUMMY") => f.null_dummy = true,
            Some("CHECKLOCKTIMEVERIFY") => f.bip65_active = true,
            Some("CHECKSEQUENCEVERIFY") => f.bip112_active = true,
            Some("WITNESS") => f.witness_active = true,
            Some("TAPROOT") => f.taproot_active = true,
            _ => return Err(bad(format!("unknown flag {name}"))),
        }
    }
    Ok(f)
}

/// The script error token, without the `txid=` annotation a block adds.
fn script_error(e: &ConsensusError) -> String {
    match e {
        ConsensusError::Script(msg) => msg.split(" txid=").next().unwrap_or(msg).to_string(),
        other => other.to_string(),
    }
}

fn info() -> Resp {
    Ok(json!({
        "name": "rbitcoin-consensus",
        "version": env!("CARGO_PKG_VERSION"),
        "spec_version": "v32.1",
        "ops": OPS,
    }))
}

fn script_verify(req: &Value) -> Resp {
    let tx: Transaction = match deserialize(&hex_field(req, "tx")?) {
        Ok(tx) => tx,
        Err(e) => return Ok(json!({"valid": false, "script_error": format!("tx-decode ({e})")})),
    };
    let index = index_field(req, &tx)?;
    let prevouts = spent_outputs(req, &tx)?;
    let flags = consensus_flags(field(req, "flags")?)?;
    let job = ScriptCheckJob::try_new(prevouts, tx, flags)
        .map_err(|e| internal(format!("ScriptCheckJob: {e}")))?;
    // Only `verify_input` gives the verdict. A job that cannot be set up is
    // this harness failing, and must not count as a script found invalid.
    let ii = InputIndex::in_tx(&job.tx, index).map_err(|e| bad(e.to_string()))?;
    let (value, spk) = job.prevout_parts(ii).map_err(|e| internal(e.to_string()))?;
    let pre = job.pre().map_err(|e| internal(e.to_string()))?;
    let verdict = script::verify_input(
        &job,
        ii,
        &job.tx,
        &mut None,
        pre,
        &crypto::TapSpentHashes::default(),
        Amount::from_sat(value),
        spk,
    );
    Ok(match verdict {
        Ok(()) => json!({"valid": true, "script_error": "OK"}),
        Err(e) => json!({"valid": false, "script_error": script_error(&e)}),
    })
}

fn check_transaction(tx: &Transaction) -> Result<(), ConsensusError> {
    block::check_tx_shape(tx, TxPrecompute::from_tx(tx).base_size)?;
    block::reject_duplicate_outpoints(tx, &mut OutPointSet::default())?;
    if tx.is_coinbase() {
        block::check_coinbase_script_sig(tx)
    } else {
        block::reject_null_prevouts(tx)
    }
}

fn tx_check(req: &Value) -> Resp {
    let Ok(tx) = deserialize::<Transaction>(&hex_field(req, "tx")?) else {
        return Ok(json!({"valid": false, "reason": "tx-decode"}));
    };
    Ok(match check_transaction(&tx) {
        Ok(()) => json!({"valid": true}),
        Err(e) => json!({"valid": false, "reason": block_reject_reason(&e)}),
    })
}

fn sighash_legacy(req: &Value) -> Resp {
    let tx = tx_field(req)?;
    let index = index_field(req, &tx)?;
    let script_code = hex_field(req, "script_code")?;
    let stripped = interpreter::strip_op_codeseparator(&script_code);
    // A signed 32-bit hash type; Core hashes its low 32 bits.
    let hash_type = int_field(req, "hash_type")? as i32 as u32;
    let h = SighashCache::new(&tx)
        .legacy_signature_hash(index, Script::from_bytes(&stripped), hash_type)
        .map_err(|e| internal(format!("legacy_signature_hash: {e}")))?;
    Ok(json!({"sighash": h.to_byte_array().to_lower_hex_string()}))
}

fn sighash_taproot(req: &Value) -> Resp {
    let tx = tx_field(req)?;
    let index = index_field(req, &tx)?;
    let prevouts = spent_outputs(req, &tx)?;
    let hash_type =
        u8::try_from(int_field(req, "hash_type")?).map_err(|_| bad("hash_type is not 0 to 255"))?;
    let annex = opt_hex_field(req, "annex")?;
    let codesep = match req.get("codesep_pos") {
        None | Some(Value::Null) => u32::MAX,
        Some(_) => u32::try_from(int_field(req, "codesep_pos")?)
            .map_err(|_| bad("codesep_pos is not a u32"))?,
    };
    let leaf = match opt_hex_field(req, "leaf_hash")? {
        None => None,
        Some(l) => {
            let raw: [u8; 32] = l.try_into().map_err(|_| bad("leaf_hash is not 32 bytes"))?;
            Some((TapLeafHash::from_byte_array(raw), codesep))
        }
    };
    let Ok(ty) = TapSighashType::from_consensus_u8(hash_type) else {
        return Ok(json!({"valid": false}));
    };
    let job = ScriptCheckJob::try_new(
        prevouts,
        tx,
        ScriptVerifyFlags::buried(true, true, true, true, true),
    )
    .map_err(|e| internal(format!("ScriptCheckJob: {e}")))?;
    let ii = InputIndex::in_tx(&job.tx, index).map_err(|e| bad(e.to_string()))?;
    let (value, spk) = job.prevout_parts(ii).map_err(|e| internal(e.to_string()))?;
    let h = crypto::tap_signature_hash(
        &job,
        ii,
        ty,
        &crypto::TapSpentHashes::default(),
        annex.as_deref().map(crypto::annex_hash),
        leaf,
        &OnceCell::new(),
        value,
        spk,
    );
    Ok(match h {
        Ok(h) => json!({"valid": true, "sighash": h.to_lower_hex_string()}),
        Err(_) => json!({"valid": false}),
    })
}

fn taproot_commitment_verify(req: &Value) -> Resp {
    let control = hex_field(req, "control_block")?;
    let leaf = hex_field(req, "script")?;
    let output_key = hex_field(req, "output_key")?;
    let ok =
        p2tr::verify_control_commitment(&control, &output_key, Script::from_bytes(&leaf)).is_ok();
    Ok(json!({"valid": ok}))
}

fn schnorr_verify(req: &Value) -> Resp {
    let pubkey = hex_field(req, "pubkey")?;
    let msg = hex_field(req, "msg")?;
    let sig = hex_field(req, "sig")?;
    // rbitcoin verifies BIP340 only over 32-byte sighashes.
    let digest: [u8; 32] = msg
        .as_slice()
        .try_into()
        .map_err(|_| internal(format!("no BIP340 path for a {}-byte message", msg.len())))?;
    let (Ok(key), Ok(sig)) = (
        XOnlyPublicKey::from_slice(&pubkey),
        schnorr::Signature::from_slice(&sig),
    ) else {
        return Ok(json!({"valid": false}));
    };
    let msg = Message::from_digest(digest);
    let ok = crypto::SECP.with(|secp| secp.verify_schnorr(&sig, &msg, &key).is_ok());
    Ok(json!({"valid": ok}))
}

fn u32_field(req: &Value, name: &str) -> Result<u32, Fail> {
    u32::try_from(int_field(req, name)?).map_err(|_| bad(format!("{name} is not 0 to 2^32 - 1")))
}

fn bits_field(req: &Value) -> Result<CompactTarget, Fail> {
    u32_field(req, "bits").map(CompactTarget::from_consensus)
}

fn network_field(req: &Value) -> Result<Network, Fail> {
    match field(req, "network")?.as_str() {
        Some("main") => Ok(Network::Mainnet),
        Some("testnet3") => Ok(Network::Testnet),
        Some("testnet4") => Ok(Network::Testnet4),
        Some("signet") => Ok(Network::Signet),
        Some("regtest") => Ok(Network::Regtest),
        _ => Err(bad(
            "network is not main, testnet3, testnet4, signet or regtest",
        )),
    }
}

fn params_field(req: &Value) -> Result<ChainParams, Fail> {
    network_field(req).map(ChainParams::for_network)
}

fn be_hex(be: [u8; 32]) -> String {
    be.to_lower_hex_string()
}

fn pow_compact(req: &Value) -> Resp {
    let bits = bits_field(req)?;
    let raw = bits.to_consensus();
    let size = raw >> 24;
    // Core tests the mantissa after a size below 4 shifts it right.
    let word = (raw & 0x007f_ffff) >> (8 * 3u32.saturating_sub(size));
    let target = Target::from_compact(bits);
    Ok(json!({
        "target": be_hex(target.to_be_bytes()),
        "negative": word != 0 && raw & 0x0080_0000 != 0,
        "overflow": word != 0
            && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32)),
        "compact": target.to_compact_lossy().to_consensus(),
        "work": be_hex(rbitcoin_net::chain::header_work_bits(raw).to_be_bytes()),
    }))
}

fn pow_check(req: &Value) -> Resp {
    let params = params_field(req)?;
    let hash = field(req, "hash")?
        .as_str()
        .and_then(|s| BlockHash::from_str(s).ok())
        .ok_or_else(|| bad("hash is not a 32-byte hash"))?;
    let ok =
        header::pow_hash_meets_target(hash.to_byte_array(), bits_field(req)?, params.pow_limit)
            .is_ok();
    Ok(json!({"valid": ok}))
}

/// `chain`'s runs `[count, time, step, bits]` as one `(time, bits)` per header.
fn chain_headers(req: &Value) -> Result<Vec<(u32, CompactTarget)>, Fail> {
    let mut out = Vec::new();
    for run in field(req, "chain")?
        .as_array()
        .ok_or_else(|| bad("chain is not an array"))?
    {
        let nums: Vec<i64> = run
            .as_array()
            .filter(|r| r.len() == 4)
            .and_then(|r| r.iter().map(Value::as_i64).collect())
            .ok_or_else(|| bad("a chain run is not [count, time, step, bits]"))?;
        let bits = u32::try_from(nums[3]).map_err(|_| bad("a run's bits are not a u32"))?;
        for i in 0..nums[0].max(0) {
            let time = u32::try_from(nums[1] + i * nums[2])
                .map_err(|_| bad("a header time is not a u32"))?;
            out.push((time, CompactTarget::from_consensus(bits)));
        }
    }
    Ok(out)
}

fn pow_next_work(req: &Value) -> Resp {
    let params = params_field(req)?;
    let parent_height = u32_field(req, "parent_height")?;
    let time = u32_field(req, "time")?;
    let chain = chain_headers(req)?;
    // The runs end at the parent and start where Core's difficulty period
    // does. rbitcoin's own period length decides what it reads.
    let start = u32::try_from(chain.len())
        .ok()
        .and_then(|n| (parent_height + 1).checked_sub(n))
        .ok_or_else(|| bad("chain has more headers than parent_height + 1"))?;
    let (prev_time, prev_bits) = *chain.last().ok_or_else(|| bad("chain is empty"))?;
    let at = |h: u32| {
        h.checked_sub(start)
            .and_then(|i| chain.get(i as usize))
            .copied()
    };
    let height = parent_height + 1;
    // A header below the runs is one Core does not read, so a read of it is
    // rbitcoin's answer differing from Core's, not a malformed request.
    let missing = || internal("rbitcoin reads a header before the runs Core's period gives");
    let period_first = match params.period_first_height(height) {
        Some(h) => Some(
            at(h)
                .map(|(time, bits)| PeriodFirst { time, bits })
                .ok_or_else(missing)?,
        ),
        None => None,
    };
    let bits = header::next_work_bits(
        &params,
        height,
        prev_bits,
        prev_time,
        time,
        period_first,
        |h| at(h).map(|(_, bits)| bits),
    )
    .ok_or_else(missing)?;
    Ok(json!({"bits": bits.to_consensus()}))
}

fn signet_check(req: &Value) -> Resp {
    let block: Block = deserialize(&hex_field(req, "block")?)
        .map_err(|e| bad(format!("block does not decode whole: {e}")))?;
    let challenge = ScriptBuf::from_bytes(hex_field(req, "challenge")?);
    let ok = rbitcoin_consensus::validate_signet_block_solution(&block, &challenge).is_ok();
    Ok(json!({"valid": ok}))
}

/// The hashes `ScriptVerifyFlags::for_block` gives another P2SH, WITNESS and
/// TAPROOT set than every other block, with the flags of that set.
fn script_flag_exceptions(params: &ChainParams) -> Vec<Value> {
    let mut out: Vec<(String, Vec<&str>)> = [
        block::BIP16_EXCEPTION_MAINNET,
        block::TAPROOT_EXCEPTION_MAINNET,
        block::BIP16_EXCEPTION_TESTNET3,
    ]
    .iter()
    .filter_map(|hash| {
        // Above every buried height, where any other hash gets all three.
        let f = ScriptVerifyFlags::for_block(params, 1_000_000, hash, 0);
        let set: Vec<&str> = [
            (f.bip16_active, "P2SH"),
            (f.witness_active, "WITNESS"),
            (f.taproot_active, "TAPROOT"),
        ]
        .into_iter()
        .filter_map(|(on, name)| on.then_some(name))
        .collect();
        (set.len() < 3).then(|| (BlockHash::from_byte_array(*hash).to_string(), set))
    })
    .collect();
    out.sort();
    out.into_iter().map(|(h, set)| json!([h, set])).collect()
}

fn network_params(req: &Value) -> Resp {
    let network = network_field(req)?;
    let params = ChainParams::for_network(network);
    let btc = &params.btc;
    let bip34_hash = params
        .bip34_hash
        .unwrap_or_else(|| BlockHash::from_byte_array([0; 32]));
    Ok(json!({
        "genesis_hash": params.genesis_hash.to_string(),
        "subsidy_halving_interval": params.subsidy_halving_interval(),
        "bip34_height": btc.bip34_height,
        "bip34_hash": bip34_hash.to_string(),
        "bip65_height": btc.bip65_height,
        "bip66_height": btc.bip66_height,
        "csv_height": params.csv_height(),
        "segwit_height": params.segwit_height(),
        "pow_limit": be_hex(params.pow_limit.to_be_bytes()),
        "pow_target_timespan": btc.pow_target_timespan,
        "pow_target_spacing": btc.pow_target_spacing,
        "pow_allow_min_difficulty_blocks": params.allow_min_difficulty_blocks(),
        "pow_no_retargeting": params.no_pow_retargeting(),
        "enforce_bip94": params.enforce_bip94,
        "script_flag_exceptions": script_flag_exceptions(&params),
        "signet_challenge": params.signet_challenge.as_ref().map(|s| s.as_bytes().to_lower_hex_string()),
        "message_start": rbitcoin_net::service::magic_for_params(&params).to_bytes().to_lower_hex_string(),
        "default_port": rbitcoin_net::seeds::default_port(network),
    }))
}

fn dispatch(op: &str, req: &Value) -> Resp {
    match op {
        "info" => info(),
        "script_verify" => script_verify(req),
        "tx_check" => tx_check(req),
        "sighash_legacy" => sighash_legacy(req),
        "sighash_taproot" => sighash_taproot(req),
        "taproot_commitment_verify" => taproot_commitment_verify(req),
        "schnorr_verify" => schnorr_verify(req),
        "pow_compact" => pow_compact(req),
        "pow_check" => pow_check(req),
        "pow_next_work" => pow_next_work(req),
        "signet_check" => signet_check(req),
        "network_params" => network_params(req),
        other => Err(("unsupported_op", format!("{other} is not served here"))),
    }
}

fn respond(line: &str) -> Value {
    let Ok(req) = serde_json::from_str::<Value>(line) else {
        return json!({"id": null, "ok": false, "error": "bad_request", "message": "not JSON"});
    };
    if !req.is_object() {
        return json!({"id": null, "ok": false, "error": "bad_request", "message": "not an object"});
    }
    // PROTOCOL.md section 2: a request without an integer id is not performed.
    let Some(id) = req.get("id").filter(|v| v.is_i64() || v.is_u64()).cloned() else {
        return json!({"id": null, "ok": false, "error": "bad_request", "message": "id is not an integer"});
    };
    let op = req.get("op").and_then(Value::as_str).unwrap_or_default();
    let answer = catch_unwind(AssertUnwindSafe(|| dispatch(op, &req)))
        .unwrap_or_else(|_| Err(internal("panic")));
    match answer {
        Ok(Value::Object(mut m)) => {
            m.insert("id".into(), id);
            m.insert("ok".into(), Value::Bool(true));
            Value::Object(m)
        }
        Ok(other) => {
            json!({"id": id, "ok": false, "error": "internal", "message": other.to_string()})
        }
        Err((code, msg)) => json!({"id": id, "ok": false, "error": code, "message": msg}),
    }
}

fn main() {
    let mut out = std::io::stdout().lock();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        if writeln!(out, "{}", respond(&line))
            .and_then(|()| out.flush())
            .is_err()
        {
            break;
        }
    }
}
