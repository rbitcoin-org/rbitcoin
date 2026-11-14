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
//! Chain operations are `scripts/consensus-spec/chain_harness.py`.

use std::cell::OnceCell;
use std::io::{BufRead, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::script::Script;
use bitcoin::secp256k1::{schnorr, Message, XOnlyPublicKey};
use bitcoin::sighash::{SighashCache, TapSighashType};
use bitcoin::{Amount, ScriptBuf, TapLeafHash, Transaction, TxOut};
use rbitcoin_consensus::block::{self, InputIndex, ScriptCheckJob, ScriptVerifyFlags};
use rbitcoin_consensus::script::{self, crypto, interpreter, p2tr};
use rbitcoin_consensus::{block_reject_reason, ConsensusError, OutPointSet, TxPrecompute};
use serde_json::{json, Value};

const OPS: &[&str] = &[
    "info",
    "script_verify",
    "tx_check",
    "sighash_legacy",
    "sighash_taproot",
    "taproot_commitment_verify",
    "schnorr_verify",
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
    // `buried` sets NULLDUMMY and WITNESS; the request names every flag it wants.
    let mut f = ScriptVerifyFlags::buried(false, false, false, false, false);
    f.null_dummy = false;
    f.witness_active = false;
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
    let verdict = (|| {
        let ii = InputIndex::in_tx(&job.tx, index)?;
        let (value, spk) = job.prevout_parts(ii)?;
        script::verify_input(
            &job,
            ii,
            &job.tx,
            &mut None,
            job.pre()?,
            &crypto::TapSpentHashes::default(),
            Amount::from_sat(value),
            spk,
        )
    })();
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

fn dispatch(op: &str, req: &Value) -> Resp {
    match op {
        "info" => info(),
        "script_verify" => script_verify(req),
        "tx_check" => tx_check(req),
        "sighash_legacy" => sighash_legacy(req),
        "sighash_taproot" => sighash_taproot(req),
        "taproot_commitment_verify" => taproot_commitment_verify(req),
        "schnorr_verify" => schnorr_verify(req),
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
    let id = req.get("id").cloned().unwrap_or(Value::Null);
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
