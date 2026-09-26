//! One EVTX chunk in, its records out as JSON lines.
//!
//! An EVTX file is a 4 KiB header followed by 64 KiB chunks, and each chunk carries its own string
//! and template tables, so a chunk decodes without the rest of the file. The ingest worker reads the
//! file one chunk at a time and hands each here: memory stays at one chunk whatever the file's size.
//!
//! The interface is plain exports over linear memory, so the page needs no generated glue:
//! `alloc` a buffer, copy the chunk into it, call `parse_chunk`, read `out_len` bytes at `out_ptr`.
//! Each output line is one record: `{"id":<EventRecordID>,"t":"<header write time>","d":<event>}`
//! where the event is the JSON pyevtx-rs gives the server (an integer past 2^53 is written as
//! `{"$big":"<digits>"}`, see `wrap_big`); a record that cannot be rendered is
//! `{"id":<id or null>,"e":"<error>"}`. A chunk that cannot be read at all returns -1 and its error
//! as the output.

use std::sync::{Arc, OnceLock};

use evtx::{EvtxChunkData, ParserSettings};

static mut OUT: Vec<u8> = Vec::new();

#[link(wasm_import_module = "env")]
extern "C" {
    /// Fills `len` bytes at `ptr` with crypto.getRandomValues.
    fn random_fill(ptr: *mut u8, len: usize);
}

/// getrandom's custom backend (see .cargo/config.toml).
///
/// # Safety
/// Called by getrandom with a writable buffer of `len` bytes.
#[no_mangle]
pub unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    random_fill(dest, len);
    Ok(())
}

fn settings() -> Arc<ParserSettings> {
    static S: OnceLock<Arc<ParserSettings>> = OnceLock::new();
    // pyevtx-rs's defaults: attributes under "#attributes", no indentation, checksums not enforced
    // (a damaged chunk is still read; the worker reports its checksum itself)
    S.get_or_init(|| Arc::new(ParserSettings::new().indent(false).separate_json_attributes(false).validate_checksums(false)))
        .clone()
}

#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from one `alloc` call.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len));
}

#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    #[allow(static_mut_refs)]
    unsafe {
        OUT.as_ptr()
    }
}

#[no_mangle]
pub extern "C" fn out_len() -> usize {
    #[allow(static_mut_refs)]
    unsafe {
        OUT.len()
    }
}

fn escape(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

/// Decode the chunk at `ptr` (`len` bytes, normally 65536). Takes ownership of the buffer.
/// Returns the number of records written (rendered or not), or -1 when the chunk cannot be read.
///
/// # Safety
/// `ptr` and `len` must come from one `alloc` call, filled with `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn parse_chunk(ptr: *mut u8, len: usize) -> i32 {
    let data = Vec::from_raw_parts(ptr, len, len);
    let mut out = Vec::<u8>::with_capacity(len * 4);
    let n = match decode(data, &mut out) {
        Ok(n) => n as i32,
        Err(e) => {
            out.clear();
            out.extend_from_slice(e.as_bytes());
            -1
        }
    };
    #[allow(static_mut_refs)]
    {
        OUT = out;
    }
    n
}

/// JavaScript reads JSON numbers as doubles, and a 64-bit value past 2^53 (a UInt64 of all ones is
/// common) would silently change. Such a number is written as `{"$big":"<digits>"}` instead: no
/// XML name starts with `$`, so the wrapper cannot be mistaken for an element of the event.
fn wrap_big(v: &mut serde_json::Value) {
    const SAFE: u64 = (1 << 53) - 1;
    match v {
        serde_json::Value::Number(n) => {
            let unsafe_int = n.as_u64().map(|u| u > SAFE).unwrap_or(false) || n.as_i64().map(|i| i.unsigned_abs() > SAFE).unwrap_or(false);
            if unsafe_int {
                let mut m = serde_json::Map::new();
                m.insert("$big".into(), serde_json::Value::String(n.to_string()));
                *v = serde_json::Value::Object(m);
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(wrap_big),
        serde_json::Value::Object(m) => m.values_mut().for_each(wrap_big),
        _ => {}
    }
}

fn decode(data: Vec<u8>, out: &mut Vec<u8>) -> Result<usize, String> {
    let mut chunk_data = EvtxChunkData::new(data, false).map_err(|e| e.to_string())?;
    let mut chunk = chunk_data.parse(settings()).map_err(|e| e.to_string())?;
    let mut n = 0;
    for rec in chunk.iter() {
        n += 1;
        match rec {
            Ok(r) => {
                let id = r.event_record_id;
                let t = r.timestamp.to_string();
                match r.into_json_value() {
                    Ok(mut s) => {
                        wrap_big(&mut s.data);
                        out.extend_from_slice(format!("{{\"id\":{id},\"t\":{},\"d\":", escape(&t)).as_bytes());
                        serde_json::to_writer(&mut *out, &s.data).map_err(|e| e.to_string())?;
                        out.extend_from_slice(b"}\n");
                    }
                    Err(e) => out.extend_from_slice(format!("{{\"id\":{id},\"e\":{}}}\n", escape(&e.to_string())).as_bytes()),
                }
            }
            Err(e) => out.extend_from_slice(format!("{{\"id\":null,\"e\":{}}}\n", escape(&e.to_string())).as_bytes()),
        }
    }
    Ok(n)
}
