#![no_main]

use std::ffi::{c_void, CString};

use libfuzzer_sys::fuzz_target;
use libz_rs_sys::*;
use zlib_rs::ReturnCode;

fuzz_target!(|data: &[u8]| {
    // Write fuzzed data through gzwrite, then read it back through gzread and verify the
    // round-trip. Uses a temporary file as the backing store.

    let dir = std::env::temp_dir();
    let path = dir.join(format!("gz_fuzz_{}", std::process::id()));
    let c_path = CString::new(path.to_str().unwrap()).unwrap();

    // --- write phase ---
    let wb = CString::new("wb").unwrap();
    let gz = unsafe { gzopen(c_path.as_ptr(), wb.as_ptr()) };
    if gz.is_null() {
        return;
    }

    // Write in chunks of varying size to exercise internal buffering.
    let chunk_size = 137;
    let mut written_total = 0usize;
    for chunk in data.chunks(chunk_size) {
        let n = unsafe { gzwrite(gz, chunk.as_ptr() as *const c_void, chunk.len() as _) };
        if n <= 0 {
            unsafe { gzclose(gz) };
            let _ = std::fs::remove_file(&path);
            return;
        }
        written_total += n as usize;
    }
    assert_eq!(written_total, data.len());

    let err = unsafe { gzclose(gz) };
    assert_eq!(err, ReturnCode::Ok as i32);

    // --- read phase ---
    let rb = CString::new("rb").unwrap();
    let gz = unsafe { gzopen(c_path.as_ptr(), rb.as_ptr()) };
    assert!(!gz.is_null());

    let mut output = vec![0u8; data.len() + 1]; // +1 so we can detect over-read
    let mut read_total = 0usize;

    loop {
        let remaining = output.len() - read_total;
        if remaining == 0 {
            break;
        }
        let n = unsafe {
            gzread(
                gz,
                output[read_total..].as_mut_ptr() as *mut c_void,
                remaining as _,
            )
        };
        if n == 0 {
            // EOF
            break;
        }
        if n < 0 {
            panic!("gzread returned error: {n}");
        }
        read_total += n as usize;
    }

    assert_eq!(unsafe { gzeof(gz) }, 1, "expected EOF after reading all data");

    let err = unsafe { gzclose(gz) };
    assert_eq!(err, ReturnCode::Ok as i32);

    assert_eq!(read_total, data.len());
    assert_eq!(&output[..read_total], data);

    let _ = std::fs::remove_file(&path);
});
