#![no_main]

use std::mem::{size_of, MaybeUninit};

use libfuzzer_sys::fuzz_target;
use libz_rs_sys::*;
use zlib_rs::ReturnCode;

/// Compress `data` with default settings, returning the deflated bytes.
fn deflate_buf(data: &[u8]) -> Option<Vec<u8>> {
    let mut stream = MaybeUninit::zeroed();
    let err = unsafe {
        deflateInit_(
            stream.as_mut_ptr(),
            Z_DEFAULT_COMPRESSION,
            zlibVersion(),
            size_of::<z_stream>() as i32,
        )
    };

    if err != ReturnCode::Ok as i32 {
        return None;
    }

    let stream = unsafe { stream.assume_init_mut() };

    let bound = unsafe { deflateBound(stream, data.len() as _) } as usize;
    let mut out = Vec::with_capacity(bound);

    stream.next_in = data.as_ptr() as *mut u8;
    stream.avail_in = data.len() as _;
    stream.next_out = out.as_mut_ptr();
    stream.avail_out = out.capacity() as _;

    let err = unsafe { deflate(stream, Z_FINISH) };
    if ReturnCode::from(err) != ReturnCode::StreamEnd {
        unsafe { deflateEnd(stream) };
        return None;
    }

    unsafe { out.set_len(stream.total_out as usize) };
    unsafe { deflateEnd(stream) };

    Some(out)
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Split the raw input into two halves, compress each independently.
    let mid = data.len() / 2;
    let first_compressed = match deflate_buf(&data[..mid]) {
        Some(v) => v,
        None => return,
    };
    let second_compressed = match deflate_buf(&data[mid..]) {
        Some(v) => v,
        None => return,
    };

    // Initialize the inflate stream.
    let mut stream = MaybeUninit::zeroed();
    let err = unsafe {
        inflateInit_(
            stream.as_mut_ptr(),
            zlibVersion(),
            size_of::<z_stream>() as i32,
        )
    };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

    let stream = unsafe { stream.assume_init_mut() };

    // Inflate the first compressed buffer.
    let mut output1 = vec![0u8; data.len()];

    stream.next_in = first_compressed.as_ptr() as *mut u8;
    stream.avail_in = first_compressed.len() as _;
    stream.next_out = output1.as_mut_ptr();
    stream.avail_out = output1.len() as _;

    let err = unsafe { inflate(stream, Z_FINISH) };
    match ReturnCode::from(err) {
        ReturnCode::StreamEnd => {
            output1.truncate(stream.total_out as usize);
            assert_eq!(&output1, &data[..mid]);
        }
        other => {
            panic!("inflate of first buffer failed: {other:?}");
        }
    }

    // Reset the stream, reusing all internal allocations.
    let err = unsafe { inflateReset(stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

    // Inflate the second compressed buffer on the reset stream.
    let mut output2 = vec![0u8; data.len()];

    stream.next_in = second_compressed.as_ptr() as *mut u8;
    stream.avail_in = second_compressed.len() as _;
    stream.next_out = output2.as_mut_ptr();
    stream.avail_out = output2.len() as _;

    let err = unsafe { inflate(stream, Z_FINISH) };
    match ReturnCode::from(err) {
        ReturnCode::StreamEnd => {
            output2.truncate(stream.total_out as usize);
            assert_eq!(&output2, &data[mid..]);
        }
        other => {
            panic!("inflate of second buffer after reset failed: {other:?}");
        }
    }

    let err = unsafe { inflateEnd(stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
});
