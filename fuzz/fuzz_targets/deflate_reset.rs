#![no_main]

use std::mem::{size_of, MaybeUninit};

use libfuzzer_sys::fuzz_target;
use libz_rs_sys::*;
use zlib_rs::{deflate::DeflateConfig, ReturnCode};

fuzz_target!(|input: (&[u8], DeflateConfig)| {
    let (data, config) = input;

    if data.is_empty() {
        return;
    }

    // Split the input into two halves.
    let mid = data.len() / 2;
    let first = &data[..mid];
    let second = &data[mid..];

    // Initialize the deflate stream.
    let mut stream = MaybeUninit::zeroed();
    let err = unsafe {
        deflateInit2_(
            stream.as_mut_ptr(),
            config.level,
            config.method as i32,
            config.window_bits,
            config.mem_level,
            config.strategy as i32,
            zlibVersion(),
            size_of::<z_stream>() as i32,
        )
    };

    if err != ReturnCode::Ok as i32 {
        return;
    }

    let stream = unsafe { stream.assume_init_mut() };

    let mut output = Vec::with_capacity(deflate_bound_size(stream, first));

    // Deflate the first buffer.
    stream.next_in = first.as_ptr() as *mut u8;
    stream.avail_in = first.len() as _;
    stream.next_out = output.as_mut_ptr();
    stream.avail_out = output.capacity() as _;

    let err = unsafe { deflate(stream, Z_FINISH) };
    match ReturnCode::from(err) {
        ReturnCode::StreamEnd | ReturnCode::Ok => {}
        _ => {
            unsafe { deflateEnd(stream) };
            return;
        }
    }

    // Reset the stream, reusing all internal allocations.
    let err = unsafe { deflateReset(stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

    // Deflate the second buffer on the reset stream.
    let mut output2 = Vec::with_capacity(deflate_bound_size(stream, second));

    stream.next_in = second.as_ptr() as *mut u8;
    stream.avail_in = second.len() as _;
    stream.next_out = output2.as_mut_ptr();
    stream.avail_out = output2.capacity() as _;

    let err = unsafe { deflate(stream, Z_FINISH) };
    match ReturnCode::from(err) {
        ReturnCode::StreamEnd => {
            unsafe { output2.set_len(stream.total_out as usize) };
        }
        ReturnCode::Ok => {
            // Output buffer too small to finish in one call; that's fine.
        }
        other => {
            panic!("unexpected error after deflateReset: {other:?}");
        }
    }

    let err = unsafe { deflateEnd(stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
});

fn deflate_bound_size(stream: &mut z_stream, data: &[u8]) -> usize {
    unsafe { deflateBound(stream, data.len() as _) as usize }
}
