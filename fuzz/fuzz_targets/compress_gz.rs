//! Fuzz test that tries to maximize coverage of the public API, for the purpose of finding memory
//! safety bugs and UB. Validation of correctness is not important in this test.
#![cfg_attr(not(any(miri, test)), no_main)]

use std::{
    ffi::{c_int, c_uint, c_ulong, CStr, CString},
    mem::size_of,
};

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target, Corpus,
};
use libz_rs_sys::{
    alloc_func, deflate, deflateBound, deflateEnd, deflateInit2_, deflateParams, deflatePending,
    deflateReset, deflateSetHeader, free_func, gz_header, gz_headerp, inflate, inflateEnd,
    inflateGetHeader, inflateInit2_, inflateReset, z_stream, zlibVersion,
};
use zlib_rs::{
    deflate::{DeflateConfig, Strategy},
    DeflateFlush, InflateFlush, ReturnCode,
};

fuzz_target!(|input: Input| -> Corpus { run(input) });

fn run(input: Input) -> Corpus {
    // These flush modes are a lot harder to use properly, and don't really fit well with this
    // fuzz test.
    if matches!(
        input.inflate_flush,
        InflateFlush::Block | InflateFlush::Trees
    ) {
        return Corpus::Reject;
    }

    // No sense in chunking at zero width.
    if input.deflate_chunk == 0 || input.inflate_chunk == 0 {
        return Corpus::Reject;
    }

    match compress(input.clone()) {
        None => Corpus::Reject,
        Some(compressed) => decompress(compressed, input),
    }
}

#[derive(Debug, Arbitrary, Clone)]
struct Input {
    allocator: Allocator,
    source: Vec<u8>,
    deflate_config: DeflateConfig,
    deflate_params: Vec<DeflateParams>,
    deflate_chunk: u64,
    deflate_flush: DeflateFlush,
    deflate_header: GzHeaderData,
    inflate_flush: InflateFlush,
    inflate_chunk: u64,
}

/// The inputs to deflateParams().
#[derive(Debug, Clone, Copy)]
struct DeflateParams {
    level: c_int,
    strategy: Strategy,
}

impl<'a> Arbitrary<'a> for DeflateParams {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            level: u.int_in_range(0..=9)?,
            strategy: u.arbitrary()?,
        })
    }
}

#[derive(Debug, Arbitrary, Clone)]
struct GzHeaderData {
    text: i32,
    time: c_ulong,
    os: i32,
    extra: Vec<u8>,
    name: CString,
    comment: CString,
    hcrc: i32,
}

impl GzHeaderData {
    /// Safety: [`Self`] needs to live as long as the returned gz_header.
    unsafe fn as_gz_header(&mut self) -> gz_header {
        gz_header {
            text: self.text,
            time: self.time,
            xflags: 0,
            os: self.os,
            extra: self.extra.as_mut_ptr(),
            extra_len: self.extra.len().try_into().unwrap(),
            // Doesn't matter for writing.
            extra_max: 0,
            // Hack: UB if written to, but we shouldn't write during deflate.
            name: self.name.as_ptr() as *mut u8,
            // Doesn't matter for writing.
            name_max: 0,
            // Hack: UB if written to, but we shouldn't write during deflate.
            comment: self.comment.as_ptr() as *mut u8,
            // Doesn't matter for writing.
            comm_max: 0,
            hcrc: self.hcrc,
            // Doesn't matter for writing.
            done: 0,
        }
    }
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum Allocator {
    C,
    Rust,
}

impl Allocator {
    fn zalloc(&self) -> alloc_func {
        match self {
            Allocator::C => ::zlib_rs::allocate::Allocator::C.zalloc,
            Allocator::Rust => ::zlib_rs::allocate::Allocator::RUST.zalloc,
        }
    }

    fn zfree(&self) -> free_func {
        match self {
            Allocator::C => ::zlib_rs::allocate::Allocator::C.zfree,
            Allocator::Rust => ::zlib_rs::allocate::Allocator::RUST.zfree,
        }
    }
}

fn compress(input: Input) -> Option<Vec<u8>> {
    let Input {
        allocator,
        mut source,
        deflate_config: config,
        deflate_params: params,
        deflate_chunk: chunk,
        deflate_flush: flush,
        deflate_header: mut header,
        ..
    } = input;

    let mut stream = z_stream {
        next_in: core::ptr::null_mut(),
        avail_in: 0,
        total_in: 0,
        next_out: core::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        msg: std::ptr::null_mut(),
        state: std::ptr::null_mut(),
        zalloc: Some(allocator.zalloc()),
        zfree: Some(allocator.zfree()),
        opaque: std::ptr::null_mut(),
        data_type: 0,
        adler: 0,
        reserved: 0,
    };
    let err = unsafe {
        deflateInit2_(
            &mut stream,
            input.deflate_config.level,
            input.deflate_config.method as i32,
            input.deflate_config.window_bits,
            input.deflate_config.mem_level,
            input.deflate_config.strategy as i32,
            zlibVersion(),
            size_of::<z_stream>() as c_int,
        )
    };
    if err != ReturnCode::Ok as i32 {
        return None;
    }

    // Using a gzip header is only possible with gzip wrapping.
    let mut header = unsafe { header.as_gz_header() };
    if config.window_bits >= 16 {
        let err = unsafe { deflateSetHeader(&mut stream, &mut header as gz_headerp) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
    }

    let buf_size = unsafe { deflateBound(&mut stream, source.len() as u64) };

    let mut defl = vec![0; buf_size as usize];
    let max = c_uint::MAX as usize;

    let chunk: u32 = Ord::min(chunk, defl.len() as u64).try_into().unwrap();

    stream.next_in = source.as_mut_ptr().cast();
    stream.next_out = defl.as_mut_ptr().cast();

    match flush {
        DeflateFlush::PartialFlush
        | DeflateFlush::SyncFlush
        | DeflateFlush::Block
        | DeflateFlush::FullFlush
        | DeflateFlush::NoFlush => {
            // Break input into chunks.
            let mut left: u32 = Ord::min(source.len(), max) as _;
            stream.avail_out = Ord::min(defl.len(), max) as _;
            let mut params_idx = 0;
            while left > 0 {
                // Sanity check on this function. It's unlikely to ever have problems, since it's
                // straightforward load-and-store, but better safe than sorry.
                let _ = unsafe {
                    let mut pending = 0;
                    let mut bits = 0;
                    assert_eq!(
                        ReturnCode::from(deflatePending(&mut stream, &mut pending, &mut bits)),
                        ReturnCode::Ok
                    );
                    (pending, bits)
                };

                // Write the chunk.
                let avail = Ord::min(chunk, left).try_into().unwrap();
                stream.avail_in = avail;
                let err = unsafe { deflate(&mut stream, flush as i32) };
                match ReturnCode::from(err) {
                    ReturnCode::Ok => {
                        left -= avail;
                    }
                    ReturnCode::BufError => {
                        if flush == DeflateFlush::NoFlush && params.is_empty() {
                            // We shouldn't see this error in NoFlush and with static parameters,
                            // because the buffer should always be precisely allocated correctly.
                            panic!("deflateBounds() miscalculated")
                        } else {
                            let add_space: u32 = buf_size.try_into().unwrap();
                            defl.extend(core::iter::repeat_n(0, buf_size.try_into().unwrap()));

                            // If extend() reallocates, it may have moved in memory.
                            stream.next_out = defl.as_mut_ptr();
                            stream.avail_out += add_space;

                            left -= avail - stream.avail_in;
                        }
                    }
                    err => {
                        if !stream.msg.is_null() {
                            dbg!(unsafe { CStr::from_ptr(stream.msg) });
                        }
                        panic!("fatal {:?}", err)
                    }
                }

                // Exercise deflateParams(). On each chunk, choose the next set of parameters to
                // use.
                if let Some(param) = params.get(params_idx) {
                    // deflateParams() under the hood invokes a deflate() call to flush the pending
                    // buffer. Because we don't rerun deflate() in the above code directly after
                    // reallocating (it's done on the next loop iteration), we may end up writing
                    // pending bytes to the newly reallocated buffer in deflateParams(). So we
                    // still need to do bookkeeping on `left`.
                    //
                    // This could probably be refactored to be clearer.
                    let avail_in = stream.avail_in;
                    let err =
                        unsafe { deflateParams(&mut stream, param.level, param.strategy as _) };
                    match ReturnCode::from(err) {
                        ReturnCode::Ok => {
                            left -= avail_in - stream.avail_in;
                        }
                        ReturnCode::BufError => {
                            // Flushing the current pending data may run us out of buffer space.
                            let add_space: u32 = buf_size.try_into().unwrap();
                            defl.extend(core::iter::repeat_n(0, buf_size.try_into().unwrap()));

                            // If extend() reallocates, it may have moved in memory.
                            stream.next_out = defl.as_mut_ptr();
                            stream.avail_out += add_space;

                            let err = unsafe {
                                deflateParams(&mut stream, param.level, param.strategy as _)
                            };
                            assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
                            left -= avail_in - stream.avail_in;
                        }
                        err => {
                            if !stream.msg.is_null() {
                                dbg!(unsafe { CStr::from_ptr(stream.msg) });
                            }
                            panic!("fatal {:?}", err)
                        }
                    }
                }

                params_idx += 1;
            }

            assert_eq!(left, 0);

            // Finish the stream.
            let err = unsafe { deflate(&mut stream, DeflateFlush::Finish as _) };
            if (flush == DeflateFlush::NoFlush || flush == DeflateFlush::Finish)
                && params.is_empty()
            {
                // We definitely should be done if in these modes and we've not changed the
                // parameters mid-stream.
                assert_eq!(ReturnCode::from(err), ReturnCode::StreamEnd);
            } else {
                match ReturnCode::from(err) {
                    ReturnCode::Ok | ReturnCode::BufError => {
                        // We might have run out of input space, but still need more space to write the
                        // header.
                        loop {
                            let add_space: u32 = buf_size.try_into().unwrap();
                            defl.extend(core::iter::repeat_n(0, buf_size.try_into().unwrap()));

                            // If extend() reallocates, it may have moved in memory.
                            stream.next_out = defl.as_mut_ptr();
                            stream.avail_out += add_space;

                            let err = unsafe { deflate(&mut stream, DeflateFlush::Finish as _) };
                            match ReturnCode::from(err) {
                                ReturnCode::Ok => continue,
                                ReturnCode::BufError => continue,
                                ReturnCode::StreamEnd => break,
                                _ => unreachable!(),
                            }
                        }
                    }
                    ReturnCode::StreamEnd => { /* do nothing, we're done */ }
                    err => panic!("fatal {:?}", err),
                }
            }
        }
        DeflateFlush::Finish => {
            // Ignore the chunk and params parameters. We can only use Finish in the first deflate
            // call if we're doing compression in a single step. Since we're not chunking, it makes
            // no sense to try to dynamically change the deflate parameters either.
            stream.avail_in = Ord::min(source.len(), max) as _;
            stream.avail_out = Ord::min(defl.len(), max) as _;
            let err = unsafe { deflate(&mut stream, flush as _) };
            assert_eq!(ReturnCode::from(err), ReturnCode::StreamEnd);
        }
    }

    defl.truncate(stream.total_out as usize);

    // Reset the stream state and trivially write out more data to prove deflateReset() works.
    let err = unsafe { deflateReset(&mut stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
    let mut dest2 = vec![0; buf_size as usize];
    let max = c_uint::MAX as usize;
    stream.next_in = source.as_mut_ptr().cast();
    stream.next_out = dest2.as_mut_ptr().cast();
    stream.avail_in = Ord::min(source.len(), max) as _;
    stream.avail_out = Ord::min(dest2.len(), max) as _;
    let err = unsafe { deflate(&mut stream, DeflateFlush::Finish as _) };
    assert_eq!(ReturnCode::from(err), ReturnCode::StreamEnd);

    let err = unsafe { deflateEnd(&mut stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

    // Sanity inflate check against zlib-ng. Only do this if we're not under Miri, since Miri can't
    // FFI out (easily). This is fine anyways, because we're only going to run Miri against data
    // that is part of the corpus, and therefore has already passed this check anyway.
    if !cfg!(miri) {
        let mut infl_len = source.len();
        let mut infl = vec![0; infl_len];
        let err = unsafe {
            libz_ng_sys::uncompress(
                infl.as_mut_ptr(),
                &mut infl_len,
                defl.as_mut_ptr(),
                defl.len().try_into().unwrap(),
            )
        };
        if ReturnCode::from(err) != ReturnCode::Ok {
            // We've created something totally bogus that won't decompress. Ignore it.
            return None;
        }
        infl.truncate(infl_len);
        assert_eq!(infl, source);
    }

    Some(defl)
}

fn decompress(mut compressed: Vec<u8>, input: Input) -> Corpus {
    let Input {
        allocator,
        source,
        deflate_config,
        inflate_flush: flush,
        inflate_chunk: chunk,
        ..
    } = input;

    // We'll just use the deflate's configuration to ensure we choose the right wrapping.
    let window_bits = match deflate_config.window_bits {
        8 => 9,
        n => n,
    };

    let mut stream = z_stream {
        next_in: core::ptr::null_mut(),
        avail_in: 0,
        total_in: 0,
        next_out: core::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        msg: std::ptr::null_mut(),
        state: std::ptr::null_mut(),
        zalloc: Some(allocator.zalloc()),
        zfree: Some(allocator.zfree()),
        opaque: std::ptr::null_mut(),
        data_type: 0,
        adler: 0,
        reserved: 0,
    };
    let err = unsafe {
        inflateInit2_(
            &mut stream,
            window_bits,
            zlibVersion(),
            size_of::<z_stream>() as _,
        )
    };
    if err != ReturnCode::Ok as i32 {
        // Reject--the parameters are malformed.
        return Corpus::Reject;
    }

    let mut extra = vec![0; 64];
    let mut name = vec![0; 64];
    let mut comment = vec![0; 64];
    let mut header = gz_header {
        text: 0,
        time: 0,
        xflags: 0,
        os: 0,
        extra: extra.as_mut_ptr(),
        extra_len: 0,
        extra_max: 64,
        name: name.as_mut_ptr(),
        name_max: 64,
        comment: comment.as_mut_ptr(),
        comm_max: 64,
        hcrc: 0,
        done: 0,
    };
    if window_bits >= 16 {
        let err = unsafe { inflateGetHeader(&mut stream, &mut header) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
    }

    let mut buf = vec![0; source.len()];
    stream.next_in = compressed.as_mut_ptr();
    stream.avail_in = compressed.len().try_into().unwrap();
    stream.next_out = buf.as_mut_ptr();
    stream.avail_out = buf.len().try_into().unwrap();

    match flush {
        InflateFlush::NoFlush | InflateFlush::SyncFlush => {
            // Break input into chunks.
            let mut left: u32 = compressed.len().try_into().unwrap();
            stream.avail_out = buf.len().try_into().unwrap();
            while left > 0 {
                // Write the chunk.
                let avail = Ord::min(chunk, left.into()).try_into().unwrap();
                stream.avail_in = avail;
                let err = unsafe { inflate(&mut stream, flush as i32) };
                match ReturnCode::from(err) {
                    ReturnCode::Ok => {
                        left -= avail;
                    }
                    ReturnCode::StreamEnd => {
                        left -= avail;
                        break;
                    }
                    err => {
                        if !stream.msg.is_null() {
                            dbg!(unsafe { CStr::from_ptr(stream.msg) });
                        }
                        panic!("fatal {:?}", err)
                    }
                }
            }

            assert_eq!(left, 0);

            // Finish the stream.
            let err = ReturnCode::from(unsafe { inflate(&mut stream, DeflateFlush::Finish as _) });
            // Hack, if we ended the stream above this call might return BufError.
            assert!(err == ReturnCode::StreamEnd || err == ReturnCode::BufError);
        }
        InflateFlush::Finish => {
            let err = unsafe { inflate(&mut stream, InflateFlush::Finish as _) };
            match ReturnCode::from(err) {
                ReturnCode::Ok => {
                    panic!("out of space?")
                }
                ReturnCode::StreamEnd => { /* done */ }
                err => {
                    if !stream.msg.is_null() {
                        dbg!(unsafe { CStr::from_ptr(stream.msg) });
                    }
                    panic!("unexpected error: {:?}", err)
                }
            }
        }
        _ => {
            unreachable!("filtered out earlier");
        }
    }

    assert_eq!(buf, source);

    // Reset the stream state and trivially write out more data to prove inflateReset() works.
    let err = unsafe { inflateReset(&mut stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
    let mut dest2 = vec![0; source.len()];
    stream.next_in = compressed.as_mut_ptr();
    stream.avail_in = compressed.len().try_into().unwrap();
    stream.next_out = dest2.as_mut_ptr();
    stream.avail_out = dest2.len().try_into().unwrap();
    let err = unsafe { inflate(&mut stream, DeflateFlush::Finish as _) };
    assert_eq!(ReturnCode::from(err), ReturnCode::StreamEnd);

    let err = unsafe { inflateEnd(&mut stream) };
    assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

    Corpus::Keep
}

#[cfg(test)]
mod tests {
    use std::ffi::{c_int, CString};

    use libz_rs_sys::{
        deflate, deflateBound, deflateEnd, deflateInit2_, deflateParams, deflateSetHeader,
        gz_header, gz_headerp, z_stream, zlibVersion,
    };
    use zlib_rs::{
        deflate::{DeflateConfig, Method, Strategy},
        DeflateFlush, ReturnCode,
    };

    #[cfg(miri)]
    use {
        crate::{run, GzHeaderData, Input},
        libfuzzer_sys::arbitrary::{Arbitrary, Unstructured},
        rstest::rstest,
        std::{fs::File, io::Read, path::PathBuf},
    };

    #[rstest]
    #[cfg(miri)]
    fn miri_corpus(#[files("corpus/compress_gz/*")] path: PathBuf) {
        let mut input = File::open(path).unwrap();
        let mut buf = Vec::new();
        input.read_to_end(&mut buf).unwrap();

        let mut unstructured = Unstructured::new(&buf);
        let input = Input::arbitrary(&mut unstructured).unwrap();
        run(input);
    }

    #[test]
    fn inahga_1() {
        let mut source =  "\0\u{f}\u{7f}\0---\0\0\0\0\0\0\0\0<\u{2}\0\0\u{1}\0\0\0>\u{2}\0\0MMM\0\0\0\0\u{1f}\0@\0\u{3}\0\0\0\0\0\0\u{1}\0\u{2}j\0\0\0\0\u{1f}\0\0\0\u{1f}\0\0\0\u{3}\0\0\0\09===}===='''''''''''\0\u{1}\0\0\u{8}\0\u{1}\0\0\0y\0\0\0\0\0\0\0\0\0\0-\0\u{1}\u{1}\0\0\0\t\0\0\0'''''--6\06666\0\0\0\u{18}66\0\0\0\0\0\0\u{1f}(\0\0\u{3}\0\0\0'':/&'''1'''''\0\0\0\0\0\0\0\0\0\0u\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0 \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{3}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0.\u{6}\0\0\0\0\0\0\0\09===}===='''''''''''\0\u{1}\0\0\u{8}\0\u{1}\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0''''''\0\0\0\0\u{14}\u{1f}\0\0\0\u{3}\0\0\0\0\0\0~#\0'\0\u{1d}======}===='&'''''''''\0\0\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0''''''\0\0\0\0\u{10}\u{1f}\0\0\0\u{3}\0\0\0\u{10}===}====''''''+'&''''\0\0\0\0'''''\05\053uu}u*\0\0\0\0\0\u{19}\u{19}\u{19}0000000000008207641\0\u{10}\0\u{19}\u{19}0000000000016415282065675765J533$444444444444445<\0\0\04444444404444444444\0\u{10}\0\0\0\0\0=6\u{4}\0\u{1}\0 \u{3}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\"\u{1f}\0@\0\0\0\0\0\0\u{3}\0\0\0\0\u{10}\u{1}===='''''''''''\0\0\0\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\02709\0'''''\u{11}\0\0\0\0\0\0\0\0\0\0\0\0\0\u{3}\0\0\0\0\0\u{3}\0\0\0\0\u{10}\u{1}===='''''''''''\0\0\0\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\02709\0'''''\0\0\0\0\0\0\0\0\0\0\0\0\0\u{2}\u{1}\0\0\0\0\u{2}\u{1}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0>\u{2}\0\0MMM\0\0\0\0\u{1f}\0@\0\u{3}\0\0\0\0\0\0\u{1}\0\u{2}j\0\0\0\0\u{1f}\0\0\0\u{1f}\0\0\0'\u{3}\0\0\0\09===}===='''''''''''\0\u{1}\0\0\u{8}\0\u{1}\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0''''''\0\0\0\0\u{14}\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0\u{19}\u{19}0000000000016415282065675765533$444444444444445<\0\0\04>\u{2}4444404444444444\0\u{10}\0\0\0\0\0=6\0\0\0\0\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0\0\0\u{10}\0\0\0\0####'=\u{1d}\0\0=====}\u{1}\0\0\u{13}''''''''====''''''''''%\0\0\0\0\0\0\0\0\0\0\u{c}\u{c}\u{c}\u{2}\0\0\0\u{3}\u{4}\0\u{1}\0 \u{3}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\"\u{1f}\0@\0\0\0\0\0\0\u{3}\0\0\0\0\u{10}\u{1}===='''''''''''\0\0\0\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\027009\0'''''\0\0\0\0\0\0\0\0\0\0\0\0\0\u{2}\u{1}\0\0\0\0\u{2}\u{1}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{4}\0\0\0\0\0\0\u{2}\0\0\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0'''<==='''''''''''\0\0\0\0\0\0'\0\0\0\0\0\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0\0\0\u{10}\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0~#\0'\0\u{1d}======}===='&'''''''''\0\0\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0''''''\0\0\0\0\u{10}\u{1f}\0\0\0\u{3}\0\0\0\u{10}===}===='''\0'\u{1d}======}\u{1}\0\0$\u{13}'''\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0''\0\0\0\0\u{10}\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0\0\0\u{10}\0\0\0\0####\0\0'\u{1d}======}\u{1}\0\0$\u{13}'''\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0\0\0\u{10}\0\0\0\0####'=\u{1d}\0\0=====}\u{1}\0\0\u{13}''''''''===='''''''''''\0\0\0\0\0\0\0\0\0\0\u{c}\u{c}\u{c}\u{2}\0\0\0\u{3}\0\0'''''''\u{1d}(======'''''''''''\0\0\0\0\0\0\u{1}\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0''''''\0\0\0\0\u{14}\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0?\0\u{10}\0\0\0\0##''===='''''''''''\0\0\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}''''\0\0\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0'''<==='''''''''''\0\0\0\0\0\0'\0\0\0\0\0\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0\0\0\u{10}\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0~#\0'\0\u{1d}======}===='&'''''''''\0\0\0\0\0\0\0\0\0\u{1f}\u{1}\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0''''''\0\0\0\0\u{10}\u{1f}\0\0\0\u{3}\0\0\0\u{10}===}===='''''\u{1f}\u{1}\0\0\0\0\0\0\0\0\0\0''''''\0\0\0\0\u{14}\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0?\0\u{10}\0\0\0\0##c#\0\0'\u{1d}======}\u{1}\0\0$'''\0\0\0\0\0\0\u{1}\0\0\u{1f}A\0\0\0\0\0\0\u{2}\0\0\0\u{3}\0\0'''''p\0\0\0\0\u{14}\u{1f}\0\0\0\u{3}\0\0\0\u{10}\0?\0\u{10}\0\0\0\0##c#\0\0'\u{1d}======}\u{1}\0\0$\u{13}'''\0\0\0\0\u{1f}\0\0\0\0\u{3}\0\0\0\u{10}\0\0\0\u{10}\0\0\0\0'##\0\0#\u{1d}#======}\u{1}\0\0\u{13}''''''''====''''''''HHHHHHHHH\0".to_string();

        let config = DeflateConfig {
            level: -1,
            method: Method::Deflated,
            window_bits: 31,
            mem_level: 1,
            strategy: Strategy::HuffmanOnly,
        };

        let name = CString::new([
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x97, 0x97, 0x97, 0x97,
            0x97, 0x97, 0x97, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x97, 0x97,
            0x97, 0x97, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8b,
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x97, 0x97, 0x97, 0x97,
            0x97, 0x97, 0x97, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x97, 0x97, 0x97, 0x97, 0x97,
            0x97, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x97, 0x97,
            0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x97, 0x97, 0x97,
            0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0x99, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x97, 0x97, 0x97, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x97,
            0x97, 0x97, 0x97, 0x97, 0x97, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b, 0x8b,
            0x8b, 0x8b, 0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0x97, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ])
        .unwrap();

        dbg!(name.count_bytes());

        let comment = CString::new("").unwrap();

        let mut extra = [
            139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 139, 151, 151, 151, 151, 151,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 139, 0, 139, 139, 139, 139, 139, 139, 139, 139, 139,
            139, 139, 139, 139, 139, 139, 139, 223, 223, 223, 223, 223, 139, 139, 139, 255, 255,
            255, 255, 255, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193,
            193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 193, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 151, 151, 151, 151, 151, 151, 151,
            39,
        ]
        .to_vec();

        let mut header = gz_header {
            text: 0,
            time: 10055284024492657547,
            xflags: 0,
            os: -1953789045,
            extra: extra.as_mut_ptr(),
            extra_len: extra.len().try_into().unwrap(),
            extra_max: 0,                         // doesn't matter for writing.
            name: name.as_ptr() as *mut u8, // hack: UB if written to, but we shouldn't write during deflate.
            name_max: 0,                    // doesn't matter for writing.
            comment: comment.as_ptr() as *mut u8, // hack: UB if written to, but we shouldn't write during deflate.
            comm_max: 0,                          // doesn't matter for writing.
            hcrc: 222,
            done: 0, // doesn't matter for writing.
        };

        let mut stream = z_stream::default();
        let err = unsafe {
            deflateInit2_(
                &mut stream,
                config.level,
                config.method as i32,
                config.window_bits,
                config.mem_level,
                config.strategy as i32,
                libz_rs_sys::zlibVersion(),
                size_of::<z_stream>() as c_int,
            )
        };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        let err = unsafe { deflateSetHeader(&mut stream, &mut header as gz_headerp) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        let bound = unsafe { libz_rs_sys::deflateBound(&mut stream, source.len() as u64) };
        let mut dest = vec![0; bound as usize];

        dbg!(bound);

        stream.next_in = source.as_mut_ptr().cast();
        stream.avail_in = source.len() as _;
        stream.next_out = dest.as_mut_ptr().cast();
        stream.avail_out = dest.len() as _;

        dbg!(stream);

        let err = unsafe { libz_rs_sys::deflate(&mut stream, DeflateFlush::NoFlush as _) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        let err = unsafe { libz_rs_sys::deflateEnd(&mut stream) };
        assert_eq!(ReturnCode::from(err), ReturnCode::DataError);
    }

    #[test]
    fn inahga_2() {
        let mut source = "\0\0\u{10}\0\0\0\0\0\0\0\0\0-\0\u{1}\u{1}\0\0\0\t\0\0\0'''''--6\06&''\0\0\0\0\0N\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{1}\0\0\0\0\0\0\u{5}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0aa'aaa\u{f}\0\0\0\0\0\u{5}\0\0q\0\0\0\0\u{19}\u{1a}\u{1a}\0\0\0\0\u{5}\0\0(\0\0\0\u{3}\0\0\0 ;\0\0\0\0\0\0\u{1f}\0\0\0\u{2}\0\0'''''''=@=============='''aq\u{18}qqqqqyqaaaa'aaaqqqqqqqqyq,,,\0\0\0\n\0\0\u{1}\u{4}\0\0\0\0\0\0\0\0\0\0\u{19}\u{1a}A\0\0\0\0\u{5}\0\0(\0\0\0\u{3}\0\0\0 \0\0\0\0\0\0\0\0\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0#\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0(\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0l\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{1}\0\0'y\u{1f}\u{2}\0\0\0\0\0\u{3}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\0\0\0\0{y\0yyy\0\0\0\0\0\0n\u{1}\u{8}\0\0\u{1}\0\0\0\0\0\0\u{4}\0\0\0\0\0\u{2}\u{10}z\0\0\0\0\u{8}\u{8}\0\u{1f}\0\u{2}\u{10}\t\0\0\0\0\0\u{8}\0\u{1f}\0\0\0\u{3}\0\0\0\0\0\0\0\0\0+\0\0\0\0\0\0\0:\0\0\0\0\u{1f}'aaaa'aaa\u{f}\0\0\0\0\0\u{5}\0\0q\0\u{1}'\u{1a}\u{1a}\u{19}0\0\0\0\0\u{5}\0\0(\0\0\0\u{3}\0\0\0 ;\0\0\0\0\0[\u{1f}\0\0\0\u{2}\0\0'''''''=@============)\0\0\0\0\0\0\0\0\0\0\0\0\0a'aaa\u{f}\0\0\0\0\0\u{5}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0%\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0============'''aq\u{18}qqqqqyqaaaa'aaaqqqqqqqqyq,,,\0\0\0\n\0\0\u{1}\u{4}\0\0\0\0\0\0\0\0\0\0\u{19}\u{1a}A\0\0\0\0\u{5}\0\0(\0\0\0\u{3}\0\0\0 \0\0\0\0\0\0\0\0\0\0\0\0@\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0#\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0(\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0l\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{1}\0\0'y\u{1f}\u{2}\0\0\0\0'1'1'''\0\0\0\0\00\u{1}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0 \0\0\0\0\0\0\0\0\0 \0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{1}\0\0\0\0\0\0\u{1}\0\0\0\0\0\0\0\0\0\0\0\0\0\0(\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{7}\0.\u{6}\0\0\0\0\0\0\u{1f}\0\0\0\0\0@\0\0\0\u{4}\0\0\t\0\0\0\0\u{3}\0\u{2}=\0\0\0\0\0\u{1}\0\04855\0\0\0\0\0\0\0\0\0\0\0\u{5}\0\0(\0\n\u{4}\0\0\0\0\0\0.yyyyyyyy\0(\0\0\0\0\u{10}\0\0\0\0".to_string();

        let config = DeflateConfig {
            level: 0,
            method: Method::Deflated,
            window_bits: 25,
            mem_level: 3,
            strategy: Strategy::Default,
        };

        let mut stream = z_stream::default();
        let err = unsafe {
            deflateInit2_(
                &mut stream,
                config.level,
                config.method as i32,
                config.window_bits,
                config.mem_level,
                config.strategy as i32,
                zlibVersion(),
                size_of::<z_stream>() as c_int,
            )
        };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        let buf_size = unsafe { deflateBound(&mut stream, source.len() as u64) };

        let mut dest = vec![0; buf_size as usize];
        let chunk = 47u32;
        let flush = DeflateFlush::PartialFlush;

        stream.next_in = source.as_mut_ptr().cast();
        stream.next_out = dest.as_mut_ptr().cast();

        // Break input into chunks.
        let mut left: u32 = source.len().try_into().unwrap();
        stream.avail_out = dest.len().try_into().unwrap();
        while left > 0 {
            let avail = Ord::min(chunk, left).try_into().unwrap();
            stream.avail_in = avail;
            let err = unsafe { deflate(&mut stream, flush as i32) };
            match ReturnCode::from(err) {
                ReturnCode::Ok => {
                    left -= avail;
                }
                ReturnCode::BufError => {
                    let add_space = Ord::min(chunk, buf_size as u32);
                    dest.extend(core::iter::repeat_n(0, add_space.try_into().unwrap()));

                    // If extend() reallocates, it may have moved in memory.
                    stream.next_out = dest.as_mut_ptr();
                    stream.avail_out += add_space;

                    left -= avail - stream.avail_in;
                }
                err => panic!("fatal {:?}", err),
            }
        }

        assert_eq!(left, 0);

        // Finish the stream.
        let err = unsafe { deflate(&mut stream, DeflateFlush::Finish as _) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
        match ReturnCode::from(err) {
            ReturnCode::Ok | ReturnCode::BufError => {
                // We might have run out of input, but still need more space to write the header.
                loop {
                    let add_space = Ord::min(chunk, buf_size as u32);
                    dest.extend(core::iter::repeat_n(0, add_space.try_into().unwrap()));

                    // If extend() reallocates, it may have moved in memory.
                    stream.next_out = dest.as_mut_ptr();
                    stream.avail_out += add_space;

                    let err = unsafe { deflate(&mut stream, DeflateFlush::Finish as _) };
                    match ReturnCode::from(err) {
                        ReturnCode::Ok => continue,
                        ReturnCode::BufError => continue,
                        ReturnCode::StreamEnd => break,
                        _ => unreachable!(),
                    }
                }
            }
            ReturnCode::StreamEnd => { /* do nothing, we're done */ }
            err => panic!("fatal {:?}", err),
        }

        dest.truncate(stream.total_out as usize);

        let err = unsafe { deflateEnd(&mut stream) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
    }

    #[test]
    fn inahga_3() {
        let mut source = "`0q\0\u{19}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0G\0\0\0\0\0\0\u{7}\0\0\0@\0\0\0&\0\0\0\0\0\0\0\0\0\0\0VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\u{8}\0\0\0\0\0\u{1}\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0@\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0y\u{1f}\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_string();

        let config = DeflateConfig {
            level: 0,
            method: Method::Deflated,
            window_bits: 31,
            mem_level: 3,
            strategy: Strategy::Default,
        };

        let mut stream = z_stream::default();
        let err = unsafe {
            deflateInit2_(
                &mut stream,
                config.level,
                config.method as i32,
                config.window_bits,
                config.mem_level,
                config.strategy as i32,
                zlibVersion(),
                size_of::<z_stream>() as c_int,
            )
        };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        let buf_size = unsafe { deflateBound(&mut stream, source.len() as u64) };

        let mut dest = vec![0; buf_size as usize];
        let chunk = 2u32;
        let flush = DeflateFlush::NoFlush;

        stream.next_in = source.as_mut_ptr().cast();
        stream.avail_in = chunk; // First chunk.
        stream.next_out = dest.as_mut_ptr().cast();
        stream.avail_out = dest.len().try_into().unwrap();

        // Deflate first chunk.
        let err = unsafe { deflate(&mut stream, flush as i32) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        // Change the parameters.
        let new_level = 4;
        let err = unsafe { deflateParams(&mut stream, new_level, config.strategy as _) };
        match ReturnCode::from(err) {
            ReturnCode::Ok => {}
            ReturnCode::BufError => {
                // Flushing the current pending data may run us out of buffer space.
                // Worst case double the buffer size.
                let add_space = Ord::min(chunk, buf_size as u32);
                dest.extend(core::iter::repeat_n(0, add_space.try_into().unwrap()));

                // If extend() reallocates, it may have moved in memory.
                stream.next_out = dest.as_mut_ptr();
                stream.avail_out += add_space;

                let err = unsafe { deflateParams(&mut stream, new_level, config.strategy as _) };
                assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
            }
            err => panic!("fatal {:?}", err),
        }

        // Deflate the rest in chunks.
        let mut left: u32 = source.len() as u32 - chunk;
        while left > 0 {
            // Write the chunk.
            let avail = Ord::min(chunk, left).try_into().unwrap();
            stream.avail_in = avail;
            let err = unsafe { deflate(&mut stream, flush as i32) };
            match ReturnCode::from(err) {
                ReturnCode::Ok => {
                    left -= avail;
                }
                ReturnCode::BufError => {
                    // Worst case double the buffer size.
                    let add_space = Ord::min(chunk, buf_size as u32);
                    dest.extend(core::iter::repeat_n(0, add_space.try_into().unwrap()));

                    // If extend() reallocates, it may have moved in memory.
                    stream.next_out = dest.as_mut_ptr();
                    stream.avail_out += add_space;

                    left -= avail - stream.avail_in;
                }
                err => panic!("fatal {:?}", err),
            }
        }

        assert_eq!(left, 0);

        let _ = unsafe { deflateEnd(&mut stream) };
    }

    #[test]
    fn inahga_4() {
        let mut source = [
            161, 161, 161, 161, 179, 179, 179, 179, 179, 179, 133, 133, 133, 133, 13, 13, 13, 13,
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 95, 95, 95, 255, 179, 179, 179, 179, 179, 179,
            179, 179, 179, 43, 179, 8, 179, 133, 133, 133, 133, 13, 13, 122, 13, 13, 13, 13, 13,
            13, 13, 13, 13, 3, 13, 13, 95, 95, 95, 13, 13, 255, 255, 255, 189, 189, 189, 189, 189,
            189, 189, 0, 189, 189, 189, 189, 189, 189, 189, 189, 189, 173, 189, 189, 189, 189, 189,
            189, 189, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 95, 95, 95, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 95, 95, 95, 95, 255, 255, 189, 189, 189, 189, 189, 173, 189, 189, 189,
            189, 189, 189, 189, 255, 255, 245, 255, 255, 255, 255, 255, 189, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 189, 189, 189, 189, 189, 189,
            189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 255, 255, 255, 255, 189, 13, 13, 13,
            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
            125, 125, 125, 125, 125, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
            39, 39, 39, 39, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125,
            125, 125, 125, 125, 125, 125, 255, 18, 125, 125, 125, 69, 125, 125, 125, 125, 255, 255,
            255, 255, 125, 125, 125, 125, 125, 63, 125, 125, 125, 125, 125, 125, 125, 125, 125,
            223, 223, 223, 223, 223, 223, 223, 223, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
            39, 39, 39, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 255, 255, 255, 255, 255, 255, 13, 13, 13,
            13, 13, 13, 13, 95, 95, 95, 255, 179, 179, 179, 179, 179, 179, 179, 179, 179, 43, 179,
            8, 179, 133, 133, 133, 133, 13, 13, 122, 13, 13, 13, 13, 13, 13, 13, 13, 13, 3, 13, 13,
            95, 95, 95, 13, 13, 255, 255, 255, 189, 189, 189, 189, 189, 189, 189, 0, 189, 189, 189,
            189, 189, 189, 189, 189, 189, 173, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
            189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 255, 255, 255, 255,
            189, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
            13, 13, 13, 13, 13, 125, 125, 125, 125, 125, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
            39, 39, 39, 39, 39, 39, 39, 39, 39, 125, 125, 125, 125, 125, 125, 125, 125, 125, 125,
            125, 125, 125, 125, 125, 125, 125, 125, 125, 125, 255, 18, 125, 125, 125, 69, 125, 125,
            125, 125, 255, 255, 255, 255, 125, 125, 125, 125, 125, 63, 125, 125, 125, 125, 125,
            125, 125, 125, 125, 223, 223, 223, 223, 223, 223, 223, 223, 39, 39, 39, 39, 39, 39, 39,
            39, 39, 39, 39, 39, 39, 39, 39, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 255, 255, 255, 255,
            255, 255, 189, 189, 189, 189, 189, 189, 183, 183, 183, 183, 183, 189, 189, 189, 189,
            189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189, 189,
            189, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 189, 189, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 189,
            189, 189, 189, 189, 66, 189, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 158, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 95, 95, 95, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 95, 95, 95, 95, 255, 255, 189, 189, 189, 189, 189, 173, 189, 189, 189,
            189, 189, 189, 189, 255, 255, 245, 255, 255, 255, 255, 255, 189, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 189, 189,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 5, 5, 5, 5,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 39,
            39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39, 39,
            39, 39, 39, 39, 39, 39, 255, 255, 255, 189, 189, 189, 189, 189, 255, 255, 255, 255,
            255, 248, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141,
            141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 141, 255, 255,
            255, 81, 126, 81, 81, 81, 81, 81, 81, 81, 85, 5, 5, 5, 5, 5, 5, 5, 5, 49, 5, 5, 5, 5,
            5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 189, 189, 189, 189, 189, 189, 189, 255, 255, 189, 189,
            189, 189, 189, 189, 19, 189, 189, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 95, 95, 95, 255, 255, 255, 255, 255, 255, 255, 255, 255, 95, 95, 95, 95,
            255, 255, 189, 189, 189, 189, 189, 173, 189, 189, 189, 189, 189, 189, 189, 255, 255,
            245, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 189, 189, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 189, 171, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 199, 199, 199, 199,
            199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199,
            199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199, 199,
            199, 199, 199, 199, 199, 199, 199, 199, 199, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 191, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 7, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 189, 189, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 81, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 36, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 40, 255, 255,
            255, 255, 255, 255, 81, 81, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 255, 255,
        ]
        .to_vec();

        let config = DeflateConfig {
            level: 0,
            method: Method::Deflated,
            window_bits: 8,
            mem_level: 3,
            strategy: Strategy::HuffmanOnly,
        };

        let mut stream = z_stream::default();
        let err = unsafe {
            deflateInit2_(
                &mut stream,
                config.level,
                config.method as i32,
                config.window_bits,
                config.mem_level,
                config.strategy as i32,
                zlibVersion(),
                size_of::<z_stream>() as c_int,
            )
        };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        let buf_size = unsafe { deflateBound(&mut stream, source.len() as u64) };

        let mut dest = vec![0; buf_size as usize];
        let chunk = 305u32;
        let flush = DeflateFlush::NoFlush;

        stream.next_in = source.as_mut_ptr().cast();
        stream.avail_in = chunk; // First chunk.
        stream.next_out = dest.as_mut_ptr().cast();
        stream.avail_out = dest.len().try_into().unwrap();

        // Deflate first chunk.
        let err = unsafe { deflate(&mut stream, flush as i32) };
        assert_eq!(ReturnCode::from(err), ReturnCode::Ok);

        // Change the parameters.
        let new_level = 0;
        let new_strategy = Strategy::Default;
        let err = unsafe { deflateParams(&mut stream, new_level, new_strategy as _) };
        match ReturnCode::from(err) {
            ReturnCode::Ok => {}
            ReturnCode::BufError => {
                // Flushing the current pending data may run us out of buffer space.
                // Worst case double the buffer size.
                let add_space = Ord::min(chunk, buf_size as u32);
                dest.extend(core::iter::repeat_n(0, add_space.try_into().unwrap()));

                // If extend() reallocates, it may have moved in memory.
                stream.next_out = dest.as_mut_ptr();
                stream.avail_out += add_space;

                let err = unsafe { deflateParams(&mut stream, new_level, new_strategy as _) };
                assert_eq!(ReturnCode::from(err), ReturnCode::Ok);
            }
            err => panic!("fatal {:?}", err),
        }

        // Deflate the rest in chunks.
        let mut left: u32 = source.len() as u32 - chunk;
        while left > 0 {
            // Write the chunk.
            let avail = Ord::min(chunk, left).try_into().unwrap();
            stream.avail_in = avail;
            let err = unsafe { deflate(&mut stream, flush as i32) };
            match ReturnCode::from(err) {
                ReturnCode::Ok => {
                    left -= avail;
                }
                ReturnCode::BufError => {
                    // Worst case double the buffer size.
                    let add_space = Ord::min(chunk, buf_size as u32);
                    dest.extend(core::iter::repeat_n(0, add_space.try_into().unwrap()));

                    // If extend() reallocates, it may have moved in memory.
                    stream.next_out = dest.as_mut_ptr();
                    stream.avail_out += add_space;

                    left -= avail - stream.avail_in;
                }
                err => panic!("fatal {:?}", err),
            }
        }

        assert_eq!(left, 0);

        let _ = unsafe { deflateEnd(&mut stream) };
    }
}
