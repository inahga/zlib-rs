#![cfg_attr(not(miri), no_main)]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary},
    fuzz_target, Corpus,
};

use core::ffi::c_int;

use zlib_rs::ReturnCode;

#[derive(Debug, Arbitrary)]
struct Input(String, c_int);

fuzz_target!(|input: Input| -> Corpus { compress(input) });

fn compress(input: Input) -> Corpus {
    let Input(data, level) = input;

    // first, deflate the data using the standard zlib
    const LENGTH: usize = 8 * 1024;
    let mut deflated = vec![0; LENGTH];
    let mut length = LENGTH as u64;
    let error = unsafe {
        libz_rs_sys::compress2(
            deflated.as_mut_ptr().cast(),
            &mut length,
            data.as_ptr().cast(),
            data.len() as _,
            level,
        )
    };

    let error = ReturnCode::from(error as i32);
    if (-1..=9).contains(&level) {
        assert_eq!(ReturnCode::Ok, error);
    } else {
        assert_eq!(ReturnCode::StreamError, error);
        return Corpus::Reject;
    }

    deflated.truncate(length as usize);

    let mut output = vec![0u8; LENGTH];
    let config = zlib_rs::inflate::InflateConfig { window_bits: 15 };
    let (output, error) = zlib_rs::inflate::uncompress_slice(&mut output, &deflated, config);
    assert_eq!(ReturnCode::Ok, error);

    if output != data.as_bytes() {
        let path = std::env::temp_dir().join("deflate.txt");
        std::fs::write(&path, &data).unwrap();
        eprintln!("saved input file to {path:?}");
    }

    assert_eq!(output, data.as_bytes());
    Corpus::Keep
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, path::PathBuf};

    use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
    use rstest::rstest;

    use crate::{compress, Input};

    #[rstest]
    #[cfg(miri)]
    fn miri_corpus(#[files("corpus/compress/*")] path: PathBuf) {
        let mut input = File::open(path).unwrap();
        let mut buf = Vec::new();
        input.read_to_end(&mut buf).unwrap();

        let mut unstructured = Unstructured::new(&buf);
        let input = Input::arbitrary(&mut unstructured).unwrap();
        compress(input);
    }
}
