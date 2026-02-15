use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use unicode_normalization::UnicodeNormalization;

const PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b'?')
    .add(b'=')
    .add(b'\\');

pub fn normalize_nfc(input: &str) -> String {
    input.nfc().collect::<String>()
}

pub fn encode_path_segment(raw: &str) -> String {
    let nfc = normalize_nfc(raw);
    utf8_percent_encode(&nfc, PATH_ENCODE_SET).to_string()
}

pub fn decode_path_segment(encoded: &str) -> String {
    let decoded = percent_decode_str(encoded).decode_utf8_lossy();
    normalize_nfc(&decoded)
}

#[cfg(test)]
mod tests {
    use super::{decode_path_segment, encode_path_segment, normalize_nfc};

    #[test]
    fn keeps_cjk_and_symbols_reversible_for_transport() {
        let cases = [
            "中文 文档(最终版)-v1.0+.mp4",
            "日本語-テスト+空白 (A-B)*.txt",
            "한국어_샘플-파일 (v2)+*.jpg",
            "mix 空格 + - * () [] {} & # % ? = , ; ' \".mkv",
            "破折号–和—以及-普通横杠",
        ];

        for c in cases {
            let nfc = normalize_nfc(c);
            let enc = encode_path_segment(&nfc);
            assert!(!enc.is_empty());
            // '+' must not survive as ambiguous plus.
            assert!(!enc.contains('+'));
            assert_eq!(decode_path_segment(&enc), nfc);
        }
    }
}
