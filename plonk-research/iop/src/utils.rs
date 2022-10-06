#[macro_export]
macro_rules! to_bytes {
    ($x:expr) => {{
        let mut buf = vec![];
        ark_serialize::CanonicalSerialize::serialize($x, &mut buf).map(|_| buf)
    }};
}
