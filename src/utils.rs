pub fn xor(lhs: &[u8], rhs: &[u8]) -> Vec<u8> {
    assert_eq!(lhs.len(), rhs.len());

    let mut result = vec![0; lhs.len()];
    for i in 0..lhs.len() {
        result[i] = lhs[i] ^ rhs[i];
    }
    result
}

#[cfg(test)]
mod test {
    use crate::encoding::hex_decode;

    use super::*;

    #[test]
    fn cryptopals_s1c2() {
        let lhs = hex_decode("1c0111001f010100061a024b53535009181c");
        let rhs = hex_decode("686974207468652062756c6c277320657965");
        let result = hex_decode("746865206b696420646f6e277420706c6179");

        assert_eq!(xor(&lhs, &rhs), result);
    }
}
