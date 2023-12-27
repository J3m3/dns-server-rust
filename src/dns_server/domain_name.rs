pub type DomainName = String;
pub trait LabelEncodable {
    fn to_encoded_label(&self) -> Vec<u8>;
}

impl LabelEncodable for DomainName {
    fn to_encoded_label(&self) -> Vec<u8> {
        format!("{}.", self)
            .split('.')
            .fold(Vec::<u8>::new(), |mut acc, byte_str| {
                let len_byte = (byte_str.len() as u8).to_be_bytes().into_iter();
                let content_bytes = byte_str.bytes();
                acc.extend(len_byte.chain(content_bytes));
                acc
            })
    }
}
