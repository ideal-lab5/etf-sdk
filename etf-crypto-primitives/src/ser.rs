// https://github.com/arkworks-rs/algebra/issues/178
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use alloc::vec::Vec;

pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> 
      Result<S::Ok, S::Error> 
where S: serde::Serializer {
      let mut bytes = vec![];
      a.serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(serde::ser::Error::custom)?;
      s.serialize_bytes(&bytes)
}

pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> 
      Result<A, D::Error> 
where D: serde::de::Deserializer<'de> {
      let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
      let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
      a.map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_json::Deserializer;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use alloc::vec::Vec;

      #[derive(
            Debug, PartialEq, Serialize, Deserialize, 
            CanonicalSerialize, CanonicalDeserialize
      )]
      struct TestStruct {
            field1: u32,
      }

    #[test]
      fn test_serialization() {
            // Create an instance of TestStruct for testing
            let test_struct = TestStruct {
                  field1: 42,
            };
            // Serialize the struct using `ark_se`
            let mut ark_se_result = ark_se(&test_struct,  &mut serde_json::Serializer::new(Vec::new()));

            // Check if serialization was successful
            assert!(ark_se_result.is_ok());
    }
}
