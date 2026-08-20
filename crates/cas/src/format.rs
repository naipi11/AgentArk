use crate::CasError;

pub const MAGIC: &[u8; 8] = b"AARKCAS1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum ObjectType {
    AgentRawRecord = 1,
}

impl ObjectType {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(value: u8) -> Result<Self, CasError> {
        match value {
            1 => Ok(Self::AgentRawRecord),
            _ => Err(CasError::UnsupportedObjectType),
        }
    }
}
