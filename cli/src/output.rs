use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsonEnvelope<T> {
    pub schema_version: u32,
    pub ok: bool,
    pub command: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<PublicError>,
    pub warnings: Vec<PublicWarning>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicError {
    pub code: &'static str,
    pub message: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicWarning {
    pub code: &'static str,
    pub message: &'static str,
}

pub fn success<T: Serialize>(command: &'static str, data: T) -> JsonEnvelope<T> {
    JsonEnvelope {
        schema_version: 1,
        ok: true,
        command,
        data: Some(data),
        error: None,
        warnings: Vec::new(),
    }
}

pub fn failure<T>(
    command: &'static str,
    code: &'static str,
    message: &'static str,
) -> JsonEnvelope<T> {
    JsonEnvelope {
        schema_version: 1,
        ok: false,
        command,
        data: None,
        error: Some(PublicError { code, message }),
        warnings: Vec::new(),
    }
}
