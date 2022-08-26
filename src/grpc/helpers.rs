use crate::grpc::blockjoy_ui::{ResponseMeta, Uuid};
use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn pb_current_timestamp() -> Timestamp {
    let start = SystemTime::now();
    let seconds = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;
    let nanos = (start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos()
        * 1000) as i32;

    Timestamp { seconds, nanos }
}

pub fn success_response_meta(status: i32, request_id: Option<Uuid>) -> ResponseMeta {
    ResponseMeta {
        status,
        origin_request_id: request_id,
        messages: vec![],
        pagination: None,
    }
}
