use crate::grpc::blockjoy_ui::{response_meta, Pagination, ResponseMeta, Uuid};
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

pub fn success_response_meta(request_id: Option<Uuid>) -> ResponseMeta {
    ResponseMeta {
        status: response_meta::Status::Success.into(),
        origin_request_id: request_id,
        messages: vec![],
        pagination: None,
    }
}

pub fn success_response_with_pagination(request_id: Option<Uuid>) -> ResponseMeta {
    let pagination = Pagination {
        total_items: 0,
        offset: 0,
        items_per_page: 0,
    };

    ResponseMeta {
        status: response_meta::Status::Success.into(),
        origin_request_id: request_id,
        messages: vec![],
        pagination: Some(pagination),
    }
}
