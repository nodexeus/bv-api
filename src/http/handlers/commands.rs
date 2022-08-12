use crate::errors::Result as ApiResult;
use crate::models::Command;
use crate::server::DbPool;
use axum::extract::{Extension, Json, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use uuid::Uuid;

pub async fn get_command(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let command = Command::find_by_id(id, db.as_ref()).await?;
    Ok((StatusCode::OK, Json(command)))
}

pub async fn delete_command(
    Extension(db): Extension<DbPool>,
    Path(id): Path<Uuid>,
) -> ApiResult<impl IntoResponse> {
    let result = Command::delete(id, &db).await?;
    Ok((
        StatusCode::OK,
        Json(format!("Successfully deleted {} record(s).", result)),
    ))
}
