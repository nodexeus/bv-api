use actix_web::http::StatusCode;
use actix_web::HttpResponse;
use actix_web::ResponseError;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    ValidationError(String),

    #[error("Record not found.")]
    NotFoundError(sqlx::Error),

    #[error("Duplicate resource conflict.")]
    DuplicateResource,

    #[error("Invalid email or password")]
    InvalidAuthentication(anyhow::Error),

    #[error("Error processing JWT")]
    JWTError(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

impl std::fmt::Debug for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => Self::NotFoundError(e),
            sqlx::Error::Database(dbe) if dbe.to_string().contains("duplicate key value") => {
                Self::DuplicateResource
            }
            _ => Self::UnexpectedError(anyhow::Error::from(e)),
        }
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(e: argon2::password_hash::Error) -> Self {
        Self::InvalidAuthentication(anyhow::Error::msg(e.to_string()))
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::ValidationError(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFoundError(_) => StatusCode::NOT_FOUND,
            ApiError::DuplicateResource => StatusCode::CONFLICT,
            ApiError::InvalidAuthentication(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(self.to_string())
    }
}

pub fn error_chain_fmt(
    e: &impl std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}
