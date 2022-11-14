use crate::errors::ApiError;
use crate::grpc::blockjoy::key_files_server::KeyFiles;
use crate::grpc::blockjoy::{KeyFilesGetRequest, KeyFilesGetResponse};
use crate::models::NodeKeyFile;
use crate::server::DbPool;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct KeyFileServiceImpl {
    db: DbPool,
}

impl KeyFileServiceImpl {
    pub fn new(db: DbPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl KeyFiles for KeyFileServiceImpl {
    async fn get(
        &self,
        request: Request<KeyFilesGetRequest>,
    ) -> Result<Response<KeyFilesGetResponse>, Status> {
        let inner = request.into_inner();
        let node_id = Uuid::parse_str(inner.node_id.as_str())
            .map_err(|e| Status::invalid_argument(format!("Cannot parse node ID: {e}")))?;
        let request_id = inner.request_id.clone();
        let key_files = NodeKeyFile::find_by_node(node_id, &self.db).await?;

        // Ensure we return "Not found" if no key files could be found
        if key_files.is_empty() {
            return Err(Status::not_found("No key files for given node ID"));
        }

        let response = KeyFilesGetResponse {
            origin_request_id: request_id,
            key_files: key_files
                .into_iter()
                .map(|f: NodeKeyFile| f.try_into())
                .collect::<Result<_, ApiError>>()?,
        };

        Ok(Response::new(response))
    }
}
