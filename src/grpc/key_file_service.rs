use crate::auth::FindableById;
use crate::errors::ApiError;
use crate::grpc::blockjoy::key_files_server::KeyFiles;
use crate::grpc::blockjoy::{
    KeyFilesGetRequest, KeyFilesGetResponse, KeyFilesSaveRequest, KeyFilesSaveResponse,
};
use crate::models;
use diesel_async::scoped_futures::ScopedFutureExt;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct KeyFileServiceImpl {
    db: models::DbPool,
}

impl KeyFileServiceImpl {
    pub fn new(db: models::DbPool) -> Self {
        Self { db }
    }

    fn uuid_from_string(val: String) -> Result<Uuid, Status> {
        Uuid::parse_str(val.as_str())
            .map_err(|e| Status::invalid_argument(format!("Cannot parse node ID: {e}")))
    }
}

#[tonic::async_trait]
impl KeyFiles for KeyFileServiceImpl {
    async fn get(
        &self,
        request: Request<KeyFilesGetRequest>,
    ) -> Result<Response<KeyFilesGetResponse>, Status> {
        let inner = request.into_inner();
        let node_id = Self::uuid_from_string(inner.node_id)?;
        let request_id = inner.request_id.clone();
        let mut conn = self.db.conn().await?;
        let key_files = models::NodeKeyFile::find_by_node(node_id, &mut conn).await?;

        // Ensure we return "Not found" if no key files could be found
        if key_files.is_empty() {
            tracing::debug!("No key files found");
        }

        let response = KeyFilesGetResponse {
            origin_request_id: request_id,
            key_files: key_files
                .into_iter()
                .map(|f| f.try_into())
                .collect::<Result<_, ApiError>>()?,
        };

        Ok(Response::new(response))
    }

    async fn save(
        &self,
        request: Request<KeyFilesSaveRequest>,
    ) -> Result<Response<KeyFilesSaveResponse>, Status> {
        let inner = request.into_inner();
        let node_id = KeyFileServiceImpl::uuid_from_string(inner.node_id)?;
        let request_id = inner.request_id.clone();

        self.db
            .trx(|c| {
                async move {
                    // Explicitly check, if node exists
                    models::Node::find_by_id(node_id, c).await?;

                    for file in inner.key_files {
                        let new_node_key_file = models::NewNodeKeyFile {
                            name: &file.name,
                            content: std::str::from_utf8(&file.content).map_err(|e| {
                                Status::invalid_argument(format!(
                                    "Couldn't read key file contents: {e}"
                                ))
                            })?,
                            node_id,
                        };

                        new_node_key_file.create(c).await?;
                    }
                    Ok(())
                }
                .scope_boxed()
            })
            .await?;

        let response = KeyFilesSaveResponse {
            origin_request_id: request_id,
            messages: vec![],
        };

        Ok(Response::new(response))
    }
}
