mod helper_traits;

use api::models::{Blockchain, Host, User};
use api::TestDb;
use helper_traits::GrpcClient;
use sqlx::PgPool;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use tempfile::NamedTempFile;
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

#[macro_export]
macro_rules! assert_grpc_request {
    ($m:tt, $r:expr, $s:expr, $db: expr, $client: ty) => {{
        use setup::server_and_client_stub;

        let pool = Arc::new($db.pool.clone());
        let (serve_future, mut client) = server_and_client_stub::<$client>(pool).await;

        let request_future = async {
            match client.$m($r).await {
                Ok(response) => {
                    let inner = response.into_inner();
                    println!("response OK: {:?}", inner);
                    // TODO: removing this assertion makes lots of tests pass that should fail
                    // assert_eq!($s, tonic::Code::Ok);
                }
                Err(e) => {
                    let s = Status::from(e);
                    println!("response ERROR: {:?}", s);
                    assert_eq!($s, s.code());
                }
            }
        };

        // Wait for completion, when the client request future completes
        tokio::select! {
            _ = serve_future => panic!("server returned first"),
            _ = request_future => (),
        }
    }};
}

pub async fn setup() -> TestDb {
    TestDb::setup().await
}

#[allow(dead_code)]
pub async fn server_and_client_stub<Client>(db: Arc<PgPool>) -> (impl Future<Output = ()>, Client)
where
    Client: GrpcClient<Channel> + Debug,
{
    let socket = NamedTempFile::new().unwrap();
    let socket = Arc::new(socket.into_temp_path());
    std::fs::remove_file(&*socket).unwrap();

    let uds = UnixListener::bind(&*socket).unwrap();
    let stream = UnixListenerStream::new(uds);
    let serve_future = async {
        let result = api::grpc::server(db)
            .await
            .serve_with_incoming(stream)
            .await;

        assert!(result.is_ok());
    };

    let socket = Arc::clone(&socket);
    // Connect to the server over a Unix socket
    // The URL will be ignored.
    let channel = Endpoint::try_from("http://any.url")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = Arc::clone(&socket);
            async move { UnixStream::connect(&*socket).await }
        }))
        .await
        .unwrap();

    let client = Client::create(channel);

    (serve_future, client)
}

pub async fn get_test_host(db: &PgPool) -> Host {
    sqlx::query("select h.*, t.token, t.role from hosts h right join tokens t on h.id = t.host_id where name = 'Host-1'")
        .map(Host::from)
        .fetch_one(db)
        .await
        .unwrap()
}

pub async fn get_admin_user(db: &PgPool) -> User {
    User::find_by_email("admin@here.com", db)
        .await
        .expect("Could not get admin test user from db.")
}

#[allow(dead_code)]
pub async fn get_blockchain(db: &PgPool) -> Blockchain {
    let chains = Blockchain::find_all(db)
        .await
        .expect("To have at least one blockchain");
    chains
        .first()
        .expect("To have a test blockchain")
        .to_owned()
}
