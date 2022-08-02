use api::is_owned_by;
use api::new_auth::*;

struct Resource;
struct Owner;
struct NoOwner;
struct Repo;

#[tonic::async_trait]
impl Owned<Owner, ()> for Resource {
    async fn is_owned_by(&self, _resource: Owner, _db: ()) -> OwnershipState {
        OwnershipState::Owned
    }
}

#[tonic::async_trait]
impl Owned<Owner, Repo> for Resource {
    async fn is_owned_by(&self, _resource: Owner, _db: Repo) -> OwnershipState {
        OwnershipState::Owned
    }
}

#[tonic::async_trait]
impl Owned<NoOwner, ()> for Resource {
    async fn is_owned_by(&self, _resource: NoOwner, _db: ()) -> OwnershipState {
        OwnershipState::NotOwned
    }
}

#[tonic::async_trait]
impl Owned<NoOwner, Repo> for Resource {
    async fn is_owned_by(&self, _resource: NoOwner, _db: Repo) -> OwnershipState {
        OwnershipState::NotOwned
    }
}

#[tokio::test]
async fn is_owned_by_macro_works_without_repo() {
    let resource = Resource;
    let owner = Owner;

    assert!(is_owned_by! { resource => owner });
}

#[tokio::test]
async fn is_not_owned_by_macro_works_without_repo() {
    let resource = Resource;
    let no_owner = NoOwner;

    assert!(!is_owned_by! { resource => no_owner });
}

#[tokio::test]
async fn is_owned_by_macro_works_with_repo() {
    let resource = Resource;
    let owner = Owner;
    let repo = Repo;

    assert!(is_owned_by! { resource => owner, using repo });
}

#[tokio::test]
async fn is_not_owned_by_macro_works_with_repo() {
    let resource = Resource;
    let no_owner = NoOwner;
    let repo = Repo;

    assert!(!is_owned_by! { resource => no_owner, using repo });
}
