# Casbin authorization macros

## Ownership


Macro to validate ownership of a given object.
Actually, the macro enables another one to be used inside the annotated function:
```rust
is_owned_by!(resource => owner, using db.clone());
```


# Example


```
#[ownership(subject = "user")]
async fn some_handler(
    Extension(user): Extension<User>,
    Extension(db): Extension<Arc<PgPool>>
) -> impl axum::response::IntoResponse
{
    let resource = Model::find_all().first();
    
    if is_owned_by!(resource => user, using db.clone()) {
        (HttpStatusCode::Ok, axum::Json("ownership validated"))
    }
}
```

## Privileges


Macro to validate current user's privileges to conduct action on object.
If _subject_ is omitted, _user_ will be assumed as default, where _user_ must be
an object inside the annotated function and implement ***casbin_authorization::auth::Authorizable***

### Example


```rust
#[validate_privileges(subject = "user", object = "users", action = "create")]
async fn some_handler() -> impl IntoResponse {
    (HttpStatusCode::Ok, Json("authorized"))
}
```

## Ownership and privileges


Shortcut macro for validating privileges and enabling _is_owned_by_ macro.


# Example


```
#[validate_owner_privileges(subject = "user", object = "users", action = "create")]
async fn some_handler() -> impl axum::response::IntoResponse {
    if is_owned_by!(resource => user, using db.clone()) {
        (HttpStatusCode::Ok, axum::Json("ownership and authorization validated"))
    }
}
```


## Improvements


### Loading configuration once at startup


Currently, each time #apply_authorization is called, the config is read from disk. That should be improved by providing
an Authorization instance to the server once, so that the config are only read once.