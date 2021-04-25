table! {
    hosts (id) {
        id -> Uuid,
        name -> Text,
    }
}

table! {
    rewards (id) {
        id -> Uuid,
        block -> Int8,
        transaction_hash -> Nullable<Text>,
        time -> Int8,
        validator_id -> Uuid,
        account -> Text,
        amount -> Int8,
    }
}

table! {
    users (id) {
        id -> Uuid,
        email -> Text,
        hashword -> Text,
        salt -> Text,
    }
}

table! {
    validators (id) {
        id -> Uuid,
        host_id -> Uuid,
        user_id -> Nullable<Uuid>,
        address -> Text,
        swarm -> Text,
        is_staked -> Nullable<Bool>,
        is_consensus -> Nullable<Bool>,
        is_enabled -> Nullable<Bool>,
        status -> Nullable<Text>,
    }
}

joinable!(validators -> hosts (host_id));
joinable!(validators -> users (user_id));

allow_tables_to_appear_in_same_query!(
    hosts,
    rewards,
    users,
    validators,
);
