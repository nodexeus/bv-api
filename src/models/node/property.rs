use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::auth::resource::NodeId;
use crate::models::{self, schema::node_properties};

#[derive(Debug, Clone, Insertable, Queryable)]
#[diesel(table_name = node_properties)]
pub struct NodeProperty {
    pub id: uuid::Uuid,
    pub node_id: NodeId,
    pub blockchain_property_id: uuid::Uuid,
    pub value: String,
}

impl NodeProperty {
    pub async fn bulk_create(
        props: Vec<Self>,
        conn: &mut models::Conn,
    ) -> crate::Result<Vec<Self>> {
        let props = diesel::insert_into(node_properties::table)
            .values(props)
            .get_results(conn)
            .await?;
        Ok(props)
    }

    pub async fn by_node(node: &super::Node, conn: &mut models::Conn) -> crate::Result<Vec<Self>> {
        let props = node_properties::table
            .filter(node_properties::node_id.eq(node.id))
            .get_results(conn)
            .await?;
        Ok(props)
    }

    pub async fn by_nodes(
        nodes: &[super::Node],
        conn: &mut models::Conn,
    ) -> crate::Result<Vec<Self>> {
        let ids: Vec<_> = nodes.iter().map(|n| n.id).collect();
        let props = node_properties::table
            .filter(node_properties::node_id.eq_any(ids))
            .get_results(conn)
            .await?;
        Ok(props)
    }
}
