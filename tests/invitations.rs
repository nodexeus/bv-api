mod setup;

use api::grpc::blockjoy_ui::Invitation as GrpcInvitation;
use api::models::Invitation;

#[tokio::test]
async fn cannot_create_invitation_without_valid_props() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let grpc_invitation = GrpcInvitation {
        created_by_id: None,
        created_for_org_id: None,
        invitee_email: None,
        created_at: None,
        accepted_at: None,
        declined_at: None,
    };

    match Invitation::create(&grpc_invitation, &tester.pool).await {
        Ok(_) => panic!("This shouldn't work"),
        Err(_) => Ok(()),
    }
}

#[tokio::test]
async fn can_create_invitation_with_valid_props() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org().await;
    let grpc_invitation = GrpcInvitation {
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
    };
    let invitation = Invitation::create(&grpc_invitation, &tester.pool).await?;

    assert!(!invitation.id().to_string().is_empty());

    Ok(())
}
