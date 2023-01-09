mod setup;

use api::grpc::blockjoy_ui::Invitation as GrpcInvitation;
use api::models::Invitation;

#[tokio::test]
async fn cannot_create_invitation_without_valid_props() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let grpc_invitation = GrpcInvitation {
        id: None,
        created_by_id: None,
        created_for_org_id: None,
        invitee_email: None,
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: None,
        created_for_org_name: None,
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
        id: None,
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: Some("hugo".to_string()),
        created_for_org_name: Some("boss".to_string()),
    };
    let invitation = Invitation::create(&grpc_invitation, &tester.pool).await?;

    assert!(!invitation.id().to_string().is_empty());

    Ok(())
}

#[tokio::test]
async fn can_list_pending_invitations() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org().await;
    let grpc_invitation = GrpcInvitation {
        id: None,
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: Some("hugo".to_string()),
        created_for_org_name: Some("boss".to_string()),
    };
    Invitation::create(&grpc_invitation, &tester.pool).await?;
    let invitations = Invitation::pending(org.id, &tester.pool).await?;

    assert_eq!(invitations.len(), 1);

    Ok(())
}

#[tokio::test]
async fn can_list_received_invitations() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org().await;
    let grpc_invitation = GrpcInvitation {
        id: None,
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: Some("hugo".to_string()),
        created_for_org_name: Some("boss".to_string()),
    };
    Invitation::create(&grpc_invitation, &tester.pool).await?;

    let invitations = Invitation::received("hugo@boss.com".to_string(), &tester.pool).await?;

    assert_eq!(invitations.len(), 1);

    Ok(())
}

#[tokio::test]
async fn can_accept_invitation() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org().await;
    let grpc_invitation = GrpcInvitation {
        id: None,
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: Some("hugo".to_string()),
        created_for_org_name: Some("boss".to_string()),
    };
    let invitation = Invitation::create(&grpc_invitation, &tester.pool).await?;
    let invitation = Invitation::accept(invitation.id().to_owned(), &tester.pool).await?;

    assert!(invitation.accepted_at().is_some());

    Ok(())
}

#[tokio::test]
async fn can_decline_invitation() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org().await;
    let grpc_invitation = GrpcInvitation {
        id: None,
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: Some("hugo".to_string()),
        created_for_org_name: Some("boss".to_string()),
    };
    let invitation = Invitation::create(&grpc_invitation, &tester.pool).await?;
    let invitation = Invitation::decline(invitation.id().to_owned(), &tester.pool).await?;

    assert!(invitation.declined_at().is_some());

    Ok(())
}

#[tokio::test]
async fn can_revoke_invitation() -> anyhow::Result<()> {
    let tester = setup::Tester::new().await;
    let user = tester.admin_user().await;
    let org = tester.org().await;
    let grpc_invitation = GrpcInvitation {
        id: None,
        created_by_id: Some(user.id.to_string()),
        created_for_org_id: Some(org.id.to_string()),
        invitee_email: Some("hugo@boss.com".to_string()),
        created_at: None,
        accepted_at: None,
        declined_at: None,
        created_by_user_name: Some("hugo".to_string()),
        created_for_org_name: Some("boss".to_string()),
    };
    let invitation = Invitation::create(&grpc_invitation, &tester.pool).await?;
    let invitation_id = invitation.id().to_owned();

    Invitation::revoke(invitation_id, &tester.pool).await?;

    let cnt: i32 = sqlx::query_scalar("select count(*)::int from invitations where id = $1")
        .bind(invitation_id)
        .fetch_one(&tester.pool)
        .await?;

    assert_eq!(cnt, 0);

    Ok(())
}
