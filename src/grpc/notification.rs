use std::env;
use tokio::sync::broadcast::{self, Receiver, Sender};
use uuid::Uuid;

#[derive(Debug)]
pub struct ChannelNotifier {
    commands: (Sender<ChannelNotification>, Receiver<ChannelNotification>),
    nodes: (Sender<ChannelNotification>, Receiver<ChannelNotification>),
    hosts: (Sender<ChannelNotification>, Receiver<ChannelNotification>),
    organizations: (Sender<ChannelNotification>, Receiver<ChannelNotification>),
}

impl ChannelNotifier {
    pub fn create() -> Self {
        Self {
            commands: get_channel_pair(),
            nodes: get_channel_pair(),
            hosts: get_channel_pair(),
            organizations: get_channel_pair(),
        }
    }

    pub fn commands_sender(&self) -> Sender<ChannelNotification> {
        self.commands.0.clone()
    }

    pub fn commands_receiver(&self) -> Receiver<ChannelNotification> {
        self.commands.0.subscribe()
    }

    pub fn nodes_sender(&self) -> Sender<ChannelNotification> {
        self.nodes.0.clone()
    }

    pub fn nodes_receiver(&self) -> Receiver<ChannelNotification> {
        self.commands.0.subscribe()
    }

    pub fn hosts_sender(&self) -> Sender<ChannelNotification> {
        self.hosts.0.clone()
    }

    pub fn hosts_receiver(&self) -> Receiver<ChannelNotification> {
        self.commands.0.subscribe()
    }

    pub fn organizations_sender(&self) -> Sender<ChannelNotification> {
        self.organizations.0.clone()
    }

    pub fn organizations_receiver(&self) -> Receiver<ChannelNotification> {
        self.commands.0.subscribe()
    }
}

#[derive(Debug, Default, Clone)]
pub enum ChannelNotification {
    #[default]
    Empty,
    Node(NotificationPayload),
    Host(NotificationPayload),
    Command(NotificationPayload),
}

#[derive(Debug, Clone)]
pub struct NotificationPayload {
    id: Uuid,
}

impl NotificationPayload {
    pub fn new(id: Uuid) -> Self {
        Self { id }
    }

    pub fn get_id(&self) -> Uuid {
        self.id
    }
}

/// Create sender/receiver interprocess comm pair
pub fn get_channel_pair() -> (Sender<ChannelNotification>, Receiver<ChannelNotification>) {
    broadcast::channel::<ChannelNotification>(get_bidi_channel_size())
}

fn get_bidi_channel_size() -> usize {
    env::var("INTERNAL_BUFFER_SIZE")
        .map(|bs| bs.parse::<usize>())
        .unwrap()
        .unwrap_or(128)
}
