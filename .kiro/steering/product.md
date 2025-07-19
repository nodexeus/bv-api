# Product Overview

Blockvisor API is a distributed infrastructure management system that orchestrates software deployment and monitoring across physical and virtual machines. Originally designed for blockchain node management, it has evolved into a general-purpose platform for running and managing any software.

## Core Concepts

- **Hosts**: Physical or virtual machines registered with the system via the `bvup` tool
- **Nodes**: Running software instances with real-time state and metrics monitoring
- **Organizations**: Groups of users sharing resources and permissions
- **Users**: Individual accounts with role-based access control (RBAC)
- **Commands**: Instructions sent to hosts for software lifecycle management

## Key Features

- Multi-tenant architecture with organization-based resource isolation
- Real-time monitoring and metrics collection
- Automated software deployment, upgrades, and lifecycle management
- DNS management integration with Cloudflare
- S3-compatible storage for archives and bundles
- MQTT-based communication for real-time updates
- Stripe integration for billing and subscription management