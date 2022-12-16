/**
 * Helper lib providing types for node-types and their actually values stored in nodes
 *
 */

/**
 * All possible node-type IDs (taken from src/models/node_type.rs)
 */
export enum NodeTypeKey {
    Miner = 1,
    Etl = 2,
    Validator = 3,
    Api = 4,
    Oracle = 5,
    Relay = 6,
    Execution = 7,
    Beacon = 8,
    MevBoost = 9,
    Node = 10,
    FullNode = 11,
    LightNode = 12,
}

/**
 * All possible UI types provided for nodes
 */
export enum UiType {
    // Upload e.g. validator keys component
    KeyUpload = 'key-upload',
    // Upload arbitrary files component
    FileUpload = 'file-upload',
    // Enter arbitrary text
    Text = 'text',
    // Enter some password
    Password = "password",
    // Enter arbitrary numbers
    Number = 'number',
    // Enter a voting key pwd
    VotingKeyPwd = 'voting_key_pwd',
    // Enter a wallet address
    WalletAddress = 'wallet_address',
    // Render a switch
    Switch = 'switch',
    // Render a URL
    Url = 'url',
}

/**
 * A single node property template
 */
export type Property = {
    // Property name as used in the resulting node
    name: string,
    // Type of UI element to input value
    ui_type: UiType,
    // Optional default value
    default: any | null,
    // Indicates whether the field should be read-only
    disabled: boolean,
};

/**
 * A node-type template
 */
export type NodeType = {
    // The ID of the node-type matching the enum in the DB
    id: NodeTypeKey,
    // An optional array of node-type properties
    properties: Array<Property> | null,
};

/**
 * Collection of all supported node-types among a blockchain
 */
export type SupportedNodeTypes = Array<NodeType>;

/**
 * Node property value storing an actual field of one node property
 */
export type NodePropertyValue = {
    // The technical ID of the value field
    id: string,
    // The display name of the value field
    label: string,
    // Optional descriptive text (e.g. shown in a tooltip)
    description: string | null,
    // The actual value
    value: any | null,
    // The UI type for rendering
    ui_type: UiType,
    // Determines if value is read-only
    disabled: boolean,
};

/**
 * Collection of NodeProperty values to be created within the UI
 */
export type NodeProperties = {
    id: NodeTypeKey,
    values: Array<NodePropertyValue> | null,
};

/// Samples
const disabled_self_hosted: Property = {
    name: 'self-hosted',
    ui_type: UiType.Switch,
    default: false,
    disabled: true,
};

////////////////////////////////////////////////////
///             HNT sample                       ///
////////////////////////////////////////////////////

const hnt_miner: NodeType = {
    id: NodeTypeKey.Miner,
    properties: [
        {
            name: 'keystore-file',
            ui_type: UiType.KeyUpload,
            default: null,
            disabled: false,
        },
        disabled_self_hosted
    ],
};

const hnt_validator: NodeType = {
    id: NodeTypeKey.Validator,
    properties: [
        {
            name: 'keystore-file',
            ui_type: UiType.KeyUpload,
            default: null,
            disabled: false,
        },
        disabled_self_hosted
    ],
};

////////////////////////////////////////////////////
///             ETH sample                       ///
////////////////////////////////////////////////////

const eth_validator: NodeType = {
    id: NodeTypeKey.Validator,
    properties: [
        {
            name: 'keystore-file-1',
            ui_type: UiType.KeyUpload,
            default: null,
            disabled: false,
        },
        {
            name: 'keystore-file-2',
            ui_type: UiType.KeyUpload,
            default: null,
            disabled: false,
        },
        {
            name: 'keystore-file-3',
            ui_type: UiType.KeyUpload,
            default: null,
            disabled: false,
        },
        {
            name: 'voting-pwd',
            ui_type: UiType.VotingKeyPwd,
            default: null,
            disabled: false,
        },
        {
            name: 'fee-recipient',
            ui_type: UiType.WalletAddress,
            default: null,
            disabled: false,
        },
        {
            name: 'mev-boost',
            ui_type: UiType.Switch,
            default: null,
            disabled: false,
        },
        disabled_self_hosted,
    ],
};

const supported_nodes: SupportedNodeTypes = [hnt_miner, hnt_validator, eth_validator];
const path = './supported_node_types.json';
const json = JSON.stringify(supported_nodes);

Deno.writeTextFile(path, json).then(() => {
    console.log(`Created JSON file in ${path}`);
}).catch((e) => {
    console.error(`Failed writing JSON file in ${path}: ${e}`);
});
