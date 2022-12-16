/**
 * All possible node-type IDs
 */
enum NodeTypeKey {
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
enum UiType {
    KeyUpload = 'key-upload',
    FileUpload = 'file-upload',
    Text = 'text',
    Password = "password",
    Number = 'number',
    VotingKeyPwd = 'voting_key_pwd',
    WalletAddress = 'wallet_address',
    Switch = 'switch',
    Url = 'url',
}

/**
 * A single node property template
 */
type Property = {
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
type NodeType = {
    // The ID of the node-type matching the enum in the DB
    id: NodeTypeKey,
    // An optional array of node-type properties
    properties: Array<Property> | null,
};

/**
 * Collection of all supported node-types among a blockchain
 */
type SupportedNodeTypes = Array<NodeType>;

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

let hnt_miner: NodeType = {
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

let hnt_validator: NodeType = {
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

let eth_validator: NodeType = {
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

let supported_nodes: SupportedNodeTypes = [hnt_miner, hnt_validator, eth_validator];
let path = './supported_node_types.json';
let json = JSON.stringify(supported_nodes);

Deno.writeTextFile(path, json).then(() => {
    console.log(`Created JSON file in ${path}`);
}).catch((e) => {
    console.error(`Failed wrting JSON file in ${path}: ${e}`);
});
