import * as jspb from 'google-protobuf'

import * as google_protobuf_timestamp_pb from 'google-protobuf/google/protobuf/timestamp_pb';
import * as google_protobuf_any_pb from 'google-protobuf/google/protobuf/any_pb';


export class Uuid extends jspb.Message {
  getValue(): string;
  setValue(value: string): Uuid;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Uuid.AsObject;
  static toObject(includeInstance: boolean, msg: Uuid): Uuid.AsObject;
  static serializeBinaryToWriter(message: Uuid, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Uuid;
  static deserializeBinaryFromReader(message: Uuid, reader: jspb.BinaryReader): Uuid;
}

export namespace Uuid {
  export type AsObject = {
    value: string,
  }
}

export class ApiToken extends jspb.Message {
  getValue(): string;
  setValue(value: string): ApiToken;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ApiToken.AsObject;
  static toObject(includeInstance: boolean, msg: ApiToken): ApiToken.AsObject;
  static serializeBinaryToWriter(message: ApiToken, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ApiToken;
  static deserializeBinaryFromReader(message: ApiToken, reader: jspb.BinaryReader): ApiToken;
}

export namespace ApiToken {
  export type AsObject = {
    value: string,
  }
}

export class Pagination extends jspb.Message {
  getTotalItems(): number;
  setTotalItems(value: number): Pagination;

  getOffset(): number;
  setOffset(value: number): Pagination;

  getItemsPerPage(): number;
  setItemsPerPage(value: number): Pagination;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Pagination.AsObject;
  static toObject(includeInstance: boolean, msg: Pagination): Pagination.AsObject;
  static serializeBinaryToWriter(message: Pagination, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Pagination;
  static deserializeBinaryFromReader(message: Pagination, reader: jspb.BinaryReader): Pagination;
}

export namespace Pagination {
  export type AsObject = {
    totalItems: number,
    offset: number,
    itemsPerPage: number,
  }
}

export class RequestMeta extends jspb.Message {
  getId(): Uuid | undefined;
  setId(value?: Uuid): RequestMeta;
  hasId(): boolean;
  clearId(): RequestMeta;

  getToken(): ApiToken | undefined;
  setToken(value?: ApiToken): RequestMeta;
  hasToken(): boolean;
  clearToken(): RequestMeta;

  getFieldsList(): Array<string>;
  setFieldsList(value: Array<string>): RequestMeta;
  clearFieldsList(): RequestMeta;
  addFields(value: string, index?: number): RequestMeta;

  getLimit(): number;
  setLimit(value: number): RequestMeta;
  hasLimit(): boolean;
  clearLimit(): RequestMeta;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RequestMeta.AsObject;
  static toObject(includeInstance: boolean, msg: RequestMeta): RequestMeta.AsObject;
  static serializeBinaryToWriter(message: RequestMeta, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RequestMeta;
  static deserializeBinaryFromReader(message: RequestMeta, reader: jspb.BinaryReader): RequestMeta;
}

export namespace RequestMeta {
  export type AsObject = {
    id?: Uuid.AsObject,
    token?: ApiToken.AsObject,
    fieldsList: Array<string>,
    limit?: number,
  }

  export enum TokenCase { 
    _TOKEN_NOT_SET = 0,
    TOKEN = 2,
  }

  export enum LimitCase { 
    _LIMIT_NOT_SET = 0,
    LIMIT = 4,
  }
}

export class ResponseMeta extends jspb.Message {
  getStatus(): ResponseMeta.Status;
  setStatus(value: ResponseMeta.Status): ResponseMeta;

  getOriginRequestId(): Uuid | undefined;
  setOriginRequestId(value?: Uuid): ResponseMeta;
  hasOriginRequestId(): boolean;
  clearOriginRequestId(): ResponseMeta;

  getMessagesList(): Array<string>;
  setMessagesList(value: Array<string>): ResponseMeta;
  clearMessagesList(): ResponseMeta;
  addMessages(value: string, index?: number): ResponseMeta;

  getPagination(): Pagination | undefined;
  setPagination(value?: Pagination): ResponseMeta;
  hasPagination(): boolean;
  clearPagination(): ResponseMeta;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): ResponseMeta.AsObject;
  static toObject(includeInstance: boolean, msg: ResponseMeta): ResponseMeta.AsObject;
  static serializeBinaryToWriter(message: ResponseMeta, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): ResponseMeta;
  static deserializeBinaryFromReader(message: ResponseMeta, reader: jspb.BinaryReader): ResponseMeta;
}

export namespace ResponseMeta {
  export type AsObject = {
    status: ResponseMeta.Status,
    originRequestId?: Uuid.AsObject,
    messagesList: Array<string>,
    pagination?: Pagination.AsObject,
  }

  export enum Status { 
    UNKNOWNRESPONSE = 0,
    SUCCESS = 1,
    GENERALERROR = 2,
  }

  export enum PaginationCase { 
    _PAGINATION_NOT_SET = 0,
    PAGINATION = 4,
  }
}

export class Host extends jspb.Message {
  getId(): Uuid | undefined;
  setId(value?: Uuid): Host;
  hasId(): boolean;
  clearId(): Host;

  getOrgId(): Uuid | undefined;
  setOrgId(value?: Uuid): Host;
  hasOrgId(): boolean;
  clearOrgId(): Host;

  getName(): string;
  setName(value: string): Host;
  hasName(): boolean;
  clearName(): Host;

  getVersion(): string;
  setVersion(value: string): Host;
  hasVersion(): boolean;
  clearVersion(): Host;

  getLocation(): string;
  setLocation(value: string): Host;
  hasLocation(): boolean;
  clearLocation(): Host;

  getCpuCount(): number;
  setCpuCount(value: number): Host;
  hasCpuCount(): boolean;
  clearCpuCount(): Host;

  getMemSize(): number;
  setMemSize(value: number): Host;
  hasMemSize(): boolean;
  clearMemSize(): Host;

  getDiskSize(): number;
  setDiskSize(value: number): Host;
  hasDiskSize(): boolean;
  clearDiskSize(): Host;

  getOs(): string;
  setOs(value: string): Host;
  hasOs(): boolean;
  clearOs(): Host;

  getOsVersion(): string;
  setOsVersion(value: string): Host;
  hasOsVersion(): boolean;
  clearOsVersion(): Host;

  getIp(): string;
  setIp(value: string): Host;
  hasIp(): boolean;
  clearIp(): Host;

  getStatus(): Host.HostStatus;
  setStatus(value: Host.HostStatus): Host;
  hasStatus(): boolean;
  clearStatus(): Host;

  getNodesList(): Array<Node>;
  setNodesList(value: Array<Node>): Host;
  clearNodesList(): Host;
  addNodes(value?: Node, index?: number): Node;

  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Host;
  hasCreatedAt(): boolean;
  clearCreatedAt(): Host;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Host.AsObject;
  static toObject(includeInstance: boolean, msg: Host): Host.AsObject;
  static serializeBinaryToWriter(message: Host, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Host;
  static deserializeBinaryFromReader(message: Host, reader: jspb.BinaryReader): Host;
}

export namespace Host {
  export type AsObject = {
    id?: Uuid.AsObject,
    orgId?: Uuid.AsObject,
    name?: string,
    version?: string,
    location?: string,
    cpuCount?: number,
    memSize?: number,
    diskSize?: number,
    os?: string,
    osVersion?: string,
    ip?: string,
    status?: Host.HostStatus,
    nodesList: Array<Node.AsObject>,
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
  }

  export enum HostStatus { 
    UNDEFINEDCONTAINERSTATUS = 0,
    CREATING = 1,
    RUNNING = 2,
    STARTING = 3,
    STOPPING = 4,
    STOPPED = 5,
    UPGRADING = 6,
    UPGRADED = 7,
    DELETING = 8,
    DELETED = 9,
    INSTALLING = 10,
    SNAPSHOTTING = 11,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 1,
  }

  export enum OrgIdCase { 
    _ORG_ID_NOT_SET = 0,
    ORG_ID = 2,
  }

  export enum NameCase { 
    _NAME_NOT_SET = 0,
    NAME = 3,
  }

  export enum VersionCase { 
    _VERSION_NOT_SET = 0,
    VERSION = 4,
  }

  export enum LocationCase { 
    _LOCATION_NOT_SET = 0,
    LOCATION = 5,
  }

  export enum CpuCountCase { 
    _CPU_COUNT_NOT_SET = 0,
    CPU_COUNT = 6,
  }

  export enum MemSizeCase { 
    _MEM_SIZE_NOT_SET = 0,
    MEM_SIZE = 7,
  }

  export enum DiskSizeCase { 
    _DISK_SIZE_NOT_SET = 0,
    DISK_SIZE = 8,
  }

  export enum OsCase { 
    _OS_NOT_SET = 0,
    OS = 9,
  }

  export enum OsVersionCase { 
    _OS_VERSION_NOT_SET = 0,
    OS_VERSION = 10,
  }

  export enum IpCase { 
    _IP_NOT_SET = 0,
    IP = 11,
  }

  export enum StatusCase { 
    _STATUS_NOT_SET = 0,
    STATUS = 12,
  }

  export enum CreatedAtCase { 
    _CREATED_AT_NOT_SET = 0,
    CREATED_AT = 14,
  }
}

export class HostProvision extends jspb.Message {
  getId(): string;
  setId(value: string): HostProvision;
  hasId(): boolean;
  clearId(): HostProvision;

  getOrgId(): Uuid | undefined;
  setOrgId(value?: Uuid): HostProvision;
  hasOrgId(): boolean;
  clearOrgId(): HostProvision;

  getHostId(): Uuid | undefined;
  setHostId(value?: Uuid): HostProvision;
  hasHostId(): boolean;
  clearHostId(): HostProvision;

  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): HostProvision;
  hasCreatedAt(): boolean;
  clearCreatedAt(): HostProvision;

  getClaimedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setClaimedAt(value?: google_protobuf_timestamp_pb.Timestamp): HostProvision;
  hasClaimedAt(): boolean;
  clearClaimedAt(): HostProvision;

  getInstallCmd(): string;
  setInstallCmd(value: string): HostProvision;
  hasInstallCmd(): boolean;
  clearInstallCmd(): HostProvision;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): HostProvision.AsObject;
  static toObject(includeInstance: boolean, msg: HostProvision): HostProvision.AsObject;
  static serializeBinaryToWriter(message: HostProvision, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): HostProvision;
  static deserializeBinaryFromReader(message: HostProvision, reader: jspb.BinaryReader): HostProvision;
}

export namespace HostProvision {
  export type AsObject = {
    id?: string,
    orgId?: Uuid.AsObject,
    hostId?: Uuid.AsObject,
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    claimedAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    installCmd?: string,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 1,
  }

  export enum OrgIdCase { 
    _ORG_ID_NOT_SET = 0,
    ORG_ID = 2,
  }

  export enum HostIdCase { 
    _HOST_ID_NOT_SET = 0,
    HOST_ID = 3,
  }

  export enum CreatedAtCase { 
    _CREATED_AT_NOT_SET = 0,
    CREATED_AT = 4,
  }

  export enum ClaimedAtCase { 
    _CLAIMED_AT_NOT_SET = 0,
    CLAIMED_AT = 5,
  }

  export enum InstallCmdCase { 
    _INSTALL_CMD_NOT_SET = 0,
    INSTALL_CMD = 6,
  }
}

export class Node extends jspb.Message {
  getId(): Uuid | undefined;
  setId(value?: Uuid): Node;
  hasId(): boolean;
  clearId(): Node;

  getOrgId(): Uuid | undefined;
  setOrgId(value?: Uuid): Node;
  hasOrgId(): boolean;
  clearOrgId(): Node;

  getBlockchainId(): Uuid | undefined;
  setBlockchainId(value?: Uuid): Node;
  hasBlockchainId(): boolean;
  clearBlockchainId(): Node;

  getName(): string;
  setName(value: string): Node;
  hasName(): boolean;
  clearName(): Node;

  getGroupsList(): Array<string>;
  setGroupsList(value: Array<string>): Node;
  clearGroupsList(): Node;
  addGroups(value: string, index?: number): Node;

  getVersion(): string;
  setVersion(value: string): Node;
  hasVersion(): boolean;
  clearVersion(): Node;

  getIp(): string;
  setIp(value: string): Node;
  hasIp(): boolean;
  clearIp(): Node;

  getType(): Node.NodeType;
  setType(value: Node.NodeType): Node;
  hasType(): boolean;
  clearType(): Node;

  getAddress(): string;
  setAddress(value: string): Node;
  hasAddress(): boolean;
  clearAddress(): Node;

  getWalletAddress(): string;
  setWalletAddress(value: string): Node;
  hasWalletAddress(): boolean;
  clearWalletAddress(): Node;

  getBlockHeight(): number;
  setBlockHeight(value: number): Node;
  hasBlockHeight(): boolean;
  clearBlockHeight(): Node;

  getNodeData(): Uint8Array | string;
  getNodeData_asU8(): Uint8Array;
  getNodeData_asB64(): string;
  setNodeData(value: Uint8Array | string): Node;
  hasNodeData(): boolean;
  clearNodeData(): Node;

  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Node;
  hasCreatedAt(): boolean;
  clearCreatedAt(): Node;

  getUpdatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setUpdatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Node;
  hasUpdatedAt(): boolean;
  clearUpdatedAt(): Node;

  getStatus(): Node.NodeStatus;
  setStatus(value: Node.NodeStatus): Node;
  hasStatus(): boolean;
  clearStatus(): Node;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Node.AsObject;
  static toObject(includeInstance: boolean, msg: Node): Node.AsObject;
  static serializeBinaryToWriter(message: Node, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Node;
  static deserializeBinaryFromReader(message: Node, reader: jspb.BinaryReader): Node;
}

export namespace Node {
  export type AsObject = {
    id?: Uuid.AsObject,
    orgId?: Uuid.AsObject,
    blockchainId?: Uuid.AsObject,
    name?: string,
    groupsList: Array<string>,
    version?: string,
    ip?: string,
    type?: Node.NodeType,
    address?: string,
    walletAddress?: string,
    blockHeight?: number,
    nodeData?: Uint8Array | string,
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    updatedAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    status?: Node.NodeStatus,
  }

  export enum NodeType { 
    UNDEFINEDTYPE = 0,
    NODE = 1,
    API = 2,
    ETL = 3,
    MINER = 4,
    VALIDATOR = 5,
    ORACLE = 6,
    RELAY = 7,
  }

  export enum NodeStatus { 
    UNDEFINEDAPPLICATIONSTATUS = 0,
    BROADCASTING = 1,
    CANCELLED = 2,
    DELEGATING = 3,
    DELINQUENT = 4,
    DISABLED = 5,
    EARNING = 6,
    ELECTING = 7,
    ELECTED = 8,
    EXPORTING = 9,
    INGESTING = 10,
    MINING = 11,
    MINTING = 12,
    PROCESSING = 13,
    RELAYING = 14,
    REMOVED = 15,
    REMOVING = 16,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 1,
  }

  export enum OrgIdCase { 
    _ORG_ID_NOT_SET = 0,
    ORG_ID = 2,
  }

  export enum BlockchainIdCase { 
    _BLOCKCHAIN_ID_NOT_SET = 0,
    BLOCKCHAIN_ID = 3,
  }

  export enum NameCase { 
    _NAME_NOT_SET = 0,
    NAME = 4,
  }

  export enum VersionCase { 
    _VERSION_NOT_SET = 0,
    VERSION = 6,
  }

  export enum IpCase { 
    _IP_NOT_SET = 0,
    IP = 7,
  }

  export enum TypeCase { 
    _TYPE_NOT_SET = 0,
    TYPE = 8,
  }

  export enum AddressCase { 
    _ADDRESS_NOT_SET = 0,
    ADDRESS = 9,
  }

  export enum WalletAddressCase { 
    _WALLET_ADDRESS_NOT_SET = 0,
    WALLET_ADDRESS = 10,
  }

  export enum BlockHeightCase { 
    _BLOCK_HEIGHT_NOT_SET = 0,
    BLOCK_HEIGHT = 11,
  }

  export enum NodeDataCase { 
    _NODE_DATA_NOT_SET = 0,
    NODE_DATA = 12,
  }

  export enum CreatedAtCase { 
    _CREATED_AT_NOT_SET = 0,
    CREATED_AT = 13,
  }

  export enum UpdatedAtCase { 
    _UPDATED_AT_NOT_SET = 0,
    UPDATED_AT = 14,
  }

  export enum StatusCase { 
    _STATUS_NOT_SET = 0,
    STATUS = 15,
  }
}

export class Organization extends jspb.Message {
  getId(): Uuid | undefined;
  setId(value?: Uuid): Organization;
  hasId(): boolean;
  clearId(): Organization;

  getName(): string;
  setName(value: string): Organization;
  hasName(): boolean;
  clearName(): Organization;

  getPersonal(): boolean;
  setPersonal(value: boolean): Organization;
  hasPersonal(): boolean;
  clearPersonal(): Organization;

  getMemberCount(): number;
  setMemberCount(value: number): Organization;
  hasMemberCount(): boolean;
  clearMemberCount(): Organization;

  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Organization;
  hasCreatedAt(): boolean;
  clearCreatedAt(): Organization;

  getUpdatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setUpdatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Organization;
  hasUpdatedAt(): boolean;
  clearUpdatedAt(): Organization;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Organization.AsObject;
  static toObject(includeInstance: boolean, msg: Organization): Organization.AsObject;
  static serializeBinaryToWriter(message: Organization, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Organization;
  static deserializeBinaryFromReader(message: Organization, reader: jspb.BinaryReader): Organization;
}

export namespace Organization {
  export type AsObject = {
    id?: Uuid.AsObject,
    name?: string,
    personal?: boolean,
    memberCount?: number,
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    updatedAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 1,
  }

  export enum NameCase { 
    _NAME_NOT_SET = 0,
    NAME = 2,
  }

  export enum PersonalCase { 
    _PERSONAL_NOT_SET = 0,
    PERSONAL = 3,
  }

  export enum MemberCountCase { 
    _MEMBER_COUNT_NOT_SET = 0,
    MEMBER_COUNT = 4,
  }

  export enum CreatedAtCase { 
    _CREATED_AT_NOT_SET = 0,
    CREATED_AT = 13,
  }

  export enum UpdatedAtCase { 
    _UPDATED_AT_NOT_SET = 0,
    UPDATED_AT = 14,
  }
}

export class InfoUpdate extends jspb.Message {
  getHost(): Host | undefined;
  setHost(value?: Host): InfoUpdate;
  hasHost(): boolean;
  clearHost(): InfoUpdate;

  getNode(): Node | undefined;
  setNode(value?: Node): InfoUpdate;
  hasNode(): boolean;
  clearNode(): InfoUpdate;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): InfoUpdate.AsObject;
  static toObject(includeInstance: boolean, msg: InfoUpdate): InfoUpdate.AsObject;
  static serializeBinaryToWriter(message: InfoUpdate, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): InfoUpdate;
  static deserializeBinaryFromReader(message: InfoUpdate, reader: jspb.BinaryReader): InfoUpdate;
}

export namespace InfoUpdate {
  export type AsObject = {
    host?: Host.AsObject,
    node?: Node.AsObject,
  }

  export enum HostCase { 
    _HOST_NOT_SET = 0,
    HOST = 1,
  }

  export enum NodeCase { 
    _NODE_NOT_SET = 0,
    NODE = 2,
  }
}

export class User extends jspb.Message {
  getId(): Uuid | undefined;
  setId(value?: Uuid): User;
  hasId(): boolean;
  clearId(): User;

  getEmail(): string;
  setEmail(value: string): User;
  hasEmail(): boolean;
  clearEmail(): User;

  getFirstName(): string;
  setFirstName(value: string): User;
  hasFirstName(): boolean;
  clearFirstName(): User;

  getLastName(): string;
  setLastName(value: string): User;
  hasLastName(): boolean;
  clearLastName(): User;

  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): User;
  hasCreatedAt(): boolean;
  clearCreatedAt(): User;

  getUpdatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setUpdatedAt(value?: google_protobuf_timestamp_pb.Timestamp): User;
  hasUpdatedAt(): boolean;
  clearUpdatedAt(): User;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): User.AsObject;
  static toObject(includeInstance: boolean, msg: User): User.AsObject;
  static serializeBinaryToWriter(message: User, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): User;
  static deserializeBinaryFromReader(message: User, reader: jspb.BinaryReader): User;
}

export namespace User {
  export type AsObject = {
    id?: Uuid.AsObject,
    email?: string,
    firstName?: string,
    lastName?: string,
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    updatedAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 1,
  }

  export enum EmailCase { 
    _EMAIL_NOT_SET = 0,
    EMAIL = 2,
  }

  export enum FirstNameCase { 
    _FIRST_NAME_NOT_SET = 0,
    FIRST_NAME = 3,
  }

  export enum LastNameCase { 
    _LAST_NAME_NOT_SET = 0,
    LAST_NAME = 4,
  }

  export enum CreatedAtCase { 
    _CREATED_AT_NOT_SET = 0,
    CREATED_AT = 5,
  }

  export enum UpdatedAtCase { 
    _UPDATED_AT_NOT_SET = 0,
    UPDATED_AT = 6,
  }
}

export class Bill extends jspb.Message {
  getId(): string;
  setId(value: string): Bill;
  hasId(): boolean;
  clearId(): Bill;

  getCreatedAt(): google_protobuf_timestamp_pb.Timestamp | undefined;
  setCreatedAt(value?: google_protobuf_timestamp_pb.Timestamp): Bill;
  hasCreatedAt(): boolean;
  clearCreatedAt(): Bill;

  getTaxNumber(): string;
  setTaxNumber(value: string): Bill;
  hasTaxNumber(): boolean;
  clearTaxNumber(): Bill;

  getReceiverName(): string;
  setReceiverName(value: string): Bill;
  hasReceiverName(): boolean;
  clearReceiverName(): Bill;

  getReceiverAddress(): string;
  setReceiverAddress(value: string): Bill;
  hasReceiverAddress(): boolean;
  clearReceiverAddress(): Bill;

  getTaxRate(): number;
  setTaxRate(value: number): Bill;
  hasTaxRate(): boolean;
  clearTaxRate(): Bill;

  getNetAmount(): number;
  setNetAmount(value: number): Bill;
  hasNetAmount(): boolean;
  clearNetAmount(): Bill;

  getGrossAmount(): number;
  setGrossAmount(value: number): Bill;
  hasGrossAmount(): boolean;
  clearGrossAmount(): Bill;

  getPdfUrl(): string;
  setPdfUrl(value: string): Bill;
  hasPdfUrl(): boolean;
  clearPdfUrl(): Bill;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): Bill.AsObject;
  static toObject(includeInstance: boolean, msg: Bill): Bill.AsObject;
  static serializeBinaryToWriter(message: Bill, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): Bill;
  static deserializeBinaryFromReader(message: Bill, reader: jspb.BinaryReader): Bill;
}

export namespace Bill {
  export type AsObject = {
    id?: string,
    createdAt?: google_protobuf_timestamp_pb.Timestamp.AsObject,
    taxNumber?: string,
    receiverName?: string,
    receiverAddress?: string,
    taxRate?: number,
    netAmount?: number,
    grossAmount?: number,
    pdfUrl?: string,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 1,
  }

  export enum CreatedAtCase { 
    _CREATED_AT_NOT_SET = 0,
    CREATED_AT = 2,
  }

  export enum TaxNumberCase { 
    _TAX_NUMBER_NOT_SET = 0,
    TAX_NUMBER = 3,
  }

  export enum ReceiverNameCase { 
    _RECEIVER_NAME_NOT_SET = 0,
    RECEIVER_NAME = 4,
  }

  export enum ReceiverAddressCase { 
    _RECEIVER_ADDRESS_NOT_SET = 0,
    RECEIVER_ADDRESS = 5,
  }

  export enum TaxRateCase { 
    _TAX_RATE_NOT_SET = 0,
    TAX_RATE = 6,
  }

  export enum NetAmountCase { 
    _NET_AMOUNT_NOT_SET = 0,
    NET_AMOUNT = 7,
  }

  export enum GrossAmountCase { 
    _GROSS_AMOUNT_NOT_SET = 0,
    GROSS_AMOUNT = 8,
  }

  export enum PdfUrlCase { 
    _PDF_URL_NOT_SET = 0,
    PDF_URL = 9,
  }
}

export class KPI extends jspb.Message {
  getName(): KPI.Name;
  setName(value: KPI.Name): KPI;

  getValue(): google_protobuf_any_pb.Any | undefined;
  setValue(value?: google_protobuf_any_pb.Any): KPI;
  hasValue(): boolean;
  clearValue(): KPI;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): KPI.AsObject;
  static toObject(includeInstance: boolean, msg: KPI): KPI.AsObject;
  static serializeBinaryToWriter(message: KPI, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): KPI;
  static deserializeBinaryFromReader(message: KPI, reader: jspb.BinaryReader): KPI;
}

export namespace KPI {
  export type AsObject = {
    name: KPI.Name,
    value?: google_protobuf_any_pb.Any.AsObject,
  }

  export enum Name { 
    UNKNOWN = 0,
    NODES = 1,
    HOSTS = 2,
    ONLINE = 3,
    OFFLINE = 4,
  }
}

export class UserConfigurationParameter extends jspb.Message {
  getName(): string;
  setName(value: string): UserConfigurationParameter;

  getValue(): google_protobuf_any_pb.Any | undefined;
  setValue(value?: google_protobuf_any_pb.Any): UserConfigurationParameter;
  hasValue(): boolean;
  clearValue(): UserConfigurationParameter;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UserConfigurationParameter.AsObject;
  static toObject(includeInstance: boolean, msg: UserConfigurationParameter): UserConfigurationParameter.AsObject;
  static serializeBinaryToWriter(message: UserConfigurationParameter, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UserConfigurationParameter;
  static deserializeBinaryFromReader(message: UserConfigurationParameter, reader: jspb.BinaryReader): UserConfigurationParameter;
}

export namespace UserConfigurationParameter {
  export type AsObject = {
    name: string,
    value?: google_protobuf_any_pb.Any.AsObject,
  }
}

