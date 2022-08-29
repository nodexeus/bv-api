import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class CreateNodeRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): CreateNodeRequest;
  hasMeta(): boolean;
  clearMeta(): CreateNodeRequest;

  getNode(): common_pb.Node | undefined;
  setNode(value?: common_pb.Node): CreateNodeRequest;
  hasNode(): boolean;
  clearNode(): CreateNodeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateNodeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateNodeRequest): CreateNodeRequest.AsObject;
  static serializeBinaryToWriter(message: CreateNodeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateNodeRequest;
  static deserializeBinaryFromReader(message: CreateNodeRequest, reader: jspb.BinaryReader): CreateNodeRequest;
}

export namespace CreateNodeRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    node?: common_pb.Node.AsObject,
  }
}

export class CreateNodeResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): CreateNodeResponse;
  hasMeta(): boolean;
  clearMeta(): CreateNodeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateNodeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateNodeResponse): CreateNodeResponse.AsObject;
  static serializeBinaryToWriter(message: CreateNodeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateNodeResponse;
  static deserializeBinaryFromReader(message: CreateNodeResponse, reader: jspb.BinaryReader): CreateNodeResponse;
}

export namespace CreateNodeResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class GetNodeRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetNodeRequest;
  hasMeta(): boolean;
  clearMeta(): GetNodeRequest;

  getId(): common_pb.Uuid | undefined;
  setId(value?: common_pb.Uuid): GetNodeRequest;
  hasId(): boolean;
  clearId(): GetNodeRequest;

  getOrgId(): common_pb.Uuid | undefined;
  setOrgId(value?: common_pb.Uuid): GetNodeRequest;
  hasOrgId(): boolean;
  clearOrgId(): GetNodeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetNodeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetNodeRequest): GetNodeRequest.AsObject;
  static serializeBinaryToWriter(message: GetNodeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetNodeRequest;
  static deserializeBinaryFromReader(message: GetNodeRequest, reader: jspb.BinaryReader): GetNodeRequest;
}

export namespace GetNodeRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    id?: common_pb.Uuid.AsObject,
    orgId?: common_pb.Uuid.AsObject,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 2,
  }

  export enum OrgIdCase { 
    _ORG_ID_NOT_SET = 0,
    ORG_ID = 3,
  }
}

export class GetNodeResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetNodeResponse;
  hasMeta(): boolean;
  clearMeta(): GetNodeResponse;

  getNodesList(): Array<common_pb.Node>;
  setNodesList(value: Array<common_pb.Node>): GetNodeResponse;
  clearNodesList(): GetNodeResponse;
  addNodes(value?: common_pb.Node, index?: number): common_pb.Node;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetNodeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetNodeResponse): GetNodeResponse.AsObject;
  static serializeBinaryToWriter(message: GetNodeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetNodeResponse;
  static deserializeBinaryFromReader(message: GetNodeResponse, reader: jspb.BinaryReader): GetNodeResponse;
}

export namespace GetNodeResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    nodesList: Array<common_pb.Node.AsObject>,
  }
}

export class UpdateNodeRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): UpdateNodeRequest;
  hasMeta(): boolean;
  clearMeta(): UpdateNodeRequest;

  getNode(): common_pb.Node | undefined;
  setNode(value?: common_pb.Node): UpdateNodeRequest;
  hasNode(): boolean;
  clearNode(): UpdateNodeRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateNodeRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateNodeRequest): UpdateNodeRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateNodeRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateNodeRequest;
  static deserializeBinaryFromReader(message: UpdateNodeRequest, reader: jspb.BinaryReader): UpdateNodeRequest;
}

export namespace UpdateNodeRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    node?: common_pb.Node.AsObject,
  }
}

export class UpdateNodeResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): UpdateNodeResponse;
  hasMeta(): boolean;
  clearMeta(): UpdateNodeResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateNodeResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateNodeResponse): UpdateNodeResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateNodeResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateNodeResponse;
  static deserializeBinaryFromReader(message: UpdateNodeResponse, reader: jspb.BinaryReader): UpdateNodeResponse;
}

export namespace UpdateNodeResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

