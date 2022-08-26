import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class GetHostsRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetHostsRequest;
  hasMeta(): boolean;
  clearMeta(): GetHostsRequest;

  getId(): common_pb.Uuid | undefined;
  setId(value?: common_pb.Uuid): GetHostsRequest;
  hasId(): boolean;
  clearId(): GetHostsRequest;

  getOrgId(): common_pb.Uuid | undefined;
  setOrgId(value?: common_pb.Uuid): GetHostsRequest;
  hasOrgId(): boolean;
  clearOrgId(): GetHostsRequest;

  getToken(): string;
  setToken(value: string): GetHostsRequest;
  hasToken(): boolean;
  clearToken(): GetHostsRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetHostsRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetHostsRequest): GetHostsRequest.AsObject;
  static serializeBinaryToWriter(message: GetHostsRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetHostsRequest;
  static deserializeBinaryFromReader(message: GetHostsRequest, reader: jspb.BinaryReader): GetHostsRequest;
}

export namespace GetHostsRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    id?: common_pb.Uuid.AsObject,
    orgId?: common_pb.Uuid.AsObject,
    token?: string,
  }

  export enum IdCase { 
    _ID_NOT_SET = 0,
    ID = 2,
  }

  export enum OrgIdCase { 
    _ORG_ID_NOT_SET = 0,
    ORG_ID = 3,
  }

  export enum TokenCase { 
    _TOKEN_NOT_SET = 0,
    TOKEN = 4,
  }
}

export class GetHostsResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetHostsResponse;
  hasMeta(): boolean;
  clearMeta(): GetHostsResponse;

  getHostsList(): Array<common_pb.Host>;
  setHostsList(value: Array<common_pb.Host>): GetHostsResponse;
  clearHostsList(): GetHostsResponse;
  addHosts(value?: common_pb.Host, index?: number): common_pb.Host;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetHostsResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetHostsResponse): GetHostsResponse.AsObject;
  static serializeBinaryToWriter(message: GetHostsResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetHostsResponse;
  static deserializeBinaryFromReader(message: GetHostsResponse, reader: jspb.BinaryReader): GetHostsResponse;
}

export namespace GetHostsResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    hostsList: Array<common_pb.Host.AsObject>,
  }
}

export class CreateHostRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): CreateHostRequest;
  hasMeta(): boolean;
  clearMeta(): CreateHostRequest;

  getHost(): common_pb.Host | undefined;
  setHost(value?: common_pb.Host): CreateHostRequest;
  hasHost(): boolean;
  clearHost(): CreateHostRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateHostRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateHostRequest): CreateHostRequest.AsObject;
  static serializeBinaryToWriter(message: CreateHostRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateHostRequest;
  static deserializeBinaryFromReader(message: CreateHostRequest, reader: jspb.BinaryReader): CreateHostRequest;
}

export namespace CreateHostRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    host?: common_pb.Host.AsObject,
  }
}

export class CreateHostResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): CreateHostResponse;
  hasMeta(): boolean;
  clearMeta(): CreateHostResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateHostResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateHostResponse): CreateHostResponse.AsObject;
  static serializeBinaryToWriter(message: CreateHostResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateHostResponse;
  static deserializeBinaryFromReader(message: CreateHostResponse, reader: jspb.BinaryReader): CreateHostResponse;
}

export namespace CreateHostResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class UpdateHostRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): UpdateHostRequest;
  hasMeta(): boolean;
  clearMeta(): UpdateHostRequest;

  getHost(): common_pb.Host | undefined;
  setHost(value?: common_pb.Host): UpdateHostRequest;
  hasHost(): boolean;
  clearHost(): UpdateHostRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateHostRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateHostRequest): UpdateHostRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateHostRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateHostRequest;
  static deserializeBinaryFromReader(message: UpdateHostRequest, reader: jspb.BinaryReader): UpdateHostRequest;
}

export namespace UpdateHostRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    host?: common_pb.Host.AsObject,
  }
}

export class UpdateHostResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): UpdateHostResponse;
  hasMeta(): boolean;
  clearMeta(): UpdateHostResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateHostResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateHostResponse): UpdateHostResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateHostResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateHostResponse;
  static deserializeBinaryFromReader(message: UpdateHostResponse, reader: jspb.BinaryReader): UpdateHostResponse;
}

export namespace UpdateHostResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class DeleteHostRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): DeleteHostRequest;
  hasMeta(): boolean;
  clearMeta(): DeleteHostRequest;

  getId(): common_pb.Uuid | undefined;
  setId(value?: common_pb.Uuid): DeleteHostRequest;
  hasId(): boolean;
  clearId(): DeleteHostRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteHostRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeleteHostRequest): DeleteHostRequest.AsObject;
  static serializeBinaryToWriter(message: DeleteHostRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeleteHostRequest;
  static deserializeBinaryFromReader(message: DeleteHostRequest, reader: jspb.BinaryReader): DeleteHostRequest;
}

export namespace DeleteHostRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    id?: common_pb.Uuid.AsObject,
  }
}

export class DeleteHostResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): DeleteHostResponse;
  hasMeta(): boolean;
  clearMeta(): DeleteHostResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteHostResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DeleteHostResponse): DeleteHostResponse.AsObject;
  static serializeBinaryToWriter(message: DeleteHostResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeleteHostResponse;
  static deserializeBinaryFromReader(message: DeleteHostResponse, reader: jspb.BinaryReader): DeleteHostResponse;
}

export namespace DeleteHostResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

