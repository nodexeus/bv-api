import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class GetHostProvisionRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetHostProvisionRequest;
  hasMeta(): boolean;
  clearMeta(): GetHostProvisionRequest;

  getId(): common_pb.Uuid | undefined;
  setId(value?: common_pb.Uuid): GetHostProvisionRequest;
  hasId(): boolean;
  clearId(): GetHostProvisionRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetHostProvisionRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetHostProvisionRequest): GetHostProvisionRequest.AsObject;
  static serializeBinaryToWriter(message: GetHostProvisionRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetHostProvisionRequest;
  static deserializeBinaryFromReader(message: GetHostProvisionRequest, reader: jspb.BinaryReader): GetHostProvisionRequest;
}

export namespace GetHostProvisionRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    id?: common_pb.Uuid.AsObject,
  }
}

export class GetHostProvisionResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetHostProvisionResponse;
  hasMeta(): boolean;
  clearMeta(): GetHostProvisionResponse;

  getHostProvision(): common_pb.HostProvision | undefined;
  setHostProvision(value?: common_pb.HostProvision): GetHostProvisionResponse;
  hasHostProvision(): boolean;
  clearHostProvision(): GetHostProvisionResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetHostProvisionResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetHostProvisionResponse): GetHostProvisionResponse.AsObject;
  static serializeBinaryToWriter(message: GetHostProvisionResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetHostProvisionResponse;
  static deserializeBinaryFromReader(message: GetHostProvisionResponse, reader: jspb.BinaryReader): GetHostProvisionResponse;
}

export namespace GetHostProvisionResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    hostProvision?: common_pb.HostProvision.AsObject,
  }
}

export class CreateHostProvisionRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): CreateHostProvisionRequest;
  hasMeta(): boolean;
  clearMeta(): CreateHostProvisionRequest;

  getHostProvision(): common_pb.HostProvision | undefined;
  setHostProvision(value?: common_pb.HostProvision): CreateHostProvisionRequest;
  hasHostProvision(): boolean;
  clearHostProvision(): CreateHostProvisionRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateHostProvisionRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateHostProvisionRequest): CreateHostProvisionRequest.AsObject;
  static serializeBinaryToWriter(message: CreateHostProvisionRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateHostProvisionRequest;
  static deserializeBinaryFromReader(message: CreateHostProvisionRequest, reader: jspb.BinaryReader): CreateHostProvisionRequest;
}

export namespace CreateHostProvisionRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    hostProvision?: common_pb.HostProvision.AsObject,
  }
}

export class CreateHostProvisionResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): CreateHostProvisionResponse;
  hasMeta(): boolean;
  clearMeta(): CreateHostProvisionResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateHostProvisionResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateHostProvisionResponse): CreateHostProvisionResponse.AsObject;
  static serializeBinaryToWriter(message: CreateHostProvisionResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateHostProvisionResponse;
  static deserializeBinaryFromReader(message: CreateHostProvisionResponse, reader: jspb.BinaryReader): CreateHostProvisionResponse;
}

export namespace CreateHostProvisionResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

