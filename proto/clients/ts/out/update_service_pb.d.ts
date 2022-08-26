import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class GetUpdatesRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetUpdatesRequest;
  hasMeta(): boolean;
  clearMeta(): GetUpdatesRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetUpdatesRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetUpdatesRequest): GetUpdatesRequest.AsObject;
  static serializeBinaryToWriter(message: GetUpdatesRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetUpdatesRequest;
  static deserializeBinaryFromReader(message: GetUpdatesRequest, reader: jspb.BinaryReader): GetUpdatesRequest;
}

export namespace GetUpdatesRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
  }
}

export class GetUpdatesResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetUpdatesResponse;
  hasMeta(): boolean;
  clearMeta(): GetUpdatesResponse;

  getUpdate(): common_pb.InfoUpdate | undefined;
  setUpdate(value?: common_pb.InfoUpdate): GetUpdatesResponse;
  hasUpdate(): boolean;
  clearUpdate(): GetUpdatesResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetUpdatesResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetUpdatesResponse): GetUpdatesResponse.AsObject;
  static serializeBinaryToWriter(message: GetUpdatesResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetUpdatesResponse;
  static deserializeBinaryFromReader(message: GetUpdatesResponse, reader: jspb.BinaryReader): GetUpdatesResponse;
}

export namespace GetUpdatesResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    update?: common_pb.InfoUpdate.AsObject,
  }
}

