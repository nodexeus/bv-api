import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class CreateBillRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): CreateBillRequest;
  hasMeta(): boolean;
  clearMeta(): CreateBillRequest;

  getUserId(): common_pb.Uuid | undefined;
  setUserId(value?: common_pb.Uuid): CreateBillRequest;
  hasUserId(): boolean;
  clearUserId(): CreateBillRequest;

  getOrgId(): common_pb.Uuid | undefined;
  setOrgId(value?: common_pb.Uuid): CreateBillRequest;
  hasOrgId(): boolean;
  clearOrgId(): CreateBillRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateBillRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateBillRequest): CreateBillRequest.AsObject;
  static serializeBinaryToWriter(message: CreateBillRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateBillRequest;
  static deserializeBinaryFromReader(message: CreateBillRequest, reader: jspb.BinaryReader): CreateBillRequest;
}

export namespace CreateBillRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    userId?: common_pb.Uuid.AsObject,
    orgId?: common_pb.Uuid.AsObject,
  }

  export enum UserIdCase { 
    _USER_ID_NOT_SET = 0,
    USER_ID = 2,
  }

  export enum OrgIdCase { 
    _ORG_ID_NOT_SET = 0,
    ORG_ID = 3,
  }
}

export class CreateBillResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): CreateBillResponse;
  hasMeta(): boolean;
  clearMeta(): CreateBillResponse;

  getBill(): common_pb.Bill | undefined;
  setBill(value?: common_pb.Bill): CreateBillResponse;
  hasBill(): boolean;
  clearBill(): CreateBillResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateBillResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateBillResponse): CreateBillResponse.AsObject;
  static serializeBinaryToWriter(message: CreateBillResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateBillResponse;
  static deserializeBinaryFromReader(message: CreateBillResponse, reader: jspb.BinaryReader): CreateBillResponse;
}

export namespace CreateBillResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    bill?: common_pb.Bill.AsObject,
  }
}

