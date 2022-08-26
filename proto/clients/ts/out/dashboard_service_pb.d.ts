import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class DashboardKpiRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): DashboardKpiRequest;
  hasMeta(): boolean;
  clearMeta(): DashboardKpiRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DashboardKpiRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DashboardKpiRequest): DashboardKpiRequest.AsObject;
  static serializeBinaryToWriter(message: DashboardKpiRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DashboardKpiRequest;
  static deserializeBinaryFromReader(message: DashboardKpiRequest, reader: jspb.BinaryReader): DashboardKpiRequest;
}

export namespace DashboardKpiRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
  }
}

export class DashboardKpiResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): DashboardKpiResponse;
  hasMeta(): boolean;
  clearMeta(): DashboardKpiResponse;

  getValuesList(): Array<common_pb.KPI>;
  setValuesList(value: Array<common_pb.KPI>): DashboardKpiResponse;
  clearValuesList(): DashboardKpiResponse;
  addValues(value?: common_pb.KPI, index?: number): common_pb.KPI;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DashboardKpiResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DashboardKpiResponse): DashboardKpiResponse.AsObject;
  static serializeBinaryToWriter(message: DashboardKpiResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DashboardKpiResponse;
  static deserializeBinaryFromReader(message: DashboardKpiResponse, reader: jspb.BinaryReader): DashboardKpiResponse;
}

export namespace DashboardKpiResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    valuesList: Array<common_pb.KPI.AsObject>,
  }
}

