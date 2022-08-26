import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class GetOrganizationsRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetOrganizationsRequest;
  hasMeta(): boolean;
  clearMeta(): GetOrganizationsRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetOrganizationsRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetOrganizationsRequest): GetOrganizationsRequest.AsObject;
  static serializeBinaryToWriter(message: GetOrganizationsRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetOrganizationsRequest;
  static deserializeBinaryFromReader(message: GetOrganizationsRequest, reader: jspb.BinaryReader): GetOrganizationsRequest;
}

export namespace GetOrganizationsRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
  }
}

export class GetOrganizationsResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetOrganizationsResponse;
  hasMeta(): boolean;
  clearMeta(): GetOrganizationsResponse;

  getOrganizationsList(): Array<common_pb.Organization>;
  setOrganizationsList(value: Array<common_pb.Organization>): GetOrganizationsResponse;
  clearOrganizationsList(): GetOrganizationsResponse;
  addOrganizations(value?: common_pb.Organization, index?: number): common_pb.Organization;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetOrganizationsResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetOrganizationsResponse): GetOrganizationsResponse.AsObject;
  static serializeBinaryToWriter(message: GetOrganizationsResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetOrganizationsResponse;
  static deserializeBinaryFromReader(message: GetOrganizationsResponse, reader: jspb.BinaryReader): GetOrganizationsResponse;
}

export namespace GetOrganizationsResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    organizationsList: Array<common_pb.Organization.AsObject>,
  }
}

export class CreateOrganizationRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): CreateOrganizationRequest;
  hasMeta(): boolean;
  clearMeta(): CreateOrganizationRequest;

  getOrganization(): common_pb.Organization | undefined;
  setOrganization(value?: common_pb.Organization): CreateOrganizationRequest;
  hasOrganization(): boolean;
  clearOrganization(): CreateOrganizationRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateOrganizationRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateOrganizationRequest): CreateOrganizationRequest.AsObject;
  static serializeBinaryToWriter(message: CreateOrganizationRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateOrganizationRequest;
  static deserializeBinaryFromReader(message: CreateOrganizationRequest, reader: jspb.BinaryReader): CreateOrganizationRequest;
}

export namespace CreateOrganizationRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    organization?: common_pb.Organization.AsObject,
  }
}

export class CreateOrganizationResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): CreateOrganizationResponse;
  hasMeta(): boolean;
  clearMeta(): CreateOrganizationResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateOrganizationResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateOrganizationResponse): CreateOrganizationResponse.AsObject;
  static serializeBinaryToWriter(message: CreateOrganizationResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateOrganizationResponse;
  static deserializeBinaryFromReader(message: CreateOrganizationResponse, reader: jspb.BinaryReader): CreateOrganizationResponse;
}

export namespace CreateOrganizationResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class UpdateOrganizationRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): UpdateOrganizationRequest;
  hasMeta(): boolean;
  clearMeta(): UpdateOrganizationRequest;

  getOrganization(): common_pb.Organization | undefined;
  setOrganization(value?: common_pb.Organization): UpdateOrganizationRequest;
  hasOrganization(): boolean;
  clearOrganization(): UpdateOrganizationRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateOrganizationRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateOrganizationRequest): UpdateOrganizationRequest.AsObject;
  static serializeBinaryToWriter(message: UpdateOrganizationRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateOrganizationRequest;
  static deserializeBinaryFromReader(message: UpdateOrganizationRequest, reader: jspb.BinaryReader): UpdateOrganizationRequest;
}

export namespace UpdateOrganizationRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    organization?: common_pb.Organization.AsObject,
  }
}

export class UpdateOrganizationResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): UpdateOrganizationResponse;
  hasMeta(): boolean;
  clearMeta(): UpdateOrganizationResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpdateOrganizationResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpdateOrganizationResponse): UpdateOrganizationResponse.AsObject;
  static serializeBinaryToWriter(message: UpdateOrganizationResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpdateOrganizationResponse;
  static deserializeBinaryFromReader(message: UpdateOrganizationResponse, reader: jspb.BinaryReader): UpdateOrganizationResponse;
}

export namespace UpdateOrganizationResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class DeleteOrganizationRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): DeleteOrganizationRequest;
  hasMeta(): boolean;
  clearMeta(): DeleteOrganizationRequest;

  getId(): common_pb.Uuid | undefined;
  setId(value?: common_pb.Uuid): DeleteOrganizationRequest;
  hasId(): boolean;
  clearId(): DeleteOrganizationRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteOrganizationRequest.AsObject;
  static toObject(includeInstance: boolean, msg: DeleteOrganizationRequest): DeleteOrganizationRequest.AsObject;
  static serializeBinaryToWriter(message: DeleteOrganizationRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeleteOrganizationRequest;
  static deserializeBinaryFromReader(message: DeleteOrganizationRequest, reader: jspb.BinaryReader): DeleteOrganizationRequest;
}

export namespace DeleteOrganizationRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    id?: common_pb.Uuid.AsObject,
  }
}

export class DeleteOrganizationResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): DeleteOrganizationResponse;
  hasMeta(): boolean;
  clearMeta(): DeleteOrganizationResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): DeleteOrganizationResponse.AsObject;
  static toObject(includeInstance: boolean, msg: DeleteOrganizationResponse): DeleteOrganizationResponse.AsObject;
  static serializeBinaryToWriter(message: DeleteOrganizationResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): DeleteOrganizationResponse;
  static deserializeBinaryFromReader(message: DeleteOrganizationResponse, reader: jspb.BinaryReader): DeleteOrganizationResponse;
}

export namespace DeleteOrganizationResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

