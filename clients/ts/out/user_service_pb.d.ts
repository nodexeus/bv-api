import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class GetUserRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetUserRequest;
  hasMeta(): boolean;
  clearMeta(): GetUserRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetUserRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetUserRequest): GetUserRequest.AsObject;
  static serializeBinaryToWriter(message: GetUserRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetUserRequest;
  static deserializeBinaryFromReader(message: GetUserRequest, reader: jspb.BinaryReader): GetUserRequest;
}

export namespace GetUserRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
  }
}

export class GetUserResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetUserResponse;
  hasMeta(): boolean;
  clearMeta(): GetUserResponse;

  getUser(): common_pb.User | undefined;
  setUser(value?: common_pb.User): GetUserResponse;
  hasUser(): boolean;
  clearUser(): GetUserResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetUserResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetUserResponse): GetUserResponse.AsObject;
  static serializeBinaryToWriter(message: GetUserResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetUserResponse;
  static deserializeBinaryFromReader(message: GetUserResponse, reader: jspb.BinaryReader): GetUserResponse;
}

export namespace GetUserResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    user?: common_pb.User.AsObject,
  }
}

export class CreateUserRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): CreateUserRequest;
  hasMeta(): boolean;
  clearMeta(): CreateUserRequest;

  getUser(): common_pb.User | undefined;
  setUser(value?: common_pb.User): CreateUserRequest;
  hasUser(): boolean;
  clearUser(): CreateUserRequest;

  getPassword(): string;
  setPassword(value: string): CreateUserRequest;

  getPasswordConfirmation(): string;
  setPasswordConfirmation(value: string): CreateUserRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateUserRequest.AsObject;
  static toObject(includeInstance: boolean, msg: CreateUserRequest): CreateUserRequest.AsObject;
  static serializeBinaryToWriter(message: CreateUserRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateUserRequest;
  static deserializeBinaryFromReader(message: CreateUserRequest, reader: jspb.BinaryReader): CreateUserRequest;
}

export namespace CreateUserRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    user?: common_pb.User.AsObject,
    password: string,
    passwordConfirmation: string,
  }
}

export class CreateUserResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): CreateUserResponse;
  hasMeta(): boolean;
  clearMeta(): CreateUserResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): CreateUserResponse.AsObject;
  static toObject(includeInstance: boolean, msg: CreateUserResponse): CreateUserResponse.AsObject;
  static serializeBinaryToWriter(message: CreateUserResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): CreateUserResponse;
  static deserializeBinaryFromReader(message: CreateUserResponse, reader: jspb.BinaryReader): CreateUserResponse;
}

export namespace CreateUserResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class UpsertConfigurationRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): UpsertConfigurationRequest;
  hasMeta(): boolean;
  clearMeta(): UpsertConfigurationRequest;

  getUserId(): common_pb.Uuid | undefined;
  setUserId(value?: common_pb.Uuid): UpsertConfigurationRequest;
  hasUserId(): boolean;
  clearUserId(): UpsertConfigurationRequest;

  getParamsList(): Array<common_pb.UserConfigurationParameter>;
  setParamsList(value: Array<common_pb.UserConfigurationParameter>): UpsertConfigurationRequest;
  clearParamsList(): UpsertConfigurationRequest;
  addParams(value?: common_pb.UserConfigurationParameter, index?: number): common_pb.UserConfigurationParameter;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpsertConfigurationRequest.AsObject;
  static toObject(includeInstance: boolean, msg: UpsertConfigurationRequest): UpsertConfigurationRequest.AsObject;
  static serializeBinaryToWriter(message: UpsertConfigurationRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpsertConfigurationRequest;
  static deserializeBinaryFromReader(message: UpsertConfigurationRequest, reader: jspb.BinaryReader): UpsertConfigurationRequest;
}

export namespace UpsertConfigurationRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    userId?: common_pb.Uuid.AsObject,
    paramsList: Array<common_pb.UserConfigurationParameter.AsObject>,
  }
}

export class UpsertConfigurationResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): UpsertConfigurationResponse;
  hasMeta(): boolean;
  clearMeta(): UpsertConfigurationResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): UpsertConfigurationResponse.AsObject;
  static toObject(includeInstance: boolean, msg: UpsertConfigurationResponse): UpsertConfigurationResponse.AsObject;
  static serializeBinaryToWriter(message: UpsertConfigurationResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): UpsertConfigurationResponse;
  static deserializeBinaryFromReader(message: UpsertConfigurationResponse, reader: jspb.BinaryReader): UpsertConfigurationResponse;
}

export namespace UpsertConfigurationResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

export class GetConfigurationRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): GetConfigurationRequest;
  hasMeta(): boolean;
  clearMeta(): GetConfigurationRequest;

  getUserId(): common_pb.Uuid | undefined;
  setUserId(value?: common_pb.Uuid): GetConfigurationRequest;
  hasUserId(): boolean;
  clearUserId(): GetConfigurationRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetConfigurationRequest.AsObject;
  static toObject(includeInstance: boolean, msg: GetConfigurationRequest): GetConfigurationRequest.AsObject;
  static serializeBinaryToWriter(message: GetConfigurationRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetConfigurationRequest;
  static deserializeBinaryFromReader(message: GetConfigurationRequest, reader: jspb.BinaryReader): GetConfigurationRequest;
}

export namespace GetConfigurationRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    userId?: common_pb.Uuid.AsObject,
  }
}

export class GetConfigurationResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): GetConfigurationResponse;
  hasMeta(): boolean;
  clearMeta(): GetConfigurationResponse;

  getParamsList(): Array<common_pb.UserConfigurationParameter>;
  setParamsList(value: Array<common_pb.UserConfigurationParameter>): GetConfigurationResponse;
  clearParamsList(): GetConfigurationResponse;
  addParams(value?: common_pb.UserConfigurationParameter, index?: number): common_pb.UserConfigurationParameter;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): GetConfigurationResponse.AsObject;
  static toObject(includeInstance: boolean, msg: GetConfigurationResponse): GetConfigurationResponse.AsObject;
  static serializeBinaryToWriter(message: GetConfigurationResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): GetConfigurationResponse;
  static deserializeBinaryFromReader(message: GetConfigurationResponse, reader: jspb.BinaryReader): GetConfigurationResponse;
}

export namespace GetConfigurationResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    paramsList: Array<common_pb.UserConfigurationParameter.AsObject>,
  }
}

