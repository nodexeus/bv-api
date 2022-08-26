import * as jspb from 'google-protobuf'

import * as common_pb from './common_pb';


export class LoginUserRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): LoginUserRequest;
  hasMeta(): boolean;
  clearMeta(): LoginUserRequest;

  getEmail(): string;
  setEmail(value: string): LoginUserRequest;

  getPassword(): string;
  setPassword(value: string): LoginUserRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LoginUserRequest.AsObject;
  static toObject(includeInstance: boolean, msg: LoginUserRequest): LoginUserRequest.AsObject;
  static serializeBinaryToWriter(message: LoginUserRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LoginUserRequest;
  static deserializeBinaryFromReader(message: LoginUserRequest, reader: jspb.BinaryReader): LoginUserRequest;
}

export namespace LoginUserRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
    email: string,
    password: string,
  }
}

export class LoginUserResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): LoginUserResponse;
  hasMeta(): boolean;
  clearMeta(): LoginUserResponse;

  getToken(): common_pb.ApiToken | undefined;
  setToken(value?: common_pb.ApiToken): LoginUserResponse;
  hasToken(): boolean;
  clearToken(): LoginUserResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): LoginUserResponse.AsObject;
  static toObject(includeInstance: boolean, msg: LoginUserResponse): LoginUserResponse.AsObject;
  static serializeBinaryToWriter(message: LoginUserResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): LoginUserResponse;
  static deserializeBinaryFromReader(message: LoginUserResponse, reader: jspb.BinaryReader): LoginUserResponse;
}

export namespace LoginUserResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
    token?: common_pb.ApiToken.AsObject,
  }
}

export class RefreshTokenRequest extends jspb.Message {
  getMeta(): common_pb.RequestMeta | undefined;
  setMeta(value?: common_pb.RequestMeta): RefreshTokenRequest;
  hasMeta(): boolean;
  clearMeta(): RefreshTokenRequest;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RefreshTokenRequest.AsObject;
  static toObject(includeInstance: boolean, msg: RefreshTokenRequest): RefreshTokenRequest.AsObject;
  static serializeBinaryToWriter(message: RefreshTokenRequest, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RefreshTokenRequest;
  static deserializeBinaryFromReader(message: RefreshTokenRequest, reader: jspb.BinaryReader): RefreshTokenRequest;
}

export namespace RefreshTokenRequest {
  export type AsObject = {
    meta?: common_pb.RequestMeta.AsObject,
  }
}

export class RefreshTokenResponse extends jspb.Message {
  getMeta(): common_pb.ResponseMeta | undefined;
  setMeta(value?: common_pb.ResponseMeta): RefreshTokenResponse;
  hasMeta(): boolean;
  clearMeta(): RefreshTokenResponse;

  serializeBinary(): Uint8Array;
  toObject(includeInstance?: boolean): RefreshTokenResponse.AsObject;
  static toObject(includeInstance: boolean, msg: RefreshTokenResponse): RefreshTokenResponse.AsObject;
  static serializeBinaryToWriter(message: RefreshTokenResponse, writer: jspb.BinaryWriter): void;
  static deserializeBinary(bytes: Uint8Array): RefreshTokenResponse;
  static deserializeBinaryFromReader(message: RefreshTokenResponse, reader: jspb.BinaryReader): RefreshTokenResponse;
}

export namespace RefreshTokenResponse {
  export type AsObject = {
    meta?: common_pb.ResponseMeta.AsObject,
  }
}

