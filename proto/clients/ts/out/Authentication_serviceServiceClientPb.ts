/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as authentication_service_pb from './authentication_service_pb';


export class AuthenticationServiceClient {
  client_: grpcWeb.AbstractClientBase;
  hostname_: string;
  credentials_: null | { [index: string]: string; };
  options_: null | { [index: string]: any; };

  constructor (hostname: string,
               credentials?: null | { [index: string]: string; },
               options?: null | { [index: string]: any; }) {
    if (!options) options = {};
    if (!credentials) credentials = {};
    options['format'] = 'text';

    this.client_ = new grpcWeb.GrpcWebClientBase(options);
    this.hostname_ = hostname;
    this.credentials_ = credentials;
    this.options_ = options;
  }

  methodDescriptorLogin = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.AuthenticationService/Login',
    grpcWeb.MethodType.UNARY,
    authentication_service_pb.LoginUserRequest,
    authentication_service_pb.LoginUserResponse,
    (request: authentication_service_pb.LoginUserRequest) => {
      return request.serializeBinary();
    },
    authentication_service_pb.LoginUserResponse.deserializeBinary
  );

  login(
    request: authentication_service_pb.LoginUserRequest,
    metadata: grpcWeb.Metadata | null): Promise<authentication_service_pb.LoginUserResponse>;

  login(
    request: authentication_service_pb.LoginUserRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: authentication_service_pb.LoginUserResponse) => void): grpcWeb.ClientReadableStream<authentication_service_pb.LoginUserResponse>;

  login(
    request: authentication_service_pb.LoginUserRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: authentication_service_pb.LoginUserResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.AuthenticationService/Login',
        request,
        metadata || {},
        this.methodDescriptorLogin,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.AuthenticationService/Login',
    request,
    metadata || {},
    this.methodDescriptorLogin);
  }

  methodDescriptorRefresh = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.AuthenticationService/Refresh',
    grpcWeb.MethodType.UNARY,
    authentication_service_pb.RefreshTokenRequest,
    authentication_service_pb.RefreshTokenResponse,
    (request: authentication_service_pb.RefreshTokenRequest) => {
      return request.serializeBinary();
    },
    authentication_service_pb.RefreshTokenResponse.deserializeBinary
  );

  refresh(
    request: authentication_service_pb.RefreshTokenRequest,
    metadata: grpcWeb.Metadata | null): Promise<authentication_service_pb.RefreshTokenResponse>;

  refresh(
    request: authentication_service_pb.RefreshTokenRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: authentication_service_pb.RefreshTokenResponse) => void): grpcWeb.ClientReadableStream<authentication_service_pb.RefreshTokenResponse>;

  refresh(
    request: authentication_service_pb.RefreshTokenRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: authentication_service_pb.RefreshTokenResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.AuthenticationService/Refresh',
        request,
        metadata || {},
        this.methodDescriptorRefresh,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.AuthenticationService/Refresh',
    request,
    metadata || {},
    this.methodDescriptorRefresh);
  }

}

