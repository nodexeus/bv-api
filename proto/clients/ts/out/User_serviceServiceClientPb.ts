/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as user_service_pb from './user_service_pb';


export class UserServiceClient {
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

  methodDescriptorGet = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.UserService/Get',
    grpcWeb.MethodType.UNARY,
    user_service_pb.GetUserRequest,
    user_service_pb.GetUserResponse,
    (request: user_service_pb.GetUserRequest) => {
      return request.serializeBinary();
    },
    user_service_pb.GetUserResponse.deserializeBinary
  );

  get(
    request: user_service_pb.GetUserRequest,
    metadata: grpcWeb.Metadata | null): Promise<user_service_pb.GetUserResponse>;

  get(
    request: user_service_pb.GetUserRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: user_service_pb.GetUserResponse) => void): grpcWeb.ClientReadableStream<user_service_pb.GetUserResponse>;

  get(
    request: user_service_pb.GetUserRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: user_service_pb.GetUserResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.UserService/Get',
        request,
        metadata || {},
        this.methodDescriptorGet,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.UserService/Get',
    request,
    metadata || {},
    this.methodDescriptorGet);
  }

  methodDescriptorCreate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.UserService/Create',
    grpcWeb.MethodType.UNARY,
    user_service_pb.CreateUserRequest,
    user_service_pb.CreateUserResponse,
    (request: user_service_pb.CreateUserRequest) => {
      return request.serializeBinary();
    },
    user_service_pb.CreateUserResponse.deserializeBinary
  );

  create(
    request: user_service_pb.CreateUserRequest,
    metadata: grpcWeb.Metadata | null): Promise<user_service_pb.CreateUserResponse>;

  create(
    request: user_service_pb.CreateUserRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: user_service_pb.CreateUserResponse) => void): grpcWeb.ClientReadableStream<user_service_pb.CreateUserResponse>;

  create(
    request: user_service_pb.CreateUserRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: user_service_pb.CreateUserResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.UserService/Create',
        request,
        metadata || {},
        this.methodDescriptorCreate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.UserService/Create',
    request,
    metadata || {},
    this.methodDescriptorCreate);
  }

  methodDescriptorUpsertConfiguration = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.UserService/UpsertConfiguration',
    grpcWeb.MethodType.UNARY,
    user_service_pb.UpsertConfigurationRequest,
    user_service_pb.UpsertConfigurationResponse,
    (request: user_service_pb.UpsertConfigurationRequest) => {
      return request.serializeBinary();
    },
    user_service_pb.UpsertConfigurationResponse.deserializeBinary
  );

  upsertConfiguration(
    request: user_service_pb.UpsertConfigurationRequest,
    metadata: grpcWeb.Metadata | null): Promise<user_service_pb.UpsertConfigurationResponse>;

  upsertConfiguration(
    request: user_service_pb.UpsertConfigurationRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: user_service_pb.UpsertConfigurationResponse) => void): grpcWeb.ClientReadableStream<user_service_pb.UpsertConfigurationResponse>;

  upsertConfiguration(
    request: user_service_pb.UpsertConfigurationRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: user_service_pb.UpsertConfigurationResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.UserService/UpsertConfiguration',
        request,
        metadata || {},
        this.methodDescriptorUpsertConfiguration,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.UserService/UpsertConfiguration',
    request,
    metadata || {},
    this.methodDescriptorUpsertConfiguration);
  }

  methodDescriptorGetConfiguration = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.UserService/GetConfiguration',
    grpcWeb.MethodType.UNARY,
    user_service_pb.GetConfigurationRequest,
    user_service_pb.GetConfigurationResponse,
    (request: user_service_pb.GetConfigurationRequest) => {
      return request.serializeBinary();
    },
    user_service_pb.GetConfigurationResponse.deserializeBinary
  );

  getConfiguration(
    request: user_service_pb.GetConfigurationRequest,
    metadata: grpcWeb.Metadata | null): Promise<user_service_pb.GetConfigurationResponse>;

  getConfiguration(
    request: user_service_pb.GetConfigurationRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: user_service_pb.GetConfigurationResponse) => void): grpcWeb.ClientReadableStream<user_service_pb.GetConfigurationResponse>;

  getConfiguration(
    request: user_service_pb.GetConfigurationRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: user_service_pb.GetConfigurationResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.UserService/GetConfiguration',
        request,
        metadata || {},
        this.methodDescriptorGetConfiguration,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.UserService/GetConfiguration',
    request,
    metadata || {},
    this.methodDescriptorGetConfiguration);
  }

}

