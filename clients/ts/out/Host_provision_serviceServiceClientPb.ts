/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as host_provision_service_pb from './host_provision_service_pb';


export class HostProvisionServiceClient {
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
    '/blockjoy.api.ui_v1.HostProvisionService/Get',
    grpcWeb.MethodType.UNARY,
    host_provision_service_pb.GetHostProvisionRequest,
    host_provision_service_pb.GetHostProvisionResponse,
    (request: host_provision_service_pb.GetHostProvisionRequest) => {
      return request.serializeBinary();
    },
    host_provision_service_pb.GetHostProvisionResponse.deserializeBinary
  );

  get(
    request: host_provision_service_pb.GetHostProvisionRequest,
    metadata: grpcWeb.Metadata | null): Promise<host_provision_service_pb.GetHostProvisionResponse>;

  get(
    request: host_provision_service_pb.GetHostProvisionRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: host_provision_service_pb.GetHostProvisionResponse) => void): grpcWeb.ClientReadableStream<host_provision_service_pb.GetHostProvisionResponse>;

  get(
    request: host_provision_service_pb.GetHostProvisionRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: host_provision_service_pb.GetHostProvisionResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.HostProvisionService/Get',
        request,
        metadata || {},
        this.methodDescriptorGet,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.HostProvisionService/Get',
    request,
    metadata || {},
    this.methodDescriptorGet);
  }

  methodDescriptorCreate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.HostProvisionService/Create',
    grpcWeb.MethodType.UNARY,
    host_provision_service_pb.CreateHostProvisionRequest,
    host_provision_service_pb.CreateHostProvisionResponse,
    (request: host_provision_service_pb.CreateHostProvisionRequest) => {
      return request.serializeBinary();
    },
    host_provision_service_pb.CreateHostProvisionResponse.deserializeBinary
  );

  create(
    request: host_provision_service_pb.CreateHostProvisionRequest,
    metadata: grpcWeb.Metadata | null): Promise<host_provision_service_pb.CreateHostProvisionResponse>;

  create(
    request: host_provision_service_pb.CreateHostProvisionRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: host_provision_service_pb.CreateHostProvisionResponse) => void): grpcWeb.ClientReadableStream<host_provision_service_pb.CreateHostProvisionResponse>;

  create(
    request: host_provision_service_pb.CreateHostProvisionRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: host_provision_service_pb.CreateHostProvisionResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.HostProvisionService/Create',
        request,
        metadata || {},
        this.methodDescriptorCreate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.HostProvisionService/Create',
    request,
    metadata || {},
    this.methodDescriptorCreate);
  }

}

