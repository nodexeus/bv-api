/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as fe_host_service_pb from './fe_host_service_pb';


export class HostServiceClient {
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
    '/blockjoy.api.ui_v1.HostService/Get',
    grpcWeb.MethodType.UNARY,
    fe_host_service_pb.GetHostsRequest,
    fe_host_service_pb.GetHostsResponse,
    (request: fe_host_service_pb.GetHostsRequest) => {
      return request.serializeBinary();
    },
    fe_host_service_pb.GetHostsResponse.deserializeBinary
  );

  get(
    request: fe_host_service_pb.GetHostsRequest,
    metadata: grpcWeb.Metadata | null): Promise<fe_host_service_pb.GetHostsResponse>;

  get(
    request: fe_host_service_pb.GetHostsRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.GetHostsResponse) => void): grpcWeb.ClientReadableStream<fe_host_service_pb.GetHostsResponse>;

  get(
    request: fe_host_service_pb.GetHostsRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.GetHostsResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.HostService/Get',
        request,
        metadata || {},
        this.methodDescriptorGet,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.HostService/Get',
    request,
    metadata || {},
    this.methodDescriptorGet);
  }

  methodDescriptorCreate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.HostService/Create',
    grpcWeb.MethodType.UNARY,
    fe_host_service_pb.CreateHostRequest,
    fe_host_service_pb.CreateHostResponse,
    (request: fe_host_service_pb.CreateHostRequest) => {
      return request.serializeBinary();
    },
    fe_host_service_pb.CreateHostResponse.deserializeBinary
  );

  create(
    request: fe_host_service_pb.CreateHostRequest,
    metadata: grpcWeb.Metadata | null): Promise<fe_host_service_pb.CreateHostResponse>;

  create(
    request: fe_host_service_pb.CreateHostRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.CreateHostResponse) => void): grpcWeb.ClientReadableStream<fe_host_service_pb.CreateHostResponse>;

  create(
    request: fe_host_service_pb.CreateHostRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.CreateHostResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.HostService/Create',
        request,
        metadata || {},
        this.methodDescriptorCreate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.HostService/Create',
    request,
    metadata || {},
    this.methodDescriptorCreate);
  }

  methodDescriptorUpdate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.HostService/Update',
    grpcWeb.MethodType.UNARY,
    fe_host_service_pb.UpdateHostRequest,
    fe_host_service_pb.UpdateHostResponse,
    (request: fe_host_service_pb.UpdateHostRequest) => {
      return request.serializeBinary();
    },
    fe_host_service_pb.UpdateHostResponse.deserializeBinary
  );

  update(
    request: fe_host_service_pb.UpdateHostRequest,
    metadata: grpcWeb.Metadata | null): Promise<fe_host_service_pb.UpdateHostResponse>;

  update(
    request: fe_host_service_pb.UpdateHostRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.UpdateHostResponse) => void): grpcWeb.ClientReadableStream<fe_host_service_pb.UpdateHostResponse>;

  update(
    request: fe_host_service_pb.UpdateHostRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.UpdateHostResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.HostService/Update',
        request,
        metadata || {},
        this.methodDescriptorUpdate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.HostService/Update',
    request,
    metadata || {},
    this.methodDescriptorUpdate);
  }

  methodDescriptorDelete = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.HostService/Delete',
    grpcWeb.MethodType.UNARY,
    fe_host_service_pb.DeleteHostRequest,
    fe_host_service_pb.DeleteHostResponse,
    (request: fe_host_service_pb.DeleteHostRequest) => {
      return request.serializeBinary();
    },
    fe_host_service_pb.DeleteHostResponse.deserializeBinary
  );

  delete(
    request: fe_host_service_pb.DeleteHostRequest,
    metadata: grpcWeb.Metadata | null): Promise<fe_host_service_pb.DeleteHostResponse>;

  delete(
    request: fe_host_service_pb.DeleteHostRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.DeleteHostResponse) => void): grpcWeb.ClientReadableStream<fe_host_service_pb.DeleteHostResponse>;

  delete(
    request: fe_host_service_pb.DeleteHostRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: fe_host_service_pb.DeleteHostResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.HostService/Delete',
        request,
        metadata || {},
        this.methodDescriptorDelete,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.HostService/Delete',
    request,
    metadata || {},
    this.methodDescriptorDelete);
  }

}

