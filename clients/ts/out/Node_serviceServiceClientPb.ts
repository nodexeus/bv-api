/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as node_service_pb from './node_service_pb';


export class NodeServiceClient {
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
    '/blockjoy.api.ui_v1.NodeService/Get',
    grpcWeb.MethodType.UNARY,
    node_service_pb.GetNodeRequest,
    node_service_pb.GetNodeResponse,
    (request: node_service_pb.GetNodeRequest) => {
      return request.serializeBinary();
    },
    node_service_pb.GetNodeResponse.deserializeBinary
  );

  get(
    request: node_service_pb.GetNodeRequest,
    metadata: grpcWeb.Metadata | null): Promise<node_service_pb.GetNodeResponse>;

  get(
    request: node_service_pb.GetNodeRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: node_service_pb.GetNodeResponse) => void): grpcWeb.ClientReadableStream<node_service_pb.GetNodeResponse>;

  get(
    request: node_service_pb.GetNodeRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: node_service_pb.GetNodeResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.NodeService/Get',
        request,
        metadata || {},
        this.methodDescriptorGet,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.NodeService/Get',
    request,
    metadata || {},
    this.methodDescriptorGet);
  }

  methodDescriptorCreate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.NodeService/Create',
    grpcWeb.MethodType.UNARY,
    node_service_pb.CreateNodeRequest,
    node_service_pb.CreateNodeResponse,
    (request: node_service_pb.CreateNodeRequest) => {
      return request.serializeBinary();
    },
    node_service_pb.CreateNodeResponse.deserializeBinary
  );

  create(
    request: node_service_pb.CreateNodeRequest,
    metadata: grpcWeb.Metadata | null): Promise<node_service_pb.CreateNodeResponse>;

  create(
    request: node_service_pb.CreateNodeRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: node_service_pb.CreateNodeResponse) => void): grpcWeb.ClientReadableStream<node_service_pb.CreateNodeResponse>;

  create(
    request: node_service_pb.CreateNodeRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: node_service_pb.CreateNodeResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.NodeService/Create',
        request,
        metadata || {},
        this.methodDescriptorCreate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.NodeService/Create',
    request,
    metadata || {},
    this.methodDescriptorCreate);
  }

  methodDescriptorUpdate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.NodeService/Update',
    grpcWeb.MethodType.UNARY,
    node_service_pb.UpdateNodeRequest,
    node_service_pb.UpdateNodeResponse,
    (request: node_service_pb.UpdateNodeRequest) => {
      return request.serializeBinary();
    },
    node_service_pb.UpdateNodeResponse.deserializeBinary
  );

  update(
    request: node_service_pb.UpdateNodeRequest,
    metadata: grpcWeb.Metadata | null): Promise<node_service_pb.UpdateNodeResponse>;

  update(
    request: node_service_pb.UpdateNodeRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: node_service_pb.UpdateNodeResponse) => void): grpcWeb.ClientReadableStream<node_service_pb.UpdateNodeResponse>;

  update(
    request: node_service_pb.UpdateNodeRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: node_service_pb.UpdateNodeResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.NodeService/Update',
        request,
        metadata || {},
        this.methodDescriptorUpdate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.NodeService/Update',
    request,
    metadata || {},
    this.methodDescriptorUpdate);
  }

}

