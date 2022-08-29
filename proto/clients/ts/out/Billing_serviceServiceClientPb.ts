/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as billing_service_pb from './billing_service_pb';


export class BillingServiceClient {
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

  methodDescriptorCreate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.BillingService/Create',
    grpcWeb.MethodType.UNARY,
    billing_service_pb.CreateBillRequest,
    billing_service_pb.CreateBillResponse,
    (request: billing_service_pb.CreateBillRequest) => {
      return request.serializeBinary();
    },
    billing_service_pb.CreateBillResponse.deserializeBinary
  );

  create(
    request: billing_service_pb.CreateBillRequest,
    metadata: grpcWeb.Metadata | null): Promise<billing_service_pb.CreateBillResponse>;

  create(
    request: billing_service_pb.CreateBillRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: billing_service_pb.CreateBillResponse) => void): grpcWeb.ClientReadableStream<billing_service_pb.CreateBillResponse>;

  create(
    request: billing_service_pb.CreateBillRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: billing_service_pb.CreateBillResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.BillingService/Create',
        request,
        metadata || {},
        this.methodDescriptorCreate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.BillingService/Create',
    request,
    metadata || {},
    this.methodDescriptorCreate);
  }

}

