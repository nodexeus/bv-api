/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as dashboard_service_pb from './dashboard_service_pb';


export class DashboardServiceClient {
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

  methodDescriptorKPIs = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.DashboardService/KPIs',
    grpcWeb.MethodType.UNARY,
    dashboard_service_pb.DashboardKpiRequest,
    dashboard_service_pb.DashboardKpiResponse,
    (request: dashboard_service_pb.DashboardKpiRequest) => {
      return request.serializeBinary();
    },
    dashboard_service_pb.DashboardKpiResponse.deserializeBinary
  );

  kPIs(
    request: dashboard_service_pb.DashboardKpiRequest,
    metadata: grpcWeb.Metadata | null): Promise<dashboard_service_pb.DashboardKpiResponse>;

  kPIs(
    request: dashboard_service_pb.DashboardKpiRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: dashboard_service_pb.DashboardKpiResponse) => void): grpcWeb.ClientReadableStream<dashboard_service_pb.DashboardKpiResponse>;

  kPIs(
    request: dashboard_service_pb.DashboardKpiRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: dashboard_service_pb.DashboardKpiResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.DashboardService/KPIs',
        request,
        metadata || {},
        this.methodDescriptorKPIs,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.DashboardService/KPIs',
    request,
    metadata || {},
    this.methodDescriptorKPIs);
  }

}

