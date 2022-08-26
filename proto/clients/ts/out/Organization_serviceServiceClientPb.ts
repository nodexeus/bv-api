/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */

// GENERATED CODE -- DO NOT EDIT!


/* eslint-disable */
// @ts-nocheck


import * as grpcWeb from 'grpc-web';

import * as organization_service_pb from './organization_service_pb';


export class OrganizationServiceClient {
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
    '/blockjoy.api.ui_v1.OrganizationService/Get',
    grpcWeb.MethodType.UNARY,
    organization_service_pb.GetOrganizationsRequest,
    organization_service_pb.GetOrganizationsResponse,
    (request: organization_service_pb.GetOrganizationsRequest) => {
      return request.serializeBinary();
    },
    organization_service_pb.GetOrganizationsResponse.deserializeBinary
  );

  get(
    request: organization_service_pb.GetOrganizationsRequest,
    metadata: grpcWeb.Metadata | null): Promise<organization_service_pb.GetOrganizationsResponse>;

  get(
    request: organization_service_pb.GetOrganizationsRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: organization_service_pb.GetOrganizationsResponse) => void): grpcWeb.ClientReadableStream<organization_service_pb.GetOrganizationsResponse>;

  get(
    request: organization_service_pb.GetOrganizationsRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: organization_service_pb.GetOrganizationsResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.OrganizationService/Get',
        request,
        metadata || {},
        this.methodDescriptorGet,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.OrganizationService/Get',
    request,
    metadata || {},
    this.methodDescriptorGet);
  }

  methodDescriptorCreate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.OrganizationService/Create',
    grpcWeb.MethodType.UNARY,
    organization_service_pb.CreateOrganizationRequest,
    organization_service_pb.CreateOrganizationResponse,
    (request: organization_service_pb.CreateOrganizationRequest) => {
      return request.serializeBinary();
    },
    organization_service_pb.CreateOrganizationResponse.deserializeBinary
  );

  create(
    request: organization_service_pb.CreateOrganizationRequest,
    metadata: grpcWeb.Metadata | null): Promise<organization_service_pb.CreateOrganizationResponse>;

  create(
    request: organization_service_pb.CreateOrganizationRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: organization_service_pb.CreateOrganizationResponse) => void): grpcWeb.ClientReadableStream<organization_service_pb.CreateOrganizationResponse>;

  create(
    request: organization_service_pb.CreateOrganizationRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: organization_service_pb.CreateOrganizationResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.OrganizationService/Create',
        request,
        metadata || {},
        this.methodDescriptorCreate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.OrganizationService/Create',
    request,
    metadata || {},
    this.methodDescriptorCreate);
  }

  methodDescriptorUpdate = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.OrganizationService/Update',
    grpcWeb.MethodType.UNARY,
    organization_service_pb.UpdateOrganizationRequest,
    organization_service_pb.UpdateOrganizationResponse,
    (request: organization_service_pb.UpdateOrganizationRequest) => {
      return request.serializeBinary();
    },
    organization_service_pb.UpdateOrganizationResponse.deserializeBinary
  );

  update(
    request: organization_service_pb.UpdateOrganizationRequest,
    metadata: grpcWeb.Metadata | null): Promise<organization_service_pb.UpdateOrganizationResponse>;

  update(
    request: organization_service_pb.UpdateOrganizationRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: organization_service_pb.UpdateOrganizationResponse) => void): grpcWeb.ClientReadableStream<organization_service_pb.UpdateOrganizationResponse>;

  update(
    request: organization_service_pb.UpdateOrganizationRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: organization_service_pb.UpdateOrganizationResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.OrganizationService/Update',
        request,
        metadata || {},
        this.methodDescriptorUpdate,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.OrganizationService/Update',
    request,
    metadata || {},
    this.methodDescriptorUpdate);
  }

  methodDescriptorDelete = new grpcWeb.MethodDescriptor(
    '/blockjoy.api.ui_v1.OrganizationService/Delete',
    grpcWeb.MethodType.UNARY,
    organization_service_pb.DeleteOrganizationRequest,
    organization_service_pb.DeleteOrganizationResponse,
    (request: organization_service_pb.DeleteOrganizationRequest) => {
      return request.serializeBinary();
    },
    organization_service_pb.DeleteOrganizationResponse.deserializeBinary
  );

  delete(
    request: organization_service_pb.DeleteOrganizationRequest,
    metadata: grpcWeb.Metadata | null): Promise<organization_service_pb.DeleteOrganizationResponse>;

  delete(
    request: organization_service_pb.DeleteOrganizationRequest,
    metadata: grpcWeb.Metadata | null,
    callback: (err: grpcWeb.RpcError,
               response: organization_service_pb.DeleteOrganizationResponse) => void): grpcWeb.ClientReadableStream<organization_service_pb.DeleteOrganizationResponse>;

  delete(
    request: organization_service_pb.DeleteOrganizationRequest,
    metadata: grpcWeb.Metadata | null,
    callback?: (err: grpcWeb.RpcError,
               response: organization_service_pb.DeleteOrganizationResponse) => void) {
    if (callback !== undefined) {
      return this.client_.rpcCall(
        this.hostname_ +
          '/blockjoy.api.ui_v1.OrganizationService/Delete',
        request,
        metadata || {},
        this.methodDescriptorDelete,
        callback);
    }
    return this.client_.unaryCall(
    this.hostname_ +
      '/blockjoy.api.ui_v1.OrganizationService/Delete',
    request,
    metadata || {},
    this.methodDescriptorDelete);
  }

}

