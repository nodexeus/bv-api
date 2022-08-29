"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.OrganizationServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var organization_service_pb = require("./organization_service_pb");
var OrganizationServiceClient = /** @class */ (function () {
    function OrganizationServiceClient(hostname, credentials, options) {
        this.methodDescriptorGet = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.OrganizationService/Get', grpcWeb.MethodType.UNARY, organization_service_pb.GetOrganizationsRequest, organization_service_pb.GetOrganizationsResponse, function (request) {
            return request.serializeBinary();
        }, organization_service_pb.GetOrganizationsResponse.deserializeBinary);
        this.methodDescriptorCreate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.OrganizationService/Create', grpcWeb.MethodType.UNARY, organization_service_pb.CreateOrganizationRequest, organization_service_pb.CreateOrganizationResponse, function (request) {
            return request.serializeBinary();
        }, organization_service_pb.CreateOrganizationResponse.deserializeBinary);
        this.methodDescriptorUpdate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.OrganizationService/Update', grpcWeb.MethodType.UNARY, organization_service_pb.UpdateOrganizationRequest, organization_service_pb.UpdateOrganizationResponse, function (request) {
            return request.serializeBinary();
        }, organization_service_pb.UpdateOrganizationResponse.deserializeBinary);
        this.methodDescriptorDelete = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.OrganizationService/Delete', grpcWeb.MethodType.UNARY, organization_service_pb.DeleteOrganizationRequest, organization_service_pb.DeleteOrganizationResponse, function (request) {
            return request.serializeBinary();
        }, organization_service_pb.DeleteOrganizationResponse.deserializeBinary);
        if (!options)
            options = {};
        if (!credentials)
            credentials = {};
        options['format'] = 'text';
        this.client_ = new grpcWeb.GrpcWebClientBase(options);
        this.hostname_ = hostname;
        this.credentials_ = credentials;
        this.options_ = options;
    }
    OrganizationServiceClient.prototype.get = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.OrganizationService/Get', request, metadata || {}, this.methodDescriptorGet, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.OrganizationService/Get', request, metadata || {}, this.methodDescriptorGet);
    };
    OrganizationServiceClient.prototype.create = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.OrganizationService/Create', request, metadata || {}, this.methodDescriptorCreate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.OrganizationService/Create', request, metadata || {}, this.methodDescriptorCreate);
    };
    OrganizationServiceClient.prototype.update = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.OrganizationService/Update', request, metadata || {}, this.methodDescriptorUpdate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.OrganizationService/Update', request, metadata || {}, this.methodDescriptorUpdate);
    };
    OrganizationServiceClient.prototype["delete"] = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.OrganizationService/Delete', request, metadata || {}, this.methodDescriptorDelete, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.OrganizationService/Delete', request, metadata || {}, this.methodDescriptorDelete);
    };
    return OrganizationServiceClient;
}());
exports.OrganizationServiceClient = OrganizationServiceClient;
