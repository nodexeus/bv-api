"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.HostServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var fe_host_service_pb = require("./fe_host_service_pb");
var HostServiceClient = /** @class */ (function () {
    function HostServiceClient(hostname, credentials, options) {
        this.methodDescriptorGet = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.HostService/Get', grpcWeb.MethodType.UNARY, fe_host_service_pb.GetHostsRequest, fe_host_service_pb.GetHostsResponse, function (request) {
            return request.serializeBinary();
        }, fe_host_service_pb.GetHostsResponse.deserializeBinary);
        this.methodDescriptorCreate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.HostService/Create', grpcWeb.MethodType.UNARY, fe_host_service_pb.CreateHostRequest, fe_host_service_pb.CreateHostResponse, function (request) {
            return request.serializeBinary();
        }, fe_host_service_pb.CreateHostResponse.deserializeBinary);
        this.methodDescriptorUpdate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.HostService/Update', grpcWeb.MethodType.UNARY, fe_host_service_pb.UpdateHostRequest, fe_host_service_pb.UpdateHostResponse, function (request) {
            return request.serializeBinary();
        }, fe_host_service_pb.UpdateHostResponse.deserializeBinary);
        this.methodDescriptorDelete = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.HostService/Delete', grpcWeb.MethodType.UNARY, fe_host_service_pb.DeleteHostRequest, fe_host_service_pb.DeleteHostResponse, function (request) {
            return request.serializeBinary();
        }, fe_host_service_pb.DeleteHostResponse.deserializeBinary);
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
    HostServiceClient.prototype.get = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.HostService/Get', request, metadata || {}, this.methodDescriptorGet, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.HostService/Get', request, metadata || {}, this.methodDescriptorGet);
    };
    HostServiceClient.prototype.create = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.HostService/Create', request, metadata || {}, this.methodDescriptorCreate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.HostService/Create', request, metadata || {}, this.methodDescriptorCreate);
    };
    HostServiceClient.prototype.update = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.HostService/Update', request, metadata || {}, this.methodDescriptorUpdate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.HostService/Update', request, metadata || {}, this.methodDescriptorUpdate);
    };
    HostServiceClient.prototype["delete"] = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.HostService/Delete', request, metadata || {}, this.methodDescriptorDelete, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.HostService/Delete', request, metadata || {}, this.methodDescriptorDelete);
    };
    return HostServiceClient;
}());
exports.HostServiceClient = HostServiceClient;
