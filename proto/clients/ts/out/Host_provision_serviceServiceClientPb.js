"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.HostProvisionServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var host_provision_service_pb = require("./host_provision_service_pb");
var HostProvisionServiceClient = /** @class */ (function () {
    function HostProvisionServiceClient(hostname, credentials, options) {
        this.methodDescriptorGet = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.HostProvisionService/Get', grpcWeb.MethodType.UNARY, host_provision_service_pb.GetHostProvisionRequest, host_provision_service_pb.GetHostProvisionResponse, function (request) {
            return request.serializeBinary();
        }, host_provision_service_pb.GetHostProvisionResponse.deserializeBinary);
        this.methodDescriptorCreate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.HostProvisionService/Create', grpcWeb.MethodType.UNARY, host_provision_service_pb.CreateHostProvisionRequest, host_provision_service_pb.CreateHostProvisionResponse, function (request) {
            return request.serializeBinary();
        }, host_provision_service_pb.CreateHostProvisionResponse.deserializeBinary);
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
    HostProvisionServiceClient.prototype.get = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.HostProvisionService/Get', request, metadata || {}, this.methodDescriptorGet, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.HostProvisionService/Get', request, metadata || {}, this.methodDescriptorGet);
    };
    HostProvisionServiceClient.prototype.create = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.HostProvisionService/Create', request, metadata || {}, this.methodDescriptorCreate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.HostProvisionService/Create', request, metadata || {}, this.methodDescriptorCreate);
    };
    return HostProvisionServiceClient;
}());
exports.HostProvisionServiceClient = HostProvisionServiceClient;
