"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.NodeServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var node_service_pb = require("./node_service_pb");
var NodeServiceClient = /** @class */ (function () {
    function NodeServiceClient(hostname, credentials, options) {
        this.methodDescriptorGet = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.NodeService/Get', grpcWeb.MethodType.UNARY, node_service_pb.GetNodeRequest, node_service_pb.GetNodeResponse, function (request) {
            return request.serializeBinary();
        }, node_service_pb.GetNodeResponse.deserializeBinary);
        this.methodDescriptorCreate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.NodeService/Create', grpcWeb.MethodType.UNARY, node_service_pb.CreateNodeRequest, node_service_pb.CreateNodeResponse, function (request) {
            return request.serializeBinary();
        }, node_service_pb.CreateNodeResponse.deserializeBinary);
        this.methodDescriptorUpdate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.NodeService/Update', grpcWeb.MethodType.UNARY, node_service_pb.UpdateNodeRequest, node_service_pb.UpdateNodeResponse, function (request) {
            return request.serializeBinary();
        }, node_service_pb.UpdateNodeResponse.deserializeBinary);
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
    NodeServiceClient.prototype.get = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.NodeService/Get', request, metadata || {}, this.methodDescriptorGet, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.NodeService/Get', request, metadata || {}, this.methodDescriptorGet);
    };
    NodeServiceClient.prototype.create = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.NodeService/Create', request, metadata || {}, this.methodDescriptorCreate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.NodeService/Create', request, metadata || {}, this.methodDescriptorCreate);
    };
    NodeServiceClient.prototype.update = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.NodeService/Update', request, metadata || {}, this.methodDescriptorUpdate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.NodeService/Update', request, metadata || {}, this.methodDescriptorUpdate);
    };
    return NodeServiceClient;
}());
exports.NodeServiceClient = NodeServiceClient;
