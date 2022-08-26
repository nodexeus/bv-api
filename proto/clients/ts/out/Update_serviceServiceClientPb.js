"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.UpdateServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var update_service_pb = require("./update_service_pb");
var UpdateServiceClient = /** @class */ (function () {
    function UpdateServiceClient(hostname, credentials, options) {
        this.methodDescriptorUpdates = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.UpdateService/Updates', grpcWeb.MethodType.SERVER_STREAMING, update_service_pb.GetUpdatesRequest, update_service_pb.GetUpdatesResponse, function (request) {
            return request.serializeBinary();
        }, update_service_pb.GetUpdatesResponse.deserializeBinary);
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
    UpdateServiceClient.prototype.updates = function (request, metadata) {
        return this.client_.serverStreaming(this.hostname_ +
            '/blockjoy.api.ui_v1.UpdateService/Updates', request, metadata || {}, this.methodDescriptorUpdates);
    };
    return UpdateServiceClient;
}());
exports.UpdateServiceClient = UpdateServiceClient;
