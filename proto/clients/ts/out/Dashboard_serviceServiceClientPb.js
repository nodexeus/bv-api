"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.DashboardServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var dashboard_service_pb = require("./dashboard_service_pb");
var DashboardServiceClient = /** @class */ (function () {
    function DashboardServiceClient(hostname, credentials, options) {
        this.methodDescriptorKPIs = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.DashboardService/KPIs', grpcWeb.MethodType.UNARY, dashboard_service_pb.DashboardKpiRequest, dashboard_service_pb.DashboardKpiResponse, function (request) {
            return request.serializeBinary();
        }, dashboard_service_pb.DashboardKpiResponse.deserializeBinary);
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
    DashboardServiceClient.prototype.kPIs = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.DashboardService/KPIs', request, metadata || {}, this.methodDescriptorKPIs, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.DashboardService/KPIs', request, metadata || {}, this.methodDescriptorKPIs);
    };
    return DashboardServiceClient;
}());
exports.DashboardServiceClient = DashboardServiceClient;
