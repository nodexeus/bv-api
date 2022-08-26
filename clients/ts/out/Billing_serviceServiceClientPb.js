"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.BillingServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var billing_service_pb = require("./billing_service_pb");
var BillingServiceClient = /** @class */ (function () {
    function BillingServiceClient(hostname, credentials, options) {
        this.methodDescriptorCreate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.BillingService/Create', grpcWeb.MethodType.UNARY, billing_service_pb.CreateBillRequest, billing_service_pb.CreateBillResponse, function (request) {
            return request.serializeBinary();
        }, billing_service_pb.CreateBillResponse.deserializeBinary);
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
    BillingServiceClient.prototype.create = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.BillingService/Create', request, metadata || {}, this.methodDescriptorCreate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.BillingService/Create', request, metadata || {}, this.methodDescriptorCreate);
    };
    return BillingServiceClient;
}());
exports.BillingServiceClient = BillingServiceClient;
