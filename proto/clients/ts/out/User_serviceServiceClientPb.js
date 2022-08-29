"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.UserServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var user_service_pb = require("./user_service_pb");
var UserServiceClient = /** @class */ (function () {
    function UserServiceClient(hostname, credentials, options) {
        this.methodDescriptorGet = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.UserService/Get', grpcWeb.MethodType.UNARY, user_service_pb.GetUserRequest, user_service_pb.GetUserResponse, function (request) {
            return request.serializeBinary();
        }, user_service_pb.GetUserResponse.deserializeBinary);
        this.methodDescriptorCreate = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.UserService/Create', grpcWeb.MethodType.UNARY, user_service_pb.CreateUserRequest, user_service_pb.CreateUserResponse, function (request) {
            return request.serializeBinary();
        }, user_service_pb.CreateUserResponse.deserializeBinary);
        this.methodDescriptorUpsertConfiguration = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.UserService/UpsertConfiguration', grpcWeb.MethodType.UNARY, user_service_pb.UpsertConfigurationRequest, user_service_pb.UpsertConfigurationResponse, function (request) {
            return request.serializeBinary();
        }, user_service_pb.UpsertConfigurationResponse.deserializeBinary);
        this.methodDescriptorGetConfiguration = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.UserService/GetConfiguration', grpcWeb.MethodType.UNARY, user_service_pb.GetConfigurationRequest, user_service_pb.GetConfigurationResponse, function (request) {
            return request.serializeBinary();
        }, user_service_pb.GetConfigurationResponse.deserializeBinary);
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
    UserServiceClient.prototype.get = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.UserService/Get', request, metadata || {}, this.methodDescriptorGet, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.UserService/Get', request, metadata || {}, this.methodDescriptorGet);
    };
    UserServiceClient.prototype.create = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.UserService/Create', request, metadata || {}, this.methodDescriptorCreate, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.UserService/Create', request, metadata || {}, this.methodDescriptorCreate);
    };
    UserServiceClient.prototype.upsertConfiguration = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.UserService/UpsertConfiguration', request, metadata || {}, this.methodDescriptorUpsertConfiguration, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.UserService/UpsertConfiguration', request, metadata || {}, this.methodDescriptorUpsertConfiguration);
    };
    UserServiceClient.prototype.getConfiguration = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.UserService/GetConfiguration', request, metadata || {}, this.methodDescriptorGetConfiguration, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.UserService/GetConfiguration', request, metadata || {}, this.methodDescriptorGetConfiguration);
    };
    return UserServiceClient;
}());
exports.UserServiceClient = UserServiceClient;
