"use strict";
/**
 * @fileoverview gRPC-Web generated client stub for blockjoy.api.ui_v1
 * @enhanceable
 * @public
 */
exports.__esModule = true;
exports.AuthenticationServiceClient = void 0;
// GENERATED CODE -- DO NOT EDIT!
/* eslint-disable */
// @ts-nocheck
var grpcWeb = require("grpc-web");
var authentication_service_pb = require("./authentication_service_pb");
var AuthenticationServiceClient = /** @class */ (function () {
    function AuthenticationServiceClient(hostname, credentials, options) {
        this.methodDescriptorLogin = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.AuthenticationService/Login', grpcWeb.MethodType.UNARY, authentication_service_pb.LoginUserRequest, authentication_service_pb.LoginUserResponse, function (request) {
            return request.serializeBinary();
        }, authentication_service_pb.LoginUserResponse.deserializeBinary);
        this.methodDescriptorRefresh = new grpcWeb.MethodDescriptor('/blockjoy.api.ui_v1.AuthenticationService/Refresh', grpcWeb.MethodType.UNARY, authentication_service_pb.RefreshTokenRequest, authentication_service_pb.RefreshTokenResponse, function (request) {
            return request.serializeBinary();
        }, authentication_service_pb.RefreshTokenResponse.deserializeBinary);
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
    AuthenticationServiceClient.prototype.login = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.AuthenticationService/Login', request, metadata || {}, this.methodDescriptorLogin, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.AuthenticationService/Login', request, metadata || {}, this.methodDescriptorLogin);
    };
    AuthenticationServiceClient.prototype.refresh = function (request, metadata, callback) {
        if (callback !== undefined) {
            return this.client_.rpcCall(this.hostname_ +
                '/blockjoy.api.ui_v1.AuthenticationService/Refresh', request, metadata || {}, this.methodDescriptorRefresh, callback);
        }
        return this.client_.unaryCall(this.hostname_ +
            '/blockjoy.api.ui_v1.AuthenticationService/Refresh', request, metadata || {}, this.methodDescriptorRefresh);
    };
    return AuthenticationServiceClient;
}());
exports.AuthenticationServiceClient = AuthenticationServiceClient;
