# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: user_service.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import common_pb2 as common__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x12user_service.proto\x12\x12\x62lockjoy.api.ui_v1\x1a\x0c\x63ommon.proto\"?\n\x0eGetUserRequest\x12-\n\x04meta\x18\x01 \x01(\x0b\x32\x1f.blockjoy.api.ui_v1.RequestMeta\"i\n\x0fGetUserResponse\x12.\n\x04meta\x18\x01 \x01(\x0b\x32 .blockjoy.api.ui_v1.ResponseMeta\x12&\n\x04user\x18\x02 \x01(\x0b\x32\x18.blockjoy.api.ui_v1.User\"\x9b\x01\n\x11\x43reateUserRequest\x12-\n\x04meta\x18\x01 \x01(\x0b\x32\x1f.blockjoy.api.ui_v1.RequestMeta\x12&\n\x04user\x18\x02 \x01(\x0b\x32\x18.blockjoy.api.ui_v1.User\x12\x10\n\x08password\x18\x03 \x01(\t\x12\x1d\n\x15password_confirmation\x18\x04 \x01(\t\"D\n\x12\x43reateUserResponse\x12.\n\x04meta\x18\x01 \x01(\x0b\x32 .blockjoy.api.ui_v1.ResponseMeta\"\xb6\x01\n\x1aUpsertConfigurationRequest\x12-\n\x04meta\x18\x01 \x01(\x0b\x32\x1f.blockjoy.api.ui_v1.RequestMeta\x12)\n\x07user_id\x18\x02 \x01(\x0b\x32\x18.blockjoy.api.ui_v1.Uuid\x12>\n\x06params\x18\x03 \x03(\x0b\x32..blockjoy.api.ui_v1.UserConfigurationParameter\"M\n\x1bUpsertConfigurationResponse\x12.\n\x04meta\x18\x01 \x01(\x0b\x32 .blockjoy.api.ui_v1.ResponseMeta\"s\n\x17GetConfigurationRequest\x12-\n\x04meta\x18\x01 \x01(\x0b\x32\x1f.blockjoy.api.ui_v1.RequestMeta\x12)\n\x07user_id\x18\x02 \x01(\x0b\x32\x18.blockjoy.api.ui_v1.Uuid\"\x8a\x01\n\x18GetConfigurationResponse\x12.\n\x04meta\x18\x01 \x01(\x0b\x32 .blockjoy.api.ui_v1.ResponseMeta\x12>\n\x06params\x18\x02 \x03(\x0b\x32..blockjoy.api.ui_v1.UserConfigurationParameter2\xa5\x03\n\x0bUserService\x12P\n\x03Get\x12\".blockjoy.api.ui_v1.GetUserRequest\x1a#.blockjoy.api.ui_v1.GetUserResponse\"\x00\x12Y\n\x06\x43reate\x12%.blockjoy.api.ui_v1.CreateUserRequest\x1a&.blockjoy.api.ui_v1.CreateUserResponse\"\x00\x12x\n\x13UpsertConfiguration\x12..blockjoy.api.ui_v1.UpsertConfigurationRequest\x1a/.blockjoy.api.ui_v1.UpsertConfigurationResponse\"\x00\x12o\n\x10GetConfiguration\x12+.blockjoy.api.ui_v1.GetConfigurationRequest\x1a,.blockjoy.api.ui_v1.GetConfigurationResponse\"\x00\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'user_service_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _GETUSERREQUEST._serialized_start=56
  _GETUSERREQUEST._serialized_end=119
  _GETUSERRESPONSE._serialized_start=121
  _GETUSERRESPONSE._serialized_end=226
  _CREATEUSERREQUEST._serialized_start=229
  _CREATEUSERREQUEST._serialized_end=384
  _CREATEUSERRESPONSE._serialized_start=386
  _CREATEUSERRESPONSE._serialized_end=454
  _UPSERTCONFIGURATIONREQUEST._serialized_start=457
  _UPSERTCONFIGURATIONREQUEST._serialized_end=639
  _UPSERTCONFIGURATIONRESPONSE._serialized_start=641
  _UPSERTCONFIGURATIONRESPONSE._serialized_end=718
  _GETCONFIGURATIONREQUEST._serialized_start=720
  _GETCONFIGURATIONREQUEST._serialized_end=835
  _GETCONFIGURATIONRESPONSE._serialized_start=838
  _GETCONFIGURATIONRESPONSE._serialized_end=976
  _USERSERVICE._serialized_start=979
  _USERSERVICE._serialized_end=1400
# @@protoc_insertion_point(module_scope)
