#!/usr/bin/env ruby

protos = Dir.glob('../../blockjoy/api/ui_v1/**/*.proto').collect do |f|
    File.basename f
end.join(' ')

`grpc_tools_ruby_protoc -I=../../blockjoy/api/ui_v1 #{protos} --ruby_out=./rb_out --grpc_out=./rb_out`
