#!/usr/bin/env ruby

protos = Dir.glob('../../blockjoy/api/ui_v1/**/*.proto').collect do |f|
    File.basename f
end.join(' ')

`protoc -I=../../blockjoy/api/ui_v1 #{protos} --js_out=import_style=commonjs,binary:./out --grpc-web_out=import_style=typescript,mode=grpcwebtext:./out`
