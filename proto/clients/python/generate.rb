#!/usr/bin/env ruby

protos = Dir.glob('../../blockjoy/api/ui_v1/**/*.proto').collect do |f|
    File.basename f
end.join(' ')

`protoc -I=../../blockjoy/api/ui_v1 #{protos} --python_out=./py_out`
