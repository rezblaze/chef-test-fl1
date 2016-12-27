#
# Cookbook Name:: postgresql
# Recipe:: default
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

package 'postgrsql-server' do
	action :install
	notifies :run, 'execute[postgresql-init]'
end

execute 'posgresql-init' do
	command 'postgresql-setup initdb'
	action :nothing
end

service 'postgresql-setup initdb' do
	action [:enable, :start]
end


