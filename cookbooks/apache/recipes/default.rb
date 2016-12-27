#
# Cookbook Name:: apache
# Recipe:: default
#
# Copyright (c) 2016 The Authors, All Rights Reserved.

if node['platform_fmaily'] == "rhel"
	package = "httpd"
elsif node['platform_fmaily'] == "debian"
	package = "apache2"	
end

package 'apache2' do
	package_name 'httpd'
	action :install
end

service 'apache2' do
	service_name 'httpd'
	action [:start, :enable]
end

#include_recipe 'apache::websites'
