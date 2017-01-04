#!/usr/bin/python3

import re, ipaddress

class syslogParser:
	def __init__(self, config):
		delimiter = config['DEFAULT']['delimiter']

		datetime_name = config['SYSLOG']['datetime']
		name_name = config['SYSLOG']['name']
		source_ip_name = config['SYSLOG']['source_ip']
		destination_ip_name = config['SYSLOG']['destination_ip']
		destination_port_name = config['SYSLOG']['destination_port']
		action_name = config['SYSLOG']['action']

		self.datetime_re = re.compile(datetime_name + '=(.*?)[$' + delimiter + ']')
		self.name_re = re.compile(name_name + '=(.*?)[$' + delimiter + ']')
		self.source_ip_re = re.compile(source_ip_name + '=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[$' + delimiter + ']')
		self.destination_ip_re = re.compile(destination_ip_name + '=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[$' + delimiter + ']')
		self.destination_port_re = re.compile(destination_port_name + '=([0-9]{1,5})[$' + delimiter + ']')
		self.action_re = re.compile(action_name + '=([a-zA-Z]*?)[$' + delimiter + ']')

class csvFormatter:
	def __init__(self, config):
		self.delimiter = config['DEFAULT']['delimiter']	
		self.datetime_name = config['CSV']['datetime']
		self.name_name = config['CSV']['name']
		self.source_ip_name = config['CSV']['source_ip']
		self.destination_ip_name = config['CSV']['destination_ip']
		self.destination_port_name = config['CSV']['destination_port']
		self.action_name = config['CSV']['action']
		if config.has_option('CSV', 'aggregation'):
			self.aggregation_name = config['CSV']['aggregation']

class rangeMapper:
	def __init__(self, config):
		self.malicious_ip_range = list()
		self.client_ip_range = list()
		if config.has_option('DEFAULT', 'input_malicious_ip'):
			with open(config['DEFAULT']['input_malicious_ip'], 'r') as malicious_ip:
				for line in malicious_ip:
					line = line.rstrip()
					try:
						name, network = line.split(':')
					except ValueError:
						continue
					self.malicious_ip_range.append(tuple(network.split('-')) + (name,))
		if config.has_option('DEFAULT', 'input_client_ip'):
			with open(config['DEFAULT']['input_client_ip'], 'r') as client_ip:
				for line in client_ip:
					line = line.rstrip()
					name, network = line.split(':')
					self.client_ip_range.append(tuple(network.split('-')) + (name,))
		self.all_ip_range = self.malicious_ip_range + self.client_ip_range

	def check(self, ip):
		for ip_range in self.all_ip_range:
			if ipaddress.IPv4Address(ip_range[0]) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(ip_range[1]):
				return ip_range[2]
		return None

	def malicious_check(self, ip):
		if self.malicious_ip_range:
			for ip_range in self.malicious_ip_range:
				if ipaddress.IPv4Address(ip_range[0]) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(ip_range[1]):
					return ip_range[2]
		return None
