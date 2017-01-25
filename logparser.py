#!/usr/bin/python3

import re, ipaddress, csv

class syslogParser:
	def __init__(self, config):
		delimiter = config['DEFAULT']['delimiter']

		name_name = config['SYSLOG']['name']
		source_ip_name = config['SYSLOG']['source_ip']
		destination_ip_name = config['SYSLOG']['destination_ip']
		destination_port_name = config['SYSLOG']['destination_port']
		action_name = config['SYSLOG']['action']

		self.name_re = re.compile(name_name + '=(.*?)[$' + delimiter + ']')
		self.source_ip_re = re.compile(source_ip_name + '=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[$' + delimiter + ']')
		self.destination_ip_re = re.compile(destination_ip_name + '=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[$' + delimiter + ']')
		self.destination_port_re = re.compile(destination_port_name + '=([0-9]{1,5})[$' + delimiter + ']')
		self.action_re = re.compile(action_name + '=([a-zA-Z]*?)[$' + delimiter + ']')

class csvFormatter:
	def __init__(self, config):
		self.delimiter = config['DEFAULT']['delimiter']	
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
		self.processed_client_ip = dict()
		if config.has_option('DEFAULT', 'input_malicious_ip'):
			with open(config['DEFAULT']['input_malicious_ip'], mode='r', encoding='utf-8') as malicious_ip:
				malicious_csv = csv.DictReader(malicious_ip, delimiter=',')
				for line in malicious_csv:
					self.malicious_ip_range.append(line['DN/IP-List'])
		if config.has_option('DEFAULT', 'input_client_ip'):
			with open(config['DEFAULT']['input_client_ip'], mode='r', encoding='utf-8') as client_ip:
				for line in client_ip:
					line = line.rstrip()
					name, network = line.split(':')
					self.client_ip_range.append(tuple(network.split('~')) + (name,))

	def check(self, ip):
		client_result = self.client_check(ip)
		if client_result:
			return client_result
		else:
			return self.malicious_check(ip)

	def client_check(self, ip):
		if ip not in self.processed_client_ip:
			self.processed_client_ip[ip] = None
			for ip_range in self.client_ip_range:
				if ipaddress.IPv4Address(ip_range[0]) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(ip_range[1]):
					self.processed_client_ip[ip] = ip_range[2]
					break
		return self.processed_client_ip[ip]

	def malicious_check(self, ip):
		if ip in self.malicious_ip_range:
			return 'ICST & Hinet Malicious List'
		else:
			return None
