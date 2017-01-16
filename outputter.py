#!/usr/bin/python3

import linecache
import xml.etree.ElementTree as ET
from logparser import rangeMapper
import status

class xmlOutputter:
	def __init__(self, conn, config):
		self.conn = conn
		self.root = ET.Element('result')
		self.config = config
		self.mapper = rangeMapper(self.config)
		self.timer = status.Timer()

	def top10_source_ip(self):
		self.timer.start('Producing top10_source_ip')
		top10 = ET.SubElement(self.root, 'top10_source_ip')
		i = 0
		for row in self.conn.cursor().execute('SELECT source_ip, sum(aggregation) FROM syslog GROUP BY source_ip ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10, 'source_ip', attrib={'rank': str(i)})
			top10_node.text = str(row[0])
			for row2 in self.conn.cursor().execute('SELECT destination_ip, destination_port, action, sum(aggregation) FROM syslog WHERE source_ip=? GROUP BY destination_ip, destination_port, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'destination_ip').text = str(row2[0])
				ET.SubElement(group_node, 'destination_port').text = str(row2[1])
				ET.SubElement(group_node, 'action').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
		self.timer.stop()

	def top10_destination_ip(self):
		self.timer.start('Producing top10_destination_ip')
		top10 = ET.SubElement(self.root, 'top10_destination_ip')
		i = 0
		for row in self.conn.cursor().execute('SELECT destination_ip, sum(aggregation) FROM syslog GROUP BY destination_ip ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10, 'destination_ip', attrib={'rank': str(i)})
			top10_node.text = str(row[0])
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_port, action, sum(aggregation) FROM syslog WHERE destination_ip=? GROUP BY source_ip, destination_port, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip').text = str(row2[0])
				ET.SubElement(group_node, 'destination_port').text = str(row2[1])
				ET.SubElement(group_node, 'action').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
		self.timer.stop()

	def top10_destination_port(self):
		self.timer.start('Producing top10_destination_port')
		top10 = ET.SubElement(self.root, 'top10_destination_port')
		i = 0
		for row in self.conn.cursor().execute('SELECT destination_port, sum(aggregation) FROM syslog GROUP BY destination_port ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10, 'destination_port', attrib={'rank': str(i)})
			top10_node.text = str(row[0])
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_ip, action, sum(aggregation) FROM syslog WHERE destination_port=? GROUP BY source_ip, destination_ip, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip').text = str(row2[0])
				ET.SubElement(group_node, 'destination_ip').text = str(row2[1])
				ET.SubElement(group_node, 'action').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
		self.timer.stop()

	def top10_action(self):
		self.timer.start('Producing top10_action')
		top10 = ET.SubElement(self.root, 'top10_action')
		i = 0
		for row in self.conn.cursor().execute('SELECT action, sum(aggregation) FROM syslog GROUP BY action ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10, 'action', attrib={'rank': str(i)})
			top10_node.text = str(row[0])
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_ip, destination_port, sum(aggregation) FROM syslog WHERE action=? GROUP BY source_ip, destination_ip, destination_port ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip').text = str(row2[0])
				ET.SubElement(group_node, 'destination_ip').text = str(row2[1])
				ET.SubElement(group_node, 'destination_port').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
		self.timer.stop()

	def top10_name(self):
		self.timer.start('Producing top10_name')
		top10 = ET.SubElement(self.root, 'top10_name')
		i = 0
		for row in self.conn.cursor().execute('SELECT name, sum(aggregation) FROM syslog GROUP BY name ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10, 'name', attrib={'rank': str(i)})
			top10_node.text = str(row[0])
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_ip, destination_port, action, sum(aggregation) FROM syslog WHERE name=? GROUP BY source_ip, destination_ip, destination_port, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip').text = str(row2[0])
				ET.SubElement(group_node, 'destination_ip').text = str(row2[1])
				ET.SubElement(group_node, 'destination_port').text = str(row2[2])
				ET.SubElement(group_node, 'action').text = str(row2[3])
				ET.SubElement(group_node, 'total').text = str(row2[4])
		self.timer.stop()

	def malicious_entry(self):
		self.timer.start('Producing malicious_entry')
		entry = ET.SubElement(self.root, 'malicious_entry')
		i = 0
		for row in self.conn.cursor().execute('SELECT source_ip, destination_ip FROM syslog GROUP BY source_ip, destination_ip'):
			if self.mapper.client_check(row[0]):
				source_malicious_name = None
			else:
				source_malicious_name = self.mapper.malicious_check(row[0])
			if self.mapper.client_check(row[1]):
				destination_malicious_name = None
			else:
				destination_malicious_name = self.mapper.malicious_check(row[1])
			if source_malicious_name or destination_malicious_name:
				for row2 in self.conn.cursor().execute('SELECT * FROM syslog WHERE source_ip=? AND destination_ip=?', row):
					i = i + 1
					group_node = ET.SubElement(entry, 'group', attrib={'index': str(i)})
					ET.SubElement(group_node, 'name').text = str(row2[2])
					source_node = ET.SubElement(group_node, 'src_ip')
					source_node.text = str(row2[3])
					if source_malicious_name: source_node.set('belongs', source_malicious_name)
					destination_node = ET.SubElement(group_node, 'dst_ip')
					destination_node.text = str(row2[4])
					if destination_malicious_name: destination_node.set('belongs', destination_malicious_name)
					ET.SubElement(group_node, 'destination_port').text = str(row2[5])
					ET.SubElement(group_node, 'action').text = str(row2[6])
					ET.SubElement(group_node, 'aggregation').text = str(row2[7])
					ET.SubElement(group_node, 'rawdata').text = linecache.getline(row2[0], row2[1]).rstrip()
		self.timer.stop()

	def map_top10_belongs(self):
		self.timer.start('Mapping the corresponding name to each IP')
		for ip in self.root.iter('source_ip'):
			mapper_name = self.mapper.check(ip.text)
			if mapper_name: ip.set('belongs', mapper_name)
		for ip in self.root.iter('destination_ip'):
			mapper_name = self.mapper.check(ip.text)
			if mapper_name: ip.set('belongs', mapper_name)
		self.timer.stop()

	def write(self):
		self.top10_source_ip()
		self.top10_destination_ip()
		self.top10_destination_port()
		self.top10_action()
		self.top10_name()
		self.map_top10_belongs()
		if self.config.getboolean('OUTPUT', 'malicious_entry'):
			self.malicious_entry()
		ET.ElementTree(self.root).write(self.config['OUTPUT']['xml'], encoding='UTF-8')
