#!/usr/bin/python3

import xml.etree.ElementTree as ET
from logparser import rangeMapper
import status

class xmlOutputter:
	def __init__(self, conn, config):
		self.conn = conn
		self.root = ET.Element('result')
		self.html = '<html><head><meta charset="utf-8"><title>result</title><body><a href="#top10_name">top10_name</a><br><a href="#top10_source_ip">top10_source_ip</a><br><a href="#top10_destination_ip">top10_destination_ip</a><br><a href="#top10_destination_port">top10_destination_port</a><br><a href="#top10_action">top10_action</a><br><a href="#malicious_entry">malicious_entry</a><br>'
		self.config = config
		self.mapper = rangeMapper(self.config)
		self.timer = status.Timer()

	def top10_source_ip(self):
		self.timer.start('Producing top10_source_ip')
		top10_xml = ET.SubElement(self.root, 'top10_source_ip')
		top10_html = '<h1 id="top10_source_ip">top10_source_ip</h1><br><table border="1"><tr><td>rank</td><td>source_ip</td><td>sum</td><td>group</td></tr>'
		i = 0
		for row in self.conn.cursor().execute('SELECT source_ip, sum(aggregation) FROM syslog GROUP BY source_ip ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10_xml, 'source_ip', attrib={'rank': str(i), 'sum': str(row[1]), 'belongs': self.mapper.check(row[0])})
			top10_node.text = str(row[0])
			top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(i, row[0] + '<br>' + self.mapper.check(row[0]), row[1])
			top10_html += '<td><table border="1"><tr><td>rank</td><td>destination_ip</td><td>destination_port</td><td>action</td><td>total</td></tr>'
			for row2 in self.conn.cursor().execute('SELECT destination_ip, destination_port, action, sum(aggregation) FROM syslog WHERE source_ip=? GROUP BY destination_ip, destination_port, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'destination_ip', attrib={'belongs': self.mapper.check(row2[0])}).text = str(row2[0])
				ET.SubElement(group_node, 'destination_port').text = str(row2[1])
				ET.SubElement(group_node, 'action').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
				top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(j, row2[0] + '<br>' + self.mapper.check(row2[0]), row2[1], row2[2], row2[3])
			top10_html += '</table></td></tr>'
		top10_html += '</table><br>'
		self.html += top10_html
		self.timer.stop()

	def top10_destination_ip(self):
		self.timer.start('Producing top10_destination_ip')
		top10_xml = ET.SubElement(self.root, 'top10_destination_ip')
		top10_html = '<h1 id="top10_destination_ip">top10_destination_ip</h1><br><table border="1"><tr><td>rank</td><td>destination_ip</td><td>sum</td><td>group</td></tr>'
		i = 0
		for row in self.conn.cursor().execute('SELECT destination_ip, sum(aggregation) FROM syslog GROUP BY destination_ip ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10_xml, 'destination_ip', attrib={'rank': str(i), 'sum': str(row[1]), 'belongs': self.mapper.check(row[0])})
			top10_node.text = str(row[0])
			top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(i, row[0] + '<br>' + self.mapper.check(row[0]), row[1])
			top10_html += '<td><table border="1"><tr><td>rank</td><td>source_ip</td><td>destination_port</td><td>action</td><td>total</td></tr>'
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_port, action, sum(aggregation) FROM syslog WHERE destination_ip=? GROUP BY source_ip, destination_port, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip', attrib={'belongs': self.mapper.check(row2[0])}).text = str(row2[0])
				ET.SubElement(group_node, 'destination_port').text = str(row2[1])
				ET.SubElement(group_node, 'action').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
				top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(j, row2[0] + '<br>' + self.mapper.check(row2[0]), row2[1], row2[2], row2[3])
			top10_html += '</table></td></tr>'
		top10_html += '</table><br>'
		self.html += top10_html
		self.timer.stop()

	def top10_destination_port(self):
		self.timer.start('Producing top10_destination_port')
		top10_xml = ET.SubElement(self.root, 'top10_destination_port')
		top10_html = '<h1 id="top10_destination_port">top10_destination_port</h1><br><table border="1"><tr><td>rank</td><td>destination_port</td><td>sum</td><td>group</td></tr>'
		i = 0
		for row in self.conn.cursor().execute('SELECT destination_port, sum(aggregation) FROM syslog GROUP BY destination_port ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10_xml, 'destination_port', attrib={'rank': str(i), 'sum': str(row[1])})
			top10_node.text = str(row[0])
			top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(i, row[0], row[1])
			top10_html += '<td><table border="1"><tr><td>rank</td><td>source_ip</td><td>destination_ip</td><td>action</td><td>total</td></tr>'
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_ip, action, sum(aggregation) FROM syslog WHERE destination_port=? GROUP BY source_ip, destination_ip, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip', attrib={'belongs': self.mapper.check(row2[0])}).text = str(row2[0])
				ET.SubElement(group_node, 'destination_ip', attrib={'belongs': self.mapper.check(row2[1])}).text = str(row2[1])
				ET.SubElement(group_node, 'action').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
				top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(j, row2[0] + '<br>' + self.mapper.check(row2[0]), row2[1] + '<br>' + self.mapper.check(row2[1]), row2[2], row2[3])
			top10_html += '</table></td></tr>'
		top10_html += '</table><br>'
		self.html += top10_html
		self.timer.stop()

	def top10_action(self):
		self.timer.start('Producing top10_action')
		top10_xml = ET.SubElement(self.root, 'top10_action')
		top10_html = '<h1 id="top10_action">top10_action</h1><br><table border="1"><tr><td>rank</td><td>action</td><td>sum</td><td>group</td></tr>'
		i = 0
		for row in self.conn.cursor().execute('SELECT action, sum(aggregation) FROM syslog GROUP BY action ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10_xml, 'action', attrib={'rank': str(i), 'sum': str(row[1])})
			top10_node.text = str(row[0])
			top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(i, row[0], row[1])
			top10_html += '<td><table border="1"><tr><td>rank</td><td>source_ip</td><td>destination_ip</td><td>destination_port</td><td>total</td></tr>'
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_ip, destination_port, sum(aggregation) FROM syslog WHERE action=? GROUP BY source_ip, destination_ip, destination_port ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip', attrib={'belongs': self.mapper.check(row2[0])}).text = str(row2[0])
				ET.SubElement(group_node, 'destination_ip', attrib={'belongs': self.mapper.check(row2[1])}).text = str(row2[1])
				ET.SubElement(group_node, 'destination_port').text = str(row2[2])
				ET.SubElement(group_node, 'total').text = str(row2[3])
				top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(j, row2[0] + '<br>' + self.mapper.check(row2[0]), row2[1] + '<br>' + self.mapper.check(row2[1]), row2[2], row2[3])
			top10_html += '</table></td></tr>'
		top10_html += '</table><br>'
		self.html += top10_html
		self.timer.stop()

	def top10_name(self):
		self.timer.start('Producing top10_name')
		top10_xml = ET.SubElement(self.root, 'top10_name')
		top10_html = '<h1 id="top10_name">top10_name</h1><br><table border="1"><tr><td>rank</td><td>name</td><td>sum</td><td>group</td></tr>'
		i = 0
		for row in self.conn.cursor().execute('SELECT name, sum(aggregation) FROM syslog GROUP BY name ORDER BY sum(aggregation) DESC LIMIT 10'):
			j = 0
			i = i + 1
			top10_node = ET.SubElement(top10_xml, 'name', attrib={'rank': str(i), 'sum': str(row[1])})
			top10_node.text = str(row[0])
			top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td>'.format(i, row[0], row[1])
			top10_html += '<td><table border="1"><tr><td>rank</td><td>source_ip</td><td>destination_ip</td><td>destination_port</td><td>action</td><td>total</td></tr>'
			for row2 in self.conn.cursor().execute('SELECT source_ip, destination_ip, destination_port, action, sum(aggregation) FROM syslog WHERE name=? GROUP BY source_ip, destination_ip, destination_port, action ORDER BY sum(aggregation) DESC LIMIT 10', (row[0],)):
				j = j + 1
				group_node = ET.SubElement(top10_node, 'group', attrib={'rank': str(j)})
				ET.SubElement(group_node, 'source_ip', attrib={'belongs': self.mapper.check(row2[0])}).text = str(row2[0])
				ET.SubElement(group_node, 'destination_ip', attrib={'belongs': self.mapper.check(row2[1])}).text = str(row2[1])
				ET.SubElement(group_node, 'destination_port').text = str(row2[2])
				ET.SubElement(group_node, 'action').text = str(row2[3])
				ET.SubElement(group_node, 'total').text = str(row2[4])
				top10_html += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(j, row2[0] + '<br>' + self.mapper.check(row2[0]), row2[1] + '<br>' + self.mapper.check(row2[1]), row2[2], row2[3], row2[4])
			top10_html += '</table></td></tr>'
		top10_html += '</table><br>'
		self.html += top10_html
		self.timer.stop()

	def malicious_entry(self):
		self.timer.start('Producing malicious_entry')
		entry_xml = ET.SubElement(self.root, 'malicious_entry')
		entry_html = '<h1 id="malicious_entry">malicious_entry</h1><br><table border="1"><tr><td>index</td><td>name</td><td>source_ip</td><td>destination_ip</td><td>destination_port</td><td>action</td><td>aggregation</td><td>rawdata</td></tr>'
		i = 0
		for row in self.conn.cursor().execute('SELECT source_ip, destination_ip FROM syslog GROUP BY source_ip, destination_ip'):
			if self.mapper.malicious_check(row[0]) or self.mapper.malicious_check(row[1]):
				for row2 in self.conn.cursor().execute('SELECT * FROM syslog WHERE source_ip=? AND destination_ip=?', row):
					i = i + 1
					group_node = ET.SubElement(entry_xml, 'group', attrib={'index': str(i)})
					ET.SubElement(group_node, 'name').text = str(row2[2])
					source_node = ET.SubElement(group_node, 'source_ip')
					source_node.text = str(row2[3])
					source_node.set('belongs', self.mapper.check(row2[3]))
					destination_node = ET.SubElement(group_node, 'destination_ip')
					destination_node.text = str(row2[4])
					destination_node.set('belongs', self.mapper.check(row2[4]))
					ET.SubElement(group_node, 'destination_port').text = str(row2[5])
					ET.SubElement(group_node, 'action').text = str(row2[6])
					ET.SubElement(group_node, 'aggregation').text = str(row2[7])
					with open(row2[0], mode='r', errors='ignore', encoding='utf-8') as logfile:
						actual_number = row2[1] - 1
						for number, line in enumerate(logfile):
							if number == actual_number:
								rawdata = line.rstrip()
								break
					ET.SubElement(group_node, 'rawdata').text = rawdata
					entry_html += '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(i, row2[2], row2[3] + '<br>' + self.mapper.check(row2[3]), row2[4] + '<br>' + self.mapper.check(row2[4]), row2[5], row2[6], row2[7], rawdata)
		entry_html += '</table><br>'
		self.html += entry_html
		self.timer.stop()

	def write(self):
		self.top10_source_ip()
		self.top10_destination_ip()
		self.top10_destination_port()
		self.top10_action()
		self.top10_name()
		if self.config.getboolean('OUTPUT', 'malicious_entry'):
			self.malicious_entry()
		ET.ElementTree(self.root).write(self.config['OUTPUT']['xml'], encoding='UTF-8')
		self.html += '</body></html>'
		with open(self.config['OUTPUT']['html'], mode='w', encoding='utf-8') as html:
			html.write(self.html)
