#!/usr/bin/python3

import sqlite3, re, configparser, csv, argparse
import logparser, outputter, status
from collections import OrderedDict

arg_parser = argparse.ArgumentParser(description='pyLogStatistic')
arg_parser.add_argument('FILE', help='a list of files', nargs='+')
args = arg_parser.parse_args()

config = configparser.ConfigParser()
config.read('settings.conf', encoding='utf-8')

timer = status.Timer()

conn = sqlite3.connect(config['OUTPUT']['db'])
conn.cursor().execute('''CREATE TABLE IF NOT EXISTS syslog (filename text, line_number numeric, name text, source_ip text, destination_ip text, destination_port numeric, action text, aggregation numeric)''')

if config['DEFAULT']['log_type'] == 'syslog':
	syslog_parser = logparser.syslogParser(config)
	for filename in args.FILE:
		timer.start('Processing ' + filename)
		i = 0
		with open(filename, mode='r', errors='ignore', encoding='utf-8') as logfile:
			for line in logfile:
				i = i + 1
				name = syslog_parser.name_re.search(line)
				source_ip = syslog_parser.source_ip_re.search(line)
				destination_ip = syslog_parser.destination_ip_re.search(line)
				destination_port = syslog_parser.destination_port_re.search(line)
				action = syslog_parser.action_re.search(line)
				if name and syslog_parser.ip_validate(source_ip) and syslog_parser.ip_validate(destination_ip) and destination_port and action:
					entry = (filename, i, name.group(1), source_ip.group(1), destination_ip.group(1), destination_port.group(1), action.group(1), 1)
					conn.cursor().execute('INSERT INTO syslog VALUES (?, ?, ?, ?, ?, ?, ?, ?)', entry)
		timer.stop()
elif config['DEFAULT']['log_type'] == 'csv':
	csv_formatter = logparser.csvFormatter(config)
	for filename in args.FILE:
		timer.start('Processing ' + filename)
		i = 1
		with open(filename, mode='r', errors='ignore', encoding='utf-8') as logfile:
			reader = csv.DictReader(logfile, delimiter=csv_formatter.delimiter)
			for row in reader:
				i = i + 1
				if row[csv_formatter.name_name] and csv_formatter.ip_validate(row[csv_formatter.source_ip_name]) and csv_formatter.ip_validate(row[csv_formatter.destination_ip_name]) and row[csv_formatter.destination_port_name] and row[csv_formatter.action_name]:
					entry = (filename, i, row[csv_formatter.name_name], row[csv_formatter.source_ip_name], row[csv_formatter.destination_ip_name], row[csv_formatter.destination_port_name], row[csv_formatter.action_name], row[csv_formatter.aggregation_name] if hasattr(csv_formatter, 'aggregation_name') else 1)
					conn.cursor().execute('INSERT INTO syslog VALUES (?, ?, ?, ?, ?, ?, ?, ?)', entry)
		timer.stop()

conn.commit()
result = outputter.xmlOutputter(conn, config)
result.write()
conn.close()
