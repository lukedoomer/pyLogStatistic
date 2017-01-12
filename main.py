#!/usr/bin/python3

import sqlite3, re, configparser, csv, argparse
import logparser, outputter
from collections import OrderedDict

arg_parser = argparse.ArgumentParser(description='pyLogStatistic')
arg_parser.add_argument('FILE', help='a list of files', nargs='+')
args = arg_parser.parse_args()

config = configparser.ConfigParser()
config.read('settings.conf')

conn = sqlite3.connect(config['OUTPUT']['db'])
conn.cursor().execute('''CREATE TABLE IF NOT EXISTS syslog (datetime text, name text, source_ip text, destination_ip text, destination_port numeric, action text, aggregation numeric)''')

for filename in args.FILE:
	if config['DEFAULT']['log_type'] == 'syslog':
		syslog_parser = logparser.syslogParser(config)
		with open(filename, mode='r', errors='ignore', encoding='utf-8') as logfile:
			for line in logfile:
				datetime = syslog_parser.datetime_re.search(line)
				name = syslog_parser.name_re.search(line)
				source_ip = syslog_parser.source_ip_re.search(line)
				destination_ip = syslog_parser.destination_ip_re.search(line)
				destination_port = syslog_parser.destination_port_re.search(line)
				action = syslog_parser.action_re.search(line)
				if datetime and name and source_ip and destination_ip and destination_port and action:
					entry = (datetime.group(1), name.group(1), source_ip.group(1), destination_ip.group(1), destination_port.group(1), action.group(1), 1)
					conn.cursor().execute('INSERT INTO syslog VALUES (?, ?, ?, ?, ?, ?, ?)', entry)
	elif config['DEFAULT']['log_type'] == 'csv':
		csv_formatter = logparser.csvFormatter(config)
		with open(filename, mode='r', encoding='utf-8') as logfile:
			reader = csv.DictReader(logfile, delimiter=csv_formatter.delimiter)
			for row in reader:
					entry = (row[csv_formatter.datetime_name], row[csv_formatter.name_name], row[csv_formatter.source_ip_name], row[csv_formatter.destination_ip_name], row[csv_formatter.destination_port_name], row[csv_formatter.action_name], row[csv_formatter.aggregation_name] if csv_formatter.aggregation_name else 1)
					conn.cursor().execute('INSERT INTO syslog VALUES (?, ?, ?, ?, ?, ?, ?)', entry)

conn.commit()
result = outputter.xmlOutputter(conn, config)
result.write()
conn.close()
