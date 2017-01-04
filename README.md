# pyLogStatistic
a python log statistic tool

## configuration
pyLogStatistic support two types of log.
### syslog type
	datetime=1900/01/01 00:00:01,srcip=192.168.0.1,dstip=192.168.0.254,..
### csv type
	datetime,srcip,dstip,..
	1900/01/01 00:00:01,192.168.0.1,192.168.0.254,..
Please edit settings.conf to suits your needs.  
Also, you MUST specify every single column name in settings.conf

## usage
	./main.py LOGFILE1 LOGFILE2 ..

Eventually you will get a sqlite DB contains of all log entries
and a XML-formatted result file including various top10 statistics.  
1. top10_name  
2. top10_source_ip  
3. top10_destination_ip  
4. top10_destination_port  
5. top10_action  
