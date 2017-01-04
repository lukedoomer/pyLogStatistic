# pyLogStatistic
a python log statistic tool

## configuration
pyLogStatistic supports two types of log.
### syslog type
	datetime=1900/01/01 00:00:01,name=traffic,srcip=192.168.0.1,dstip=192.168.0.254,dstport=8888,action=deny
### csv type
	datetime,name,srcip,dstip,dstport,action,aggregation
	1900/01/01 00:00:01,traffic,192.168.0.1,192.168.0.254,8888,deny,100
Please edit settings.conf to suits your needs.  
if you provide input_malicious_ip or input_client_ip, each IP will be mapped to its corresponding name via <belongs> tag.  
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
