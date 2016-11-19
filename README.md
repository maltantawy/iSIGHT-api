# isight-api
Script to query iSIGHT partners intelligence through API quires, the results are rendered in html format

```
Main operation 
```

The scipt accpets either single queries or mass queries through text files. The main inputs for the script are IPs, domains, MD5s and SHA. 

```
Options
```
Two options are available, either single queries (-q) or mass quries (-ql).There is no restrictions on the data types in teh files. The data can be a particular type or different types. So it can actually contains collection of IPS, md5s and domains. The only one caveate is that, each line should have only one element.  


usage: isghit_intel.py [-h] [-q QUERY] [-ql QUERYLIST]

options for querying iSight intel

optional arguments:
  -h, --help            show this help message and exit
  -q QUERY, --query QUERY
                        single query submission
  -ql QUERYLIST, --querylist QUERYLIST
                        mass queries submission, through text files
                        
```
Configuration
```
The follwoing directives have to be configured before running the script, the configuration file path is: cofig/config.ini

[api]
public_key =<PUBLIC KEY> 
private_key =<PRIVATE KY>
accept_version = 2.3
accept_header = application/json





