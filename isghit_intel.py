#!/usr/bin/env python -tt

import hashlib
import hmac
import httplib
import urllib
import re
import sys
import time
import json
import os
import email
from ConfigParser import ConfigParser
import argparse
from progressbar import ProgressBar
pbar = ProgressBar()
import jinja2 

class Query():

	def main_parameters(self):
		"""
		Main parameters for API connection 
		"""
		config = ConfigParser()
		config.read('config/config.ini')
		self.public_key = config.get('api', 'public_key')
		self.private_key = config.get('api', 'private_key')
		self.accept_version = config.get('api', 'accept_version')
		self.accept_header = config.get('api', 'accept_header')
		self.time_stamp = email.Utils.formatdate(localtime=True)
		self.custom_timers = {}
		

	def options(self):
		"""
		Main script options  
		"""
		self.parser = argparse.ArgumentParser(description='options for querying iSight intel')
		self.parser.add_argument('-q','--query', help='single query submission')
		self.parser.add_argument('-ql','--querylist', help='mass queries submission, through text files')
		args = self.parser.parse_args()
		self.query = args.query
		self.queries_file = args.querylist
		if len(sys.argv[1:])==0:
			self.parser.print_help()
			self.parser.exit()

	def query_prep(self):
		"""
		query preperation/extraction - output: set(query1, query2, .....)
		"""
		
		self.domain_regex = re.compile(r'^(?=.{4,255}$)([a-zA-Z0-9][a-zA-Z0-9-]{,61}[a-zA-Z0-9]\.)+[a-zA-Z0-9]{2,5}$')
		self.ip_regex = re.compile(r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
		self.md5_regex = re.compile(r"\b([a-f\d]{32}|[A-F\d]{32})\b")
		self.sha1_regex = re.compile(r"\b([a-f\d]{40}|[A-F\d]{40})\b")
		self.query_set = set()

		if self.query:
			if re.match(self.domain_regex ,self.query) or re.match(self.ip_regex ,self.query) or re.match(self.md5_regex, self.query) or re.match(self.sha1_regex, self.query):
				query_elems = [elem.replace(' ','') for elem in self.query.split(',')]
				for elem in query_elems:
					self.query_set.add(elem)
			else:
				print 'wrong domain or ip provided'
				exit(1)
		if self.queries_file:
			try:
				with open(self.queries_file) as f:
					lines = [line.rstrip() for line in f]

				for line in lines:
					if re.match(self.domain_regex,line) or re.match(self.ip_regex,line) or re.match(self.md5_regex,line) or re.match(self.sha1_regex, line):
						self.query_set.add(line)
			except:
				print 'Error opening the file'
				exit(1)

	def api_att(self):
		self.submission_dict = dict()
		for elem in self.query_set:
			if re.match(self.domain_regex, elem):
				enc_q = "/search/basic?domain={domain_name}".format(domain_name=elem)
			if re.match(self.ip_regex, elem):
				enc_q = "/search/basic?ip={ip}".format(ip=elem)
			if re.match(self.md5_regex, elem):
				enc_q = "/search/basic?md5={md5}".format(md5=elem)
			if re.match(self.sha1_regex, elem):
				enc_q = "/search/basic?sha1={sha1}".format(sha1=elem)
				
			domain_data = enc_q + self.accept_version + self.accept_header + self.time_stamp
			hashed = hmac.new(self.private_key, domain_data, hashlib.sha256)
			headers = {
			'Accept' : self.accept_header,
			'Accept-Version' : self.accept_version,
			'X-Auth' : self.public_key,
			'X-Auth-Hash' : hashed.hexdigest(),
			'Date'  :  self.time_stamp,
			}
			self.submission_dict[elem] = [enc_q, headers]

	def generic_submissions(self):
		self.results = {k: [] for k in self.submission_dict.keys()}
		conn = httplib.HTTPSConnection('api.isightpartners.com')
		if os.path.exists('log/error.log'):
			open('log/error.log', 'w').close()
		print 'Submitting queries to iSIGHT'
		for k, v in pbar(self.submission_dict.items()):
			conn.request('GET', self.submission_dict[k][0], '', self.submission_dict[k][1])
			try:
				resp = conn.getresponse()
				data = resp.read()
				data = json.loads(data)
				status = resp.status
				if status != 200:
					del self.submission_dict[k]
				else:
					for num in range(0,len(data['message'])):
						self.results[k].append(data['message'][num]['webLink'])
			except ValueError:
				f = open('log/error.log', 'a+')
				print >> f, '{0} , {1} , Decoding JSON has failed'.format(k,v)
				f.close()
		{self.results[k].append(len(v)) for k, v in self.results.items()}
		self.results = dict((k, v) for k, v in self.results.items() if len(v) > 1)

	def template(self):
		env = jinja2.Environment(loader=jinja2.FileSystemLoader(["./templates"]))
		template = env.get_template( "index.html")
		result = template.render( title="iSIGHT submission", results=self.results, )
		with open("output/results.html", "w+") as fc:
			fc.write(result) 


if __name__ == '__main__':
	isight = Query()
	isight.main_parameters()
	isight.options()
	isight.query_prep()
	isight.api_att()
	isight.generic_submissions()
	isight.template()
