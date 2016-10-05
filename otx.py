import requests
from MaltegoTransform import *
import json
import sys
import math
import datetime
import re

base_url = 'https://otx.alienvault.com/api/v1/indicators/'
pulse_url = 'https://otx.alienvault.com/api/v1/pulses/'
headers = {'X-OTX-API-KEY':'<INSERT API KEY HERE>'}

me = MaltegoTransform()
me.parseArguments(sys.argv)

# Parse arguments
entity = sys.argv[2]
section = sys.argv[1]
entity_type = sys.argv[3]

# Determine entity type to use in API calls
if 'pulseid' in entity_type:
	entity_type = entity_type
elif 'ipaddress' in entity_type:
	entity_type = 'IPv4'
elif 'fqdn' in entity_type:
	# Check if it's a hostname or domain name
	if re.match(r'.*\..*\..*', entity_type.split("=")[1]):
		entity_type='hostname'
	else:
		entity_type='domain'
elif 'hash' in entity_type:
	entity_type = 'file'
elif 'URL' in entity_type:
	entity_type = 'url'
else:
	entity_type = entity_type

def adddatefield_indicators(indicator):
	dt = datetime.datetime.strptime(str(indicator['created']),'%Y-%m-%dT%H:%M:%S.%f')
	ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt.date()))

if section == 'indicators':
	pulse_id = entity_type.split('#')[0].split('=')[1]
	r = requests.get(pulse_url+pulse_id+'/indicators', headers=headers)
	response = r.json()
	for indicator in response['results']:
		if indicator['type'] == 'IPv4':
			ent = me.addEntity("maltego.IPv4Address",indicator['indicator'])
		if indicator['type'] == 'domain':
			ent = me.addEntity("maltego.Domain",indicator['indicator'])
		if indicator['type'] == 'URL':
			ent = me.addEntity("maltego.URL",indicator['indicator'])
		if indicator['type'] == 'FileHash-MD5':
			ent = me.addEntity("maltego.Hash",indicator['indicator'])
		if indicator['type'] == 'FileHash-SHA1':
			ent = me.addEntity("maltego.Hash",indicator['indicator'])
		if indicator['type'] == 'hostname':
			ent = me.addEntity("maltego.DNSName",indicator['indicator'])
		else:
			ent = me.addEntity("maltego.unknown",indicator['indicator'])
		adddatefield_indicators(indicator)

if section == 'analysis':
	try:
		r = requests.get(base_url+entity_type+'/'+entity+'/analysis', headers=headers)
		response = r.json()
		ent = me.addEntity("otx.OTXPulse",str(response['analysis']['info']['results']['md5']))
		ent.addAdditionalFields('Website', 'Website','','https://otx.alienvault.com/indicator/file/'+str(response['analysis']['info']['results']['md5']))
		dt = datetime.datetime.strptime(str(response['analysis']['datetime_int']),'%Y-%m-%dT%H:%M:%S')
		ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt.date()))
	except:
		pass

if section == 'pulses':
	try:
		r = requests.get(base_url+entity_type+'/'+entity+'/general', headers=headers)
		response = r.json()
		for pulse in response['pulse_info']['pulses']:
			ent = me.addEntity("otx.OTXPulse",str(pulse['name']))
			ent.addAdditionalFields('Website', 'Website','','https://otx.alienvault.com/pulse/'+str(pulse['id']))
			dt = datetime.datetime.strptime(str(pulse['modified']),'%Y-%m-%dT%H:%M:%S.%f')
			ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt.date()))
			ent.addAdditionalFields('pulseid','pulseid','',str(pulse['id']))
	except:
		pass

if section == 'geo':
	r = requests.get(base_url+entity_type+'/'+entity+'/geo', headers=headers)
	response = r.json()
	if response == {}:
		pass
	else:
		asn = response.get('asn')
		region = response.get('region')
		country_name = response.get('country_name')
		ent = me.addEntity("maltego.Location",str(asn) + '\n' + str(region) + str(country_name))
		ent.addAdditionalFields('link#maltego.link.label','Label','',' ')

if section == 'malware':
	try:
		r = requests.get(base_url+entity_type+'/'+entity+'/malware', headers=headers)
		response = r.json()
		for sample in response['data']:
			ent = me.addEntity("maltego.Hash",sample['hash'])
			dt = datetime.datetime.fromtimestamp(float(str(sample['datetime_int']))).strftime('%Y-%m-%d')
			ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt))
	except:
		pass

if section == 'url_list':
	try:
		r = requests.get(base_url+entity_type+'/'+entity+'/url_list', headers=headers)
		response = r.json()
		records = response['full_size']
		pages = int(records) / 10.0
		pages = math.ceil(float(pages))
		current_page = 1
		while current_page <= int(pages):
			params = {'page':str(current_page)}
			r = requests.get(base_url+entity_type+'/'+entity+'/url_list', headers=headers, params=params)
			response = r.json()
			current_page += 1
			ent = me.addEntity("maltego.URL",response['url_list'][0]['url'])
			ent.addAdditionalFields('url','URL','',str(response['url_list'][0]['url']))
			dt = datetime.datetime.strptime(str(response['url_list'][0]['date']),'%Y-%m-%dT%H:%M:%S')
			ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt.date()))
	except:
		pass

if section == 'domain_list':
	try:
		r = requests.get(base_url+entity_type+'/'+entity+'/url_list', headers=headers)
		response = r.json()
		records = response['full_size']
		pages = int(records) / 10.0
		pages = math.ceil(float(pages))
		current_page = 1
		while current_page <= int(pages):
			params = {'page':str(current_page)}
			r = requests.get(base_url+entity_type+'/'+entity+'/url_list', headers=headers, params=params)
			response = r.json()
			current_page += 1
			ent = me.addEntity("maltego.Domain",response['url_list'][0]['domain'])
			dt = datetime.datetime.strptime(str(response['url_list'][0]['date']),'%Y-%m-%dT%H:%M:%S.%f')
			ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt.date()))
	except:
		pass

if section == 'passive_dns':
	try:
		r = requests.get(base_url+entity_type+'/'+entity+'/passive_dns', headers=headers)
		response = r.json()
		for domain in response['passive_dns']:
			ent = me.addEntity("maltego.Domain",domain['hostname'])
			dt = datetime.datetime.strptime(str(domain['last']),'%Y-%m-%d %H:%M:%S')
			ent.addAdditionalFields('link#maltego.link.label','Label','',str(dt.date()))
	except:
		pass

me.returnOutput()
