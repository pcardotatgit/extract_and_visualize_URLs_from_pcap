# -*- coding: UTF-8 -*-
import os
import sys
import argparse
import re
import datetime
import subprocess
import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
from dpkt.compat import compat_ord
import struct
import socket
import csv
import json

output =[]

def ip_to_str(address):
    return socket.inet_ntoa(address)

def rdpcap(trace):
	for timestamp, buf in pcap:
		time = str(datetime.datetime.utcfromtimestamp(timestamp))
		print ('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
		eth = dpkt.ethernet.Ethernet(buf)
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			continue
		ip = eth.data
		do_not_fragment = bool(dpkt.ip.IP_DF)
		more_fragments = bool(dpkt.ip.IP_MF)
		fragment_offset = bool(dpkt.ip.IP_OFFMASK)
		Source = "%s" % ip_to_str(ip.src)
		Destination = "%s" % ip_to_str(ip.dst)
		Length = "%d" % (ip.len)
		TTL = "%d" % (ip.ttl)
		OFF = ip.off
		TOS = ip.tos
		Protocol = ip.p
		donnee = ip.data
		data = ( time , Source, Destination, Length, TTL, TOS, OFF, Protocol,donnee)
		#print(Source) 
		#print(Destination)
		c.writerow(data)

def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)	
	
def _parser(texte,a,mots1:list,mots2:list,parse_first_line,colomn:list):
	#a separator
	# mots1 list of words to find in the line we want to keep
	# mots2 list of words to not find in the line we want to keep. if one wor is found then the line is not kept	
	# colomn  colomns to keep  if =[0]  keep all colomns
	#start if the line begins with with this word then start to keep lines  until the end word is found
	#parse_first_line = 1 if we want to parse the first kept line  and = 0 if we don't want
	lignes = texte.split('\n')
	resultat=[]
	for ligne in lignes:
		if parse_first_line ==1:
			if mots1[0] != 'ALLWORDS':
				OK=0
				for x in mots1:
					if x in ligne:
						OK=1
			else:
				OK=1					
			for x in mots2:
				if x in ligne:
					OK=0	
			if OK:
				i1=1
				while i1 != 0:		
					ligne=ligne.replace('  ',' ')
					if ligne.find("  ") >= 0:
						ligne=ligne.replace("  "," ")
						i1=1
					else :
						i1=0				
				tableau=ligne.split(a)
				i2=1
				line_out = ''
				for x in tableau:
					x=x.strip()
					if i2 in colomn:
						OK2=1
					else:
						OK2=0
					if colomn[0] == 0:
						OK2=1
					if x !='' and OK2:
						# REMPLACEMENT de CARACTERES DEBUT
						x=x.replace('"','')
						x=x.replace(',','')
						# REMPLACEMENT de CARACTERES FIN
						line_out = line_out + x 
						# pour debug
						#line_out = line_out + '(** ' + str(i2) + ' **);'
					i2=i2+1
				#print ("=====")	
			resultat.append(line_out)
	return(resultat)	
		
def main():
	pcap_dir="traces" # directory where are located pcap traces
	# Affichage du help
	# parser.print_help()
	c = csv.writer(open("resulting_pcap.csv", "w"))
	if not os.path.isdir(pcap_dir):
		print ('diretory to pcap file/files not specified or doesn t exists in the current directory')
		return
	else:
		print ('OK the directory exists this is :',pcap_dir)
		count = 0
		for root, dirs, files in os.walk(pcap_dir):		
			print( len(files), "non-directory files")
			for name in files:	
				print(pcap_dir+'/'+name)	
				if name.find('.pcap') >=0:
					try:
						print('    >>>> Ok this is a pcap file, let\'s parse it')
						file_path = os.path.join(root, name)
						print('    >>>> The name of this file is : ' + file_path)
						f = open(file_path, 'rb')
						pcap = dpkt.pcap.Reader(f)
						for ts, buf in pcap:
							time = str(datetime.datetime.utcfromtimestamp(ts))
							eth = dpkt.ethernet.Ethernet(buf)
							if eth.type != dpkt.ethernet.ETH_TYPE_IP:
								continue
							mac_source=mac_addr(eth.src)
							mac_destination=mac_addr(eth.dst)
							ip = eth.data
							# Check for TCP in the transport layer
							if isinstance(ip.data, dpkt.tcp.TCP):
								# Set the TCP data
								tcp = ip.data
								# Now see if we can parse the contents as a HTTP request
								try:
									request = dpkt.http.Request(tcp.data)
								except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
									continue									
								do_not_fragment = bool(dpkt.ip.IP_DF)
								more_fragments = bool(dpkt.ip.IP_MF)
								fragment_offset = bool(dpkt.ip.IP_OFFMASK)
								Source = "%s" % ip_to_str(ip.src)
								Destination = "%s" % ip_to_str(ip.dst)
								Length = "%d" % (ip.len)
								TTL = "%d" % (ip.ttl)
								OFF = ip.off
								TOS = ip.tos
								Protocol = ip.p
								#donnee = ip.data
								
								mots_ok=['ALLWORDS']
								mots_nok=['NONO']
								#colonnes à garder
								#colonnes=[3]
								colonnes=[3,5,7,12,23,28]
								txt2 = repr(request)
								lignes = _parser(txt2,' ',mots_ok,mots_nok,1,colonnes)	
								requette = []
								for ligne in lignes:
									print (ligne)
									requette = ligne.split("'")
								i2=0
								liste_url = []
								for requ in requette:									
									requ = requ.strip()
									if i2==1:										
										if requ not in liste_url:
											#print (requ)
											liste_url.append(requ)
									if requ.find('http') >= 0:
										if requ not in liste_url:
											#print (requ)										
											liste_url.append(requ)
									if requ.find('www') >= 0:
										if requ not in liste_url:
											#print (requ)										
											liste_url.append(requ)														
									if requ.count('.') > 1:
										if requ not in liste_url:
											#print (requ)										
											liste_url.append(requ)
									i2 += 1
								#print (liste_url)
								#print ('===')
								data = (time,mac_source, mac_destination, Source , Destination , liste_url)
								#print(Source) 
								#print(Destination)
								#print ('HTTP request: %s\n' % repr(request))
								c.writerow(data)					
								search_phrase ='****'
								last_domain=""
								for the_url in liste_url:
									if the_url.find('?') >= 0:
										the_url=last_domain+the_url
									output.append({
										'time' : time,
										'dst_mac' : mac_destination,
										'src_mac' : mac_source,
										'dst_ip' : Destination,
										'src_ip' : Source,
										'host': the_url,
										'data':search_phrase
									})		
									last_domain=the_url
						f.close()
						print('    >>>> OK Done')
					except IOError as e:
						print (errno.e)
						print (e)
						packets= None
						return	
	fichier_out = 'data.json'
	'''
	with open(args.output,'W') as outfile:
		json.dump(output, outfile)	
	'''
	with open(fichier_out,'w') as outfile:
		json.dump(output, outfile)	
#	with open(args.output,'W') as outfile:
#		json.dump(output, outfile)		
#	if (not args.start_server):
#		print("\n\t Navigate to http://localhost:"+str(args.port)+"?filename=resultat.html\n")
#		subprocess.call(["python","-m","http.server",args.port])
if __name__ == '__main__':
	main()