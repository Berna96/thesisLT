import sys
import os
import signal as sig
from pathlib import Path
from threading import Thread
import argparse


class PcapInfo:
	def __init__(self, path, part, port=None):
		self.set_path_pcap(path)
		self.set_pcap(part, port)
		
	def __built_file_name(self, part, port):
		if port == 'None':
			filePath = self.__PATH_PCAP + "/pcapfiles/partition"+ part + "/"
		else:		
			filePath = self.__PATH_PCAP + "/pcapfiles/partition"+ part + "/port" + port + ".pcap"		
		return filePath
	
	#set della partizione e porta
	def set_pcap(self, part, port):
		self.__port = str(port)
		self.__part = str(part)
		self.__filename = self.__built_file_name(self.__part, self.__port) 
		if not Path(self.__filename).exists():
			raise FileNotFoundError()
	def get_param(self):
		return self.part, self.port
	#ritorna la stringa col nome del file
	def get_filename(self):
		return self.__filename
	#set PATH_PCAP
	def set_path_pcap(self, path):
		self.__PATH_PCAP = path	#globale???
	def is_dir():
		return self.__port == 'None'

'''
#testing PcapInfo:success
try:
	p = PcapInfo("/home/berna/", 1, None)
	print(p.get_filename())
except FileNotFoundError:
	print("File non trovato")
'''


	
class Analyzer:

	def __init__(self, path_pcap, home_net=None, snort_conf='/etc/snort/snort.conf', log_dir = '.', ctf_name=None):
		self.__PATH_PCAP = path_pcap
		self.__CTF_NAME = ctf_name
		self.__SNORT_CONF = snort_conf
		self.__HOME_NET = home_net
		self.__LOG_DIR = log_dir
		self.__PART = 1
		self.__PORT = None
		
	def testing_config(self):
		if not Path(self.__PATH_PCAP).is_dir():
			raise FileNotFoundError("PATH_PCAP")
		
		if Path(self.__PATH_PCAP+"/pcapfiles/").is_dir():
			raise FileNotFoundError("PcapFiles")
	
		try:
			portList=PATH_PCAP+"/pcapfiles/portlist.conf"
			with open(portList, "r") as f:
				lines=f.readlines()
				'''
				pl = False
            			for line in lines:
					if line.find("--port-list--"):
						pl = True
				if not pl:
					raise NotPortlistFile()
				for line in lines:
					if not line.find("--port-list--"):
						self.__PORT = line.split()
				'''
				for line in lines
					self.__PORTS = line.split(';')
					#print(self.__PORTS)	
		except FileNotFoundError:
			raise FileNotFoundError("portlist")
	    			
		if not self.__SNORT_CONF == '/etc/snort/snort.conf' :
			#conf file custom messo
			try:
				
				try:
					cmd = ["snort", "-T", "-c", self.__SNORT_CONF]
					subprocess.check_call(cmd)	#fai partire snort con il file custom
				except subprocess.CalledProcessError:
					raise SnortNotWellConfiguredError()
	    		except FileNotFoundError:
				raise FileNotFoundError("Custom config file Snort")
		else
			try:
    	        		with open("/etc/snort/snort.conf") as conf:
					lines = conf.readlines()
					for l in lines:
						
                			tmp = conf.read().replace("$CTF", CTF)
                			conf.write(tmp)
				try:
					cmd = ["snort", "-T", "-c", self.__SNORT_CONF]
					subprocess.check_call(cmd)	#fai partire snort con il file custom
				except subprocess.CalledProcessError:
					raise SnortNotWellConfiguredError()
	    		except FileNotFoundError:
				raise FileNotFoundError("snort.conf")
	
	def rec_analysis():

		#controlla se ha tentato l'invio
		try:
			pcap = PcapInfo(self.__PCAP_PATH, self.__PART, None)
		except FileNotFoundError:			
			raise SkipAnalisisError()
			return
		
		for port in self.__PORTS: 
			try:
				pcap.set_pcap(self.__PART, port)
				self.__analysis(pcap)
			except FileNotFoundException:
				raise FileNotFoundException(self.__PART, port)
 		
		self.__PART += 1
	    
	def req_analysis(part, port):
		try:
			p = PcapInfo(self.__PCAP_PATH, part, port)
			if p.is_dir():
				for porta in self.__ports:
					p.set_pcap(part, porta)
			    		self.__analysis(p)
			else:
				self.__analysis(p)
		except FileNotFoundException:
			raise RequestedAnalisisError(part, port)	

	def __analysis(pcap):
		part, port = pcap.get_param()
		snort = ['snort', '-A', 'console', '-c', self.__SNORT_CONF, '-l', self.__LOG_DIR, '-r', p.get_filename()]
		rename = ['mv', 'tcpdump.log.*', 'fpartition'+part+'/fport'+port+'.pcap']
		if not self.__HOME_NET == None:
			snort = snort.append(['-h', self.__HOME_NET])
		try:
			subprocess.check_call(snort)
			subprocess.check_call(rename)
		except subprocess.CalledProcessError:
			if cmd == 'snort':
				raise AnalysisError()
			else if cmd == 'mv':
				raise RenameError()



'''
class AnalizerThread(Thread):
    
    def __init__(self, args):
	super().__init__()
	self.__args = args	
    abstract def run() 
  
class AnalizerThreadRec(AnalizerThread):
    #to be execute in thread/process
	
    def __init__(self, args):
	super().__init__(args)
	
    def run():
	try:
		Analizer a = Analizer(self.__args)
	except WrongArgumentException():
		sys.exit(1)
	
	switcher = {
		1:__invalid_path,
		2:__invalid_path_pcap,
		3:
		4:
		}
		print_stuff=switcher.get(a.testing_config())
		self.print_stuff()
		#global REQ_START
		REQ_START = True
		a.rec_analisis()
		
		sig.signal(SIGALRM, a.rec_analysis)
		sig.alarm(5*60)
    def __invalid_path(self):
	print("Path not valid")
    	print("Quitting..")
    	sys.exit(1)
    def __invalid_path_pcap(self):
	print("Path not valid, pcap files not found")
    	print("Quitting..")
    	sys.exit(1)
    def __check_port_list
	

class AnalyzerThreadReq(AnalyzerThread):
    def __init__(self, args):
	super().__init__(args)	#super(args)

    def run():
	while not START_REC		
	a.rev_analysis()


#print("If you insert wrong home net you can probably have problem with snort")
	#print("you can modify this parameter in snort.conf file")
	#print("CTF name is a parameter that snort will search for flags in packets")
	#print("If you insert the wrong CTF name you can modify it in rules/local.rules file in $CTF")

class
#main

START_REC = False
ff




'''
'''
    def __init__(self, typethread, args):
	Thread.__init__(self)
	self.__args
	if not (typethread == "rec" or typethread == "req"):
		raise WTFEXception()
	self.__type = typethread
	
    def run(self):
	
	try:
		Analizer a = Analizer(self.__args)
	except WrongArgumentException():
		sys.exit(1)
	if self.__type == "rec":
			
		switcher = {
			1:__invalid_path,
			2:__invalid_path_pcap,
			3
			4:
		}
		print_stuff=switcher.get(a.testing_config())
		self.print_stuff()
		global REQ_START
		REQ_START = True
		a.rec_analisis()
		
		sig.signal(SIGALRM, a.rec_analysis)
		sig.alarm(5*60)
	else if self.__type == "rev":
		while not START_REC		
		a.rev_analysis()
    '''
 









