#import sys
import os
#import signal as sig
from pathlib import Path
from threading import Thread
import argparse
import subprocess

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
		return self.__part, self.__port
	#ritorna la stringa col nome del file
	def get_filename(self):
		return self.__filename
	#set PATH_PCAP
	def set_path_pcap(self, path):
		self.__PATH_PCAP = path	#globale???
	def is_dir(self):
		return self.__port == 'None'


class FilesNotFoundError(FileNotFoundError):
	def __init__(self, name):
		super().__init__()
		self.__name = name
	def get_name(self):
		return self.name
class Error(Exception):
	pass
class SnortNotWellConfiguredError(Error):
	pass
class AnalysisError(Error):
	pass
class RenameError(Error):
	pass
class SkipAnalisisError(Error):
	pass
class NotPortListFile(Error):
	def __init__(self, path):
		super().__init__()
		self.err = "Whether the file {}/pcapfiles/portlist.conf has been modified or replaced".format(path)
	
class Analyzer:
	'''
	Analizzatore che testa Snort e che presenta metodi per l'analisi "richiesta" e "ricorsiva"
	'''
	def __init__(self, path_pcap, home_net=None, snort_conf='/etc/snort/snort.conf', log_dir = '.', ctf_name=None):
		self.__PATH_PCAP = path_pcap
		self.__CTF_NAME = ctf_name
		self.__SNORT_CONF = snort_conf
		self.__HOME_NET = home_net
		self.__LOG_DIR = log_dir
		self.__PART = 1
		self.__PORT = None
		
	def testing_config(self):
		if not Path(self.__PATH_PCAP).exists():
			raise FilesNotFoundError(self.__PATH_PCAP + ' folder')

		if not Path(self.__PATH_PCAP+'/pcapfiles/').exists():
			raise FilesNotFoundError('pcapfiles folder')
		
		try:
			portList=self.__PATH_PCAP+"/pcapfiles/portlist.conf"
			with open(portList, "r") as f:
					lines=f.readlines()
					for line in lines:
						self.__PORTS = line.split(';')
					self.__PORTS[-1] = self.__PORTS[-1].replace('\n', '')
					#testing
					#print(self.__PORTS)
					#return
					#check if portlist.conf was modified
					for port in self.__PORTS:
						if not port.isdigit():
							raise NotPortListFile(self.__PATH_PCAP)
					#print(self.__PORTS)	
		except FileNotFoundError:
			raise FilesNotFoundError("portlist.conf")
		#sostituisco CTF con il nome della CTF
		if not self.__CTF_NAME == None:
			try:
				with open("/etc/snort/rules/local.rules") as f:
					lines = f.readlines()
					for l in lines:
						f.write(l.replace("$CTF", self.__CTF_NAME))
			except FileNotFoundError:
				raise FilesNotFoundError("local.rules")		
	    			
		
		try:
			cmd = ["snort", "-T", "-c", self.__SNORT_CONF]
			subprocess.check_call(cmd)
		except subprocess.CalledProcessError:
			raise SnortNotWellConfiguredError()
		except FileNotFoundError:
			raise FilesNotFoundError(self.__SNORT_CONF)
			
	def rec_analysis(self):

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
			except FileNotFoundError:
				raise FilesNotFoundError(pcap.get_filename())
 		
		self.__PART += 1
	    
	def req_analysis(self, part, port):
		try:
			p = PcapInfo(self.__PATH_PCAP, part, port)
			if p.is_dir():
				for porta in self.__PORTS:
					try:					
						p.set_pcap(part, porta)
						self.__analysis(p)
					except FileNotFoundError:
						raise FilesNotFoundError(pcap.get_filename())
			else:
				self.__analysis(p)
		except FileNotFoundError:
			raise FilesNotFoundError(pcap.get_filename())

	def __analysis(self, pcap):
		pwd = os.getcwd()
		part, port = pcap.get_param()
		snort = ['snort', '-q', '-A', 'fast', '-c', self.__SNORT_CONF, '-l', self.__LOG_DIR, '-r', pcap.get_filename()]
		mkdir = ['mkdir', self.__LOG_DIR+'/fpartition'+part+'/']
		rename1 = ['cp', self.__LOG_DIR+'/alert', self.__LOG_DIR+'/fpartition'+part+'/aport'+port]
		remove1 = ['rm', self.__LOG_DIR+'/alert']
		rename2 = 'cp '+self.__LOG_DIR+'/tcpdump.log.* '+self.__LOG_DIR+'/fpartition'+part+'/fport'+port+'.pcap'
		remove2 = 'rm '+self.__LOG_DIR+'/tcpdump.log.*'
		if not self.__HOME_NET == None:
			snort = snort.append(['-h', self.__HOME_NET])
		try:
			subprocess.check_call(snort)
			#print("Snort finished conifig")
			try:
				subprocess.check_call(mkdir)
			except subprocess.CalledProcessError:
				pass
			try:
				subprocess.check_call(rename1)
				subprocess.check_call(remove1)
			except subprocess.CalledProcessError:
				pass
			try:
				subprocess.check_call(rename2, shell = True)
				subprocess.check_call(remove2, shell = True)
			except subprocess.CalledProcessError:
				pass
			
			#subprocess.check_call(rename1)
			#subprocess.check_call(remove1)
			#subprocess.check_call(rename2, shell = True)
			#subprocess.check_call(remove2, shell = True)
			
		except subprocess.CalledProcessError as e:
			if e.cmd == 'snort':
				raise AnalysisError()
			elif e.cmd == 'mv':
				raise RenameError()

'''test Analyzer()'''
a = Analyzer('/home/berna/', log_dir = os.getcwd()+'/testing-analisi/')
try:
	a.testing_config()
except FilesNotFoundError:
	print('pcapfiles not found')

a.req_analysis(1,8000)

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








