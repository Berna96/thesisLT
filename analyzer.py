#import sys
import os
#import signal as sig
from pathlib import Path
from threading import Thread
#import argparse
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
	
	def exists(self):
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
		return self.__name
class Error(Exception):
	pass
class SnortNotWellConfiguredError(Error):
	pass
class AnalysisError(Error):
	def __init__(self, msg):
		super().__init__()
		self.msg = msg

class NoRulesFindError(Error):
	pass
class SkipAnalisisError(Error):
	pass
class NotPortListFileError(Error):
	def __init__(self, path):
		super().__init__()
		self.msg = "Whether the file {}/pcapfiles/portlist.conf has been modified or replaced".format(path)
	
class Analyzer:
	'''
	Analizzatore che testa Snort e che presenta metodi per l'analisi "richiesta" e "ricorsiva"
	'''
	def __init__(self, path_pcap, optional_args):
		'''
		home_net=None, snort_conf='/etc/snort/snort.conf', log_dir = '.', ctf_name=None
		'''
		self.__PATH_PCAP = path_pcap
		self.__HOME_NET = optional_args[0]
		self.__SNORT_CONF = optional_args[1]
		self.__LOG_DIR = optional_args[2]
		self.__CTF_NAME = optional_args[3]
		print([self.__HOME_NET, self.__SNORT_CONF, self.__LOG_DIR, self.__CTF_NAME])
		self.__PART = 1
		self.__PORTS = None
		
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
					print(self.__PORTS)	
		except FileNotFoundError:
			raise NotPortListFileError(self.__PATH_PCAP)
		#sostituisco CTF con il nome della CTF
		if not self.__CTF_NAME == None:
			if Path(self.__PATH_PCAP+'/pcapfiles/.ctfname').exists():
				with open(self.__PATH_PCAP+'pcapfiles/.ctfname', 'r') as f:
					ctf_name = f.read()
					ctf_name = ctf_name.replace('\n', '')
			else:
					ctf_name = "$CTF"
				
			try:
				with open("/etc/snort/rules/local.rules", "r+") as f:
						lines = f.readlines()
						lines2 = []
						for l in lines:
							l=l.replace(ctf_name, self.__CTF_NAME)
							lines2.append(l)
						f.seek(0)
						f.writelines(lines2)
			except FileNotFoundError:
					raise FilesNotFoundError("local.rules")	
			with open(self.__PATH_PCAP+'/pcapfiles/.ctfname','w') as f:
				f.write(self.__CTF_NAME)	
	    			

		try:
			cmd = ["snort", "-T", "-c", self.__SNORT_CONF]
			subprocess.check_call(cmd)
		except subprocess.CalledProcessError:
			raise SnortNotWellConfiguredError()
		except FileNotFoundError:
			raise FilesNotFoundError(self.__SNORT_CONF)
		
	def get_ports(self):
		return self.__PORTS
	def set_ports(self, ports):
		self.__PORTS = ports
			
	def rec_analysis(self):

		#controlla se ha tentato l'invio
		try:
			pcap = PcapInfo(self.__PATH_PCAP, self.__PART, None)
			pcap.exists()
		except FileNotFoundError:			
			raise SkipAnalisisError()
		
		n = False
		f = False
		for port in self.__PORTS:
			try:
				pcap.set_pcap(self.__PART, port)
				self.__analysis(pcap)
			except FileNotFoundError:
				n = True
			except AnalysisError:
				raise AnalysisError('Error in executing Snort: something failed')
			except NoRulesFindError:
				f = True

		if n:
			raise FileNotFoundError()
		if f:
			raise NoRulesFindError() 
 		
		self.__PART += 1
	    
	def req_analysis(self, part, port):
		try:
			p = PcapInfo(self.__PATH_PCAP, part, port)
			p.exists()
		except FileNotFoundError:
			raise FilesNotFoundError(p.get_filename())
			
		if p.is_dir():
			f = False
			n = False
			for porta in self.__PORTS:
				try:					
					p.set_pcap(part, porta)
					self.__analysis(p)
				except FileNotFoundError:
					n = True
				except AnalysisError:
					raise AnalysisError('Error in executing Snort: something failed')
				except NoRulesFindError:
					f = True

			if n:
				raise FileNotFoundError()
			if f:
				raise NoRulesFindError()
		else:
			try:
				self.__analysis(p)
			except AnalysisError:
				raise AnalysisError('Error in executing Snort: something failed')
			except NoRulesFindError:
				raise NoRulesFindError()


	def __analysis(self, pcap):
		pwd = os.getcwd()
		part, port = pcap.get_param()
		snort = ['snort', '-q', '-A', 'console', '-c', self.__SNORT_CONF, '-l', self.__LOG_DIR, '-r', pcap.get_filename()]
		#mkdir = ['mkdir', self.__LOG_DIR+'/fpartition'+part+'/']
		#rename1 = ['cp', self.__LOG_DIR+'/alert', self.__LOG_DIR+'/fpartition'+part+'/aport'+port]
		#remove1 = ['rm', self.__LOG_DIR+'/alert']
		rename2 = 'cp '+self.__LOG_DIR+'/tcpdump.log.* '+self.__LOG_DIR+'/fpartition'+part+'/fport'+port+'.pcap'
		remove2 = 'rm '+self.__LOG_DIR+'/tcpdump.log.*'
		if not self.__HOME_NET == None:
			snort.extend(['-h', self.__HOME_NET])
		try:
			subprocess.check_call(snort)
		except subprocess.CalledProcessError as e:
			raise AnalysisError('Error in executing Snort: something failed')
		
		directory = Path(self.__LOG_DIR+'/fpartition'+part+'/')
		if not directory.exists():
			directory.mkdir(parents=True, exist_ok=True)
		'''		
		try:
			subprocess.check_call(rename1)
			subprocess.check_call(remove1)
		except subprocess.CalledProcessError:
			pass
		'''
		try:
			subprocess.check_call(rename2, shell = True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
			subprocess.check_call(remove2, shell = True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		except subprocess.CalledProcessError:
			raise NoRulesFindError()	
		
			
'''test Analyzer()
a = Analyzer('/home/berna/', log_dir = os.getcwd()+'/testing-analisi/', home_net = '192.168.1.0/24', ctf_name = 'IlPippodelleMadonne')
try:
	a.testing_config()
except FilesNotFoundError:
	print('pcapfiles not found')

#a.req_analysis(1,80)
a.rec_analysis()
a.rec_analysis()
'''
