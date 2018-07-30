from analyzer import *
from threading import *
import queue
import sys
import os
import _thread

import tkinter as tk
from tkinter import filedialog as fd
from tkinter import messagebox as msg
import argparse as ap
import time

def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)


class Parser:
	# home_net, snort_conf, log_dir, ctf_name = optional_args
	def __init__(self):
		self.__path_pcap = None
		parser = ap.ArgumentParser(description='Analyzer program of pcaps with Snort')
		parser.add_argument('path_pcap', type=str, help='folder of pcapfiles')
		parser.add_argument('-o', dest='home_net', help='If you insert wrong home net you can probably have problem with snort\r\nyou can modify this parameter in snort.conf file', default=None)
		parser.add_argument('-c', dest='snort_conf', help='Snort configuration file (default: /etc/snort/snort.conf)', default='/etc/snort/snort.conf')
		parser.add_argument('-l', dest='log_dir', help='Log folder (default: current directory)', default='.')	
		parser.add_argument('-d', dest='ctf_name', help='CTF name to search for flags', default=None)
		args = parser.parse_args()
		self.__path_pcap = args.path_pcap
		self.__opt_args = [args.home_net, args.snort_conf, args.log_dir, args.ctf_name]

	def get_arguments(self):
		return self.__path_pcap, self.__opt_args	

class Gui:

	def __init__(self,title_name, path_pcap, log_dir):
		self.__PATH_PCAP = path_pcap
		self.__LOG_DIR = log_dir
		self.__title = title_name
		#gui objects
		self.__WIN = tk.Tk()
		self.__WIN.title(title_name)
		self.__WIN.rowconfigure(0, weight=1)
		self.__WIN.rowconfigure(6, weight=1)
		self.__WIN.columnconfigure(0, weight=1)
		self.__WIN.columnconfigure(6, weight=1)
		#widget
		tk.Label(self.__WIN, text='Partition:').grid(row = 0, column = 1, sticky='w')
		self.__partTXT = tk.Entry(self.__WIN)
		self.__partTXT.grid(row = 0, column = 2)
		tk.Label(self.__WIN, text='Port number:').grid(row = 0, column = 3)
		self.__portTXT = tk.Entry(self.__WIN)
		self.__portTXT.grid(row = 0, column = 4)
		
		reqButton = tk.Button(text="Request", command=self.__request)
		reqButton.grid(row=0, column=5)

		self.__TXT = tk.Text(self.__WIN)
		self.__TXT.grid(row = 1, sticky='nsew', column = 1, columnspan = 5)
		
		mb = tk.Menu(self.__WIN)
		self.__WIN.config(menu=mb)
		fm = tk.Menu(mb)
		fm.add_command(label='Open...', command=self.__do_open)
		fm.add_separator()
		fm.add_command(label='Quit', command=self.__do_quit)
		mb.add_cascade(label='File', menu=fm)
		self.__WIN.geometry("640x420")
		tk.mainloop()

	def __do_quit(self):
		ans=msg.askyesno("Quit", "Are you sure you want to quit?")
		if ans == True:
			self.__WIN.quit()
			os._exit(0)

	def __request(self):
		part = self.__partTXT.get().replace('\n', '')
		port = self.__portTXT.get().replace('\n', '')
		#print('partition: ',part, '; port: ',port)
		if part == '':
			msg.showerror('Error', 'You must insert almost the partition number')
			return
		if not part.isdigit():
			msg.showerror('Error', 'In partition field you must insert a number!')
			self.__partTXT.delete( 0, 'end')
			return
		
		if not port == '':
	
			if not port.isdigit():
				msg.showerror('Error', 'In port field you must insert a number!')
				self.__portTXT.delete( 0, 'end')
				return
			global PORTS
			if not port in PORTS:
				msg.showerror('Error', 'You have insered a port not present in the list!')
				self.__portTXT.delete( 0, 'end')
				return
			path = self.__LOG_DIR+'/fpartition'+part+'/fport'+port+'.pcap'
			flag = True

		else:
			path = self.__LOG_DIR+'/fpartition'+part+'/'
			flag = False
			
		if flag:
			tcpdump = ['tcpdump', '-A', '-r', path]
			if Path(path).exists():
				try:
					out = subprocess.check_output(tcpdump)
				except subprocess.CalledProcessError:
					msg.showerror('Error', 'Error calling tcpdump')
				else:
					self.__TXT.delete('1.0', 'end')
					self.__TXT.insert('1.0', out)
					self.__WIN.title(path)
				finally:
					return
		else:
			port = None
		
		q.put([part, port])
		req.wait()
		global OK
		if not OK:
			OK = False
			return 
		tcpdump = ['tcpdump', '-A', '-r', path]
		if port is not None:
			try:
				out = subprocess.check_output(tcpdump)
			except subprocess.CalledProcessError:
				msg.showerror('Error', 'Error calling tcpdump')
			else:
				self.__TXT.delete('1.0', 'end')
				self.__TXT.insert('1.0', out)
				self.__WIN.title(path)
			finally:
				return	
		
	def __do_open(self):
		path = fd.askopenfilename(title='Scegli un file pcap da aprire', filetypes=[("packet capture", "*.pcap")])
		if len(path) > 0:
			self.__TXT.delete('1.0', 'end')
			tcpdump = ['tcpdump', '-A','-r', path]
			try:
				out = subprocess.check_output(tcpdump)
			except subprocess.CalledProcessError:
				msg.showerror('Error', 'Error calling tcpdump')
			else:
				self.__TXT.insert('1.0', out)
				self.__WIN.title(path)


#classe generale thread analizzatore
class AnalyzerThread(Thread):
	
	def __init__(self, path_pcap, optional_args):
		super().__init__() 
		self.a = Analyzer(path_pcap, optional_args)

	def run(self):
		pass

#thread ricorsivo
class AnalyzerThreadRec(AnalyzerThread):
    #to be execute in thread/process
	def __init__(self, path_pcap, optional_args):
		super().__init__(path_pcap, optional_args)
	
	def run(self):
		#raise KeyboardInterrupt()
		try:
			self.a.testing_config()
		except FilesNotFoundError as fnfe:
			print('File not found: {}'.format(fnfe.get_name()))
			os._exit(1)
		except SnortNotWellConfiguredError:
			print('Something failed with Snort configuration: check the configuration file chosen and retry')
			os._exit(2)
		except NotPortListFileError as e:
			print(e.msg)
			os._exit(3)
		else:
			global PORTS
			PORTS = self.a.get_ports()
			ev.set()	#fa partire gli altri thread
		#ricorsivo
		curr_time = time.time()
		while True:
			if abs(time.time()-curr_time)>=300:	#300 secondi
				print('Start recursive analysis')
				ev.clear()
				try:	
					self.a.rec_analysis()
				except SkipAnalisisError:
					print('Skipped recursive analysis')
				except FileNotFoundError:
					print('At least one files does not exist. Other files has been processed')
				except NoRulesFindError:
					print('Snort has not generated at least tcpdump.log file: snort rules have not found any exploit or flag')
				except AnalysisError as e:
					eprint(e.msg)
				ev.set()
				curr_time = time.time()
		#sig.signal(SIGALRM, a.rec_analysis)
		#sig.alarm(5*60)

#thread richiesta
class AnalyzerThreadReq(AnalyzerThread):
	
	def __init__(self, path_pcap, optional_args):
		super().__init__(path_pcap, optional_args)
	
	def run(self):
		#raise KeyboardInterrupt()
		ev.wait()
		#request
		self.a.set_ports(PORTS)
		while True:
			ev.wait()
			req.clear()
			item = q.get()
			print('Got request partition {} and port {}'.format(item[0], item[1]))
			try:
				self.a.req_analysis(item[0], item[1])
			except FilesNotFoundError as fnfe:
				print('File not found: {}; Skipped request analysis'.format(fnfe.get_name()))
			except FileNotFoundError:
				print('At least one file has not been founded')
			except AnalysisError as e:
				eprint(e.msg)
			except NoRulesFindError:
				print('Snort has not generated at least a tcpdump.log file: snort rules has not found any exploit or flag')
			else:
				global OK
				OK=True
			finally:
				req.set()

class GUIThread(Thread):
	
	def __init__(self, pcap_path, log_dir):
		super().__init__()
		self.__PATH_PCAP = pcap_path
		self.__LOG_DIR = log_dir

	def run(self):
		#raise KeyboardInterrupt()
		ev.wait()	
		Gui('Analysis Pcap', self.__PATH_PCAP, self.__LOG_DIR)
		

#main
ev = Event()
ev.clear()
req = Event()
req.clear()
q = queue.Queue()
PORTS = []
OK = False
#parser
parser = Parser()
path_pcap, opt_args = parser.get_arguments()
print(path_pcap)
print(opt_args)

recursive = AnalyzerThreadRec(path_pcap, opt_args)
request = AnalyzerThreadReq(path_pcap, opt_args)
gui = GUIThread(path_pcap, opt_args[2])

try:	
	recursive.start()
	request.start()
	gui.start()
	recursive.join()
	request.join()
	gui.join()
except KeyboardInterrupt:
	pass

print('Process Terminated Successfully')
os._exit(0)
