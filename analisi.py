import sys
import os
import signal as sig
from pathlib import Path
from threading import Thread



class PcapInfo:
	def __init__(self, port, part):
		self.set_pcap(port, part)
		self.__filename = self.__built_file_name(self.__port, self.__part) 
		if not Path(self.__filename).is_file():
			raise FileNotFoundError()
	def __built_file_name(self, port, part):
		return PATH_PCAP + "pcapfiles/partition"+ part + "/port" + port + ".pcap"
	def set_pcap(self, port, part):
		self.__port = str(port)
		self.__part = str(part)

	def get_filename(self):
		return self.__filename

PATH_PCAP = "/home/berna/"
p = PcapInfo(80, 1)
print(p.get_filename())

'''
	
class Analyzer:
	
    def __init__(self, args):
	self.__args = args
	self.__part = 1	#PART=1
#sig.signal(SIGALRM, analysis)
	
	if self.check_args() == False:
	    self.usage(prog=str(sys.argv[0]))
		
	self.__PATH_PCAP = str(sys.argv[1])
	self.__HOME_NET = str(sys.argv[2])
	self.__CTF = str(sys.argv[3])
	
    def testing_config():
	if Path(self.__PATH_PCAP).is_dir():
		return 1
		
	if Path(self.__PATH_PCAP+"/pcapfiles/").is_dir():
		return 2
	#print("If you insert wrong home net you can probably have problem with snort")
	#print("you can modify this parameter in snort.conf file")
	#print("CTF name is a parameter that snort will search for flags in packets")
	#print("If you insert the wrong CTF name you can modify it in rules/local.rules file in $CTF")

	try:
	    portList=PATH_PCAP+"pcapfiles/portlist.conf"
	    with open(portList, "r") as f:
            tmp=f.read()
            PORTS=(tmp.)
	except:
	    return 3
	if args == "-f" :
	    try:
    	        with open("/etc/snort/snort.conf") as conf:
                tmp = conf.read().replace("$CTF", CTF)
                conf.write(tmp)
	    except:
    		#print("Snort Configuration file not found")
    		#print("Quitting..")
    		#sys.exit(1)
		return 4
	else:
	    if not Path("/etc/snort/snort.conf").is_file():
		return 4
	
	#

	#while true:

	#print('Process terminated successfully')	
	
    def __check_args():
	if len(sys.argv) < 2:
	    return 1
    	if 
	return 0
    def __usage(prog):
	print("%s file/to/find/pcapfiles home_net/mask [OPTIONS]" % (prog))
        print("home_net must be the ip address of the net, e.g., 192.168.1.0/24")
        sys.exit(1)

    def rec_analysis():
	if isFolder(""):
		return False
	
	for port in self.__ports: 
	    try:
		PcapInfo p = PcapInfo(port,self.__part)
	        self.__analysis(p)
		
	    except FileNotFoundException:
		print("There is no pcap file with partition %d and port number %d" % ())
	
	self.__part += 1
	return True
	    
    def req_analysis(port, part):
	try:
	    PcapInfo p = PcapInfo(port,self.__part)
	    self.__analysis(p.get_pcapname())
	except FileNotFoundException:
	    print("There is no pcap file with partition %d and port number %d" % ())	

    def __analysis(pcap):
	os.system("snort -c /etc/snort/snort.conf -h {} -r {}".format(HOME_NET, pcapname))
	
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
 









