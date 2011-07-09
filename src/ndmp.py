#!/usr/bin/env python

import struct
import time
import sys

class ndmp_header:
    def __init__(self):
        self.fields = { }
        #self.__setitem__('fraghdr',0x80000000)
        self.__setitem__('sequence',1)
        self.__setitem__('time',time.time())
        self.__setitem__('message_type',0)
        self.__setitem__('message_name',0)
        self.__setitem__('reply_sequence',0)
        self.__setitem__('err',0)
        #self.__setitem__('data',"\x00")
        
    def __setitem__(self,key,value):
        self.fields[key] = value
        
    def __getitem__(self,key):
        return self.fields[key]
        
    def __str__(self):
        #struct.pack(">L",self.__getitem__('fraghdr')) + \
        data = struct.pack(">L",self.__getitem__('sequence')) + \
            struct.pack(">L",self.__getitem__('time')) + \
            struct.pack(">L",self.__getitem__('message_type')) + \
            struct.pack(">L",self.__getitem__('message_name')) + \
            struct.pack(">L",self.__getitem__('reply_sequence')) + \
            struct.pack(">L",self.__getitem__('err'))
               
        if(self.fields.has_key('data')):
            data += self.__getitem__('data')
                              
        return(data)
                  
    def __len__(self):
        return (len(str(self)))


class ndmp(ndmp_header):    
    def __init__(self):
        self.pkt = ndmp_header()
                
    def dump(self):
        return(str(self.pkt))
    
    def parse(self,data):
        #TODO: Parse frag header also
        temp_pkt = self.pkt  #ndmp_header()
        #temp_pkt.__setitem__('fraghdr',struct.unpack(">L",data[0:4]))
        temp_pkt.__setitem__('sequence',struct.unpack(">L",data[4:8]))
        temp_pkt.__setitem__('time',struct.unpack(">L",data[8:12]))
        temp_pkt.__setitem__('message_type',struct.unpack(">L",data[12:16]))
        temp_pkt.__setitem__('message_name',struct.unpack(">L",data[16:20]))
        temp_pkt.__setitem__('reply_sequence',struct.unpack(">L",data[20:24]))
        temp_pkt.__setitem__('err',struct.unpack(">L",data[24:28]))
        temp_pkt.__setitem__('data',data[28:]) 
        self.pkt = temp_pkt
        return (self.pkt)