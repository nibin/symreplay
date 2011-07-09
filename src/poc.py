#!/usr/bin/env python

#Dummy Server and client
#Veritas software

from optparse import OptionParser

from server_ndmp import *
import client_ndmp

#magic = ""


def main():
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-c","--dma_ip",dest="dma",help="IP of Data Management Application or the Client" )
    parser.add_option("-s","--dsp_ip",dest="dsp",help="IP of Data Service Provider or the Server" )    
    parser.add_option("-n","--dsp_nbname",dest="dsp_nbname",help="NetBios name of DSP")
    parser.add_option("-f","--fake_ip",dest="fake_ip",help="The Attacker IP that will host the fake DSP")
    #parser.add_option("-m","--mode",dest="mode",help="""Mode of Operation \t\t\t\t\t
    #0 - Automatic, 1 - Manual""")
    parser.add_option("-d","--domain",dest="domain",help="Domain of DMA (Optional)" )
    
    (options, args) = parser.parse_args()
    
    if((options.dma == None) or
        (options.dsp == None) or 
        (options.dsp_nbname == None) or
        (options.fake_ip == None)):
        #(options.mode == None)):
        parser.error("Options are missing. Try -h or --help")
    
    a_server = server_ndmp(options.dma, options.dsp, options.dsp_nbname, options.fake_ip )
    a_server.pre_run()
        
  

if __name__=='__main__':
    main()