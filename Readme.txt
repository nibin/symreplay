README.txt
**********

Symantec Backup Exec MiTM Attack
--------------------------------

1. Introduction:   

   Software Link: http://www.symantec.com/business/products/family.jsp?familyid=backupexec
   Version: 
 	- Symantec Backup Exec for Windows Servers versions 11.0, 12.0, and 12.5 
	- Symantec Backup Exec 2010 versions 13.0 and 13.0 R2
   Tested on: Tested on Symantec Backup Exec 12.5 for Windows Servers
   CVE : CVE-2011-0546
   BID: 47824

   Symantec Disclosure link: http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110526_00
   iViZ Disclosure link: http://goo.gl/1vzdE

2. How to Use:
	
   2.1 Help Screen -

   nibin@nibin-desktop:~/pyworkspace/SymantecReplay/src$ python poc.py -h
   Usage: poc.py [options]

   Options:
     -h, --help            show this help message and exit
     -c DMA, --dma_ip=DMA  IP of Data Management Application or the Client
     -s DSP, --dsp_ip=DSP  IP of Data Service Provider or the Server
     -n DSP_NBNAME, --dsp_nbname=DSP_NBNAME
                           NetBios name of DSP
     -f FAKE_IP, --fake_ip=FAKE_IP
                           The Attacker IP that will host the fake DSP
     -d DOMAIN, --domain=DOMAIN
                           Domain of DMA (Optional)  

3. Details of Test Environment:

   The PoC was tested in a WINDOWS domain envorironment. The test environment had 
   3 machines
     i. A Windows 2003 Server running DMA  
    ii. A windows XP(SP2) running the remoting agent
   iii. An attacker machine(Ubuntu) running the PoC

  Demo run of PoC -
   nibin@nibin-desktop:~/pyworkspace/SymantecReplay/src$ python poc.py -c 192.168.1.180 -s 192.168.1.181 -n RevrseEngg.backupserver.ivizindia.com 
   -f 192.168.10.6 -d backupserver
                 where 	- "192.168.1.180" was the Windows 2003 Server running DMA
		 	- "192.168.1.181" was the Windows XP running remoting agent
			- RevrseEngg.backupserver.ivizindia.com was the NETBIOS/Full domain name of the 
			  Windows XP machine running the remoting agent
			- "192.168.10.6" was the attacker IP from where the PoC was run. 
			- "backupserver" was the Domain name	

4. Details of Operation:
 	
     i. Run the PoC code
    ii. Try to manually click the host from DMA> Backup Wizard > Windows Systems
   iii. If the remote agent is poisoned, the DMA will connect to the fake DSP

5. Other Details:

   The PoC was written to demonstrate the possibility of MITM attack on Symantec BackupExec
   software. Some of the things to know - 
     * The domain option "-d" is not implemented as such. The purpose of "-d" option was to
       use it in a POST authenticated  NDMP request "DATA_START_BACKUP" (0x401). The corresponding
       key it would have been used is the USERNAME field. Currently it will use the USERNAME as 
       "BACKUPSERVER\Administrator".
     * Another assumption this PoC makes is that the DMA's are configured with credentials for
       auto backup from remote machines. Possibly the same username/password should be set for 
       all the participating machines.

Hope this helps. Let me know if there is any doubts

Nibin Varghese
Security Research
iViZ Security,

twitter: twitter.com/nibin012

