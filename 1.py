#!/usr/bin/python
#0322 Next: srxfw srxrb srxrbfw
import pxssh,os,sys,time,getpass,re,libxml2
from subprocess import PIPE, Popen
import optparse 

parser = optparse.OptionParser()                 
parser.add_option("-v","--showversion",
                  action="store_true", dest="isshowver",
                  help="show system information")
parser.add_option("-V","--showmore",
                  action="store_true", dest="isshowvermore",
                  help="show more system information")
parser.add_option("-b","--bridge",
                  action="store_true", dest="isbridge",
                  help="Print linux bridges MAC table")
parser.add_option("-i","--showint",
                  action="store_true", dest="isshowint",
                  help="Print host vnet interfaces stats")
parser.add_option("-o","--noping",
                  action="store_true", dest="isskipping",
                  help="JDM is reachable, skip ping test to JDM")
parser.add_option("-q","--qos",
                  action="store_true", dest="issrxqos",
                  help="Simple command to view WAN QOS for SRX")

#hidden options:
parser.add_option("-a","--all",
                  action="store_true", dest="ischeckall",
                  help=optparse.SUPPRESS_HELP) #on 963b
parser.add_option("-l","--lanip",
                  action="store_true", dest="islanip",
                  help = optparse.SUPPRESS_HELP, default = False)
                  #help="Use this option if you know a live customer IP address in the LAN--not finished")
parser.add_option("-n","--nojdm",
                  action="store_true", dest="isnojdm",
                  help = optparse.SUPPRESS_HELP )#hidden, only used for testing script 
                  #help="Skip JDM check and manually select vnf type - for test purpose")
parser.add_option("-p","--progress",
                  action="store_true", dest="isprogress",
                  help = optparse.SUPPRESS_HELP )#hidden, check script completion 
                 

(options, args) = parser.parse_args()


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
def removefirstlastline(file):
    file = re.sub(r'.*\n', '', file,1)
    remove = jdmusername + r'@.*$'
    file = re.sub(remove, '', file,1)
    return file

def resolvename(jdmhostname):
    hostfile = os.system('cat /etc/hosts | grep -i ' + jdmhostname.strip() +' > ucpetmp/tmpfile') #on nec01
    if not os.path.getsize('ucpetmp/tmpfile') > 0:
        nlistfile = os.system('nlist ' + jdmhostname.strip() +' > ucpetmp/tmpfile') # on snd963b
        if not os.path.getsize('ucpetmp/tmpfile') > 0:
            print ('something is wong, cant resolve hostname.')
            sys.exit()
    nlist  = open('ucpetmp/tmpfile', 'r').read()
    #jdmip = nlist[-27:]
    splitnlist = nlist.split()
    for i in splitnlist:
        if '2001:' in i:
            jdmip = i
            if 'IPV6=' in i:
                jdmip = i.strip('IPV6=')
    print 'IP resolved to be:' + jdmip
    return jdmip

def pingjdm():
    ping = os.system('ping6 ' + jdmip +' -c 1 > ucpetmp/tmpfileping')
    pingresult = os.popen('cat ucpetmp/tmpfileping | grep -i from').read()
    
    if 'bytes' not in pingresult:
        print 'ping jdm failed:' + ''.join(str(e) for e in pingresult.split()[3:])
        print 'exiting'
        sys.exit()
def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]

#option -q simple QOS command

  
def srxqos():
    print 'option -q simple QOS command:'
    try: 
        sshsrx = pxssh.pxssh()
        srxhostname = raw_input('Input vSRX IP address, else enter to accept best guess:' + guesssrxip() + ' : ') or guesssrxip()
        srxusername = raw_input('GTAC username: ')
        srxpassword = getpass.getpass('GTAC password: ')


        print '\nGet SRX config...\n'

        sshsrx.PROMPT = '01>'
        sshsrx.maxread = 1000000
        sshsrx.timeout = 100
        sshsrx.login (srxhostname,srxusername,password=srxpassword, port=22,auto_prompt_reset=False,original_prompt='01>')
        sshsrx.sendline ('show configuration | display set | no-more ')  # run a command
        
        sshsrx.prompt(timeout=100)             # match the prompt     
        conffile = open("ucpetmp/tmpfilesrxconf", "w")
        conffile.write(sshsrx.before)
        conffile.flush()
        conffile.close()

        #find if CRS
        invalid_input  = os.popen('cat ucpetmp/tmpfilesrxconf | grep Invalid').read()
        if 'Invalid input detected' in invalid_input:
            print 'Error:this command works only on SRX, exiting...'
            sys.exit()
            
        

        #find WAN interface
        wan  = os.popen('cat ucpetmp/tmpfilesrxconf | grep COS_IPV4_OUTPUT_').read().split('\n')[0]
        wanmainint = wan.split()[2]
        wansubint = wan.split()[4]
        wanint = wanmainint + '.' + wansubint 
       
        shaping  = os.popen('cat ucpetmp/tmpfilesrxconf | grep shaping | grep ' + wanmainint).read()
        #print shaping
        shapingrate =  shaping.split()[-1]
        print wanint + ' is the WAN interface.'
        print wanint + ' shaping rate: ' + shapingrate        
      
        print '\nGet show int queue...'
        sshsrx.sendline ('show interfaces queue ' + wanint + ' | no-more')  # run a command        
        sshsrx.prompt()             # match the prompt     
        conffile3 = open("ucpetmp/tmpfilesrxintqueue", "w")
        conffile3.write(sshsrx.before)
        conffile3.flush()
        conffile3.close()              
        

        grepqos = os.popen('cat ucpetmp/tmpfilesrxintqueue | grep Queue:').read()
        printdrops =os.popen('cat ucpetmp/tmpfilesrxintqueue | egrep -h "Queue:|dropped|Current|Queue-depth|Bytes" ').read()
        print '\n-----Showing traffic rate, drops and queue-depth of each queue:'
        print printdrops
        print '\nGet ACL infomation...'

        #get list of queues/forwarding clas
        fcnamelist = dict()
        for line in grepqos.splitlines():
            fcnamelist.update({line.split()[1].strip(','):line.split()[4]})
       
        
        grepsmapname = os.popen('cat ucpetmp/tmpfilesrxconf | grep SCHED_MAP | grep interfaces').read()
        #print grepsmapname
        smapname = grepsmapname.split()[-1]
        #print smapname

        #print 'get show scheduler-map... '
        cmdsmap = 'show class-of-service scheduler-map ' + smapname + ' | no-more'
        #print cmdsmap
        sshsrx.sendline ('show class-of-service scheduler-map ' + smapname + ' | no-more')      
      
        sshsrx.prompt()
        sshsrx.prompt()
        sshsrx.prompt()
        sshsrx.prompt()
       
        conffile4 = open("ucpetmp/tmpfilesrxsmap", "w")
        conffile4.write(sshsrx.before)
        conffile4.flush()
        conffile4.close()        
        

        #print '\nGet show firewall filter...'
       
        
        cmd = 'show firewall filter ' + wanint + '-o | no-more'
        #print cmd
        sshsrx.sendline(cmd)  # run a command        
        sshsrx.prompt()
        sshsrx.prompt()
        conffile5 = open("ucpetmp/tmpfilesrxfilter", "w")
        conffile5.write(sshsrx.before)
        conffile5.flush()
        conffile5.close()

        
        
        sshsrx.logout()

                
                
    
        print '\n-----Showing BW/Buffer assignment and ACL counter for each queue:'
        
        for key in fcnamelist:
            fcname = fcnamelist[key]
            showsmap =os.popen('cat ucpetmp/tmpfilesrxsmap | grep -A 1 ' + fcname + '_').read()
            
            
            print '\n------BW assignment for Queue:' + fcname
            print showsmap
            
            
            print '\n------Frewall filter configuration and counter for Queue:' + fcname
            print '\n'
            filter4class = os.popen('cat ucpetmp/tmpfilesrxconf | grep "inet filter ' + fcname + '_TRAFFIC_IPV4_"').read()
            filtercounter = ''
            for line in filter4class.split('\n'):
                if ('from' in line) and ('protocol' not  in line): # ommit TCP/UDP info
                    print line.strip('set firewall family inet filter') #firewall filter ACL
                if 'then count' in line:
                    countername = line.split()[-1] + '-'
                    filtercounter = os.popen('cat ucpetmp/tmpfilesrxfilter | grep ' + countername).read()
                    print '                ' + filtercounter.strip('\n') #firewall filter counter        
    except pxssh.ExceptionPxssh, e:
        print "SRX failed on login."
        print str(e)
        sys.exit()

        
#option -v show jdm information
def showver():
    print 'option -v show jdm information:'
    try: 
        sshjdm = pxssh.pxssh()
        print ('Collecting JDM information...')
        
        sshjdm.PROMPT = '\#'
        sshjdm.login (jdmip,jdmusername,password=jdmpassword, port=22,auto_prompt_reset=False,original_prompt='\#')

        sshjdm.sendline ('uptime')  
        sshjdm.prompt()
        uptime = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM uptime:'
        print uptime

        sshjdm.sendline ('jhost cat /var/run/host-reset-reason')  
        sshjdm.prompt()
        resetcode = removefirstlastline(sshjdm.before).strip('\n').strip()
        print '---------------'
        print 'JDM last reset code:' + resetcode 
        resetreason = ''
        if resetcode == '0xC1':
            resetreason = 'power cycle'
        if resetcode =='0x80':
            resetreason = 'soft reset'
        if resetcode == '0xC0':
            resetreason = 'cold reset'
        if resetcode == '0x483':
            resetreason = 'thermal shut down'

        
        print 'JDM last reset reason:' + resetreason





        sshjdm.sendline ('jhost grep max-load /etc/watchdog.conf')  
        sshjdm.prompt()
        watchdog_timer = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'Watchdog timer configuration:\n'
        print watchdog_timer

        sshjdm.sendline ('virsh list')  
        sshjdm.prompt()
        virshlistshow = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'VM list:\n'
        print virshlistshow  

        
        sshjdm.sendline ('ls /var/third-party/images/*.qcow2')  
        sshjdm.prompt()
        qcowfile = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'image files on disk:\n'
        print qcowfile         




        sshjdm.sendline ('jhost mpstat;jhost free')  
        sshjdm.prompt()
        cpumem = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'Hypervisor CPU/Memory utilization:\n'
        print cpumem
        
        sshjdm.sendline ('jhost docker images;jhost docker ps')  
        sshjdm.prompt()
        ipsecnm = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'oob ipsec-nm status:\n'
        print ipsecnm

        sshjdm.sendline ('tail -n 999 /var/log/phc.log')  
        sshjdm.prompt()
        bootstrap = sshjdm.before
        phcfile = open("ucpetmp/tmpfilephc", "w")
        phcfile.write(bootstrap)
        phcfile.flush()
        phcfile.close
        Bootstrap = os.popen('cat ucpetmp/tmpfilephc | grep Bootstrap | tail').read()
        print '---------------'
        print 'Bootstrap time and device SN:\n'
        print Bootstrap



        


    except pxssh.ExceptionPxssh, e:
        print "jdm failed on login."
        print str(e)
        sys.exit()

#option -V show more jdm information
def showvermore():
    print 'option -V show more jdm information:'
    try: 
        sshjdm = pxssh.pxssh()
        print ('Collecting JDM information...')
        
        sshjdm.PROMPT = '\#'
        sshjdm.login (jdmip,jdmusername,password=jdmpassword, port=22,auto_prompt_reset=False,original_prompt='\#')

                 
        sshjdm.sendline ('who')  
        sshjdm.prompt()
        who = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM current users:\n'
        print who

        sshjdm.sendline ('arp -a')  
        sshjdm.prompt()
        arptable = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM ARP table:\n'
        print arptable

        sshjdm.sendline ('ip -6 neighbor show')  
        sshjdm.prompt()
        v6table = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM neighbor table IPV6:\n'
        print v6table
        
        sshjdm.sendline ('ip -f inet6 neighbor show')  
        sshjdm.prompt()
        v6table2 = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM neighbor table IPV6:\n'
        print v6table2
        


        sshjdm.sendline ('cat /etc/*-release')  
        sshjdm.prompt()
        jdmrelease = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM linux release:\n'
        print jdmrelease

        sshjdm.sendline ('jhost cat /etc/*-release')  
        sshjdm.prompt()
        jhostrelease = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'Hypervisor linux release:\n'
        print jhostrelease

        sshjdm.sendline ('ps -ef')  
        sshjdm.prompt()
        jdmps = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'JDM running process:\n'
        print jdmps        

        sshjdm.sendline ('jhost ps -ef')  
        sshjdm.prompt()
        jhostps = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'Hypervisor running process:\n'
        print jhostps
        
        sshjdm.sendline ('jhost route')  
        sshjdm.prompt()
        jhostroute = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'Hypervisor routing table:\n'
        print jhostroute

        sshjdm.sendline ('traceroute6 -m 6 2001:1890:f800:a102::c:1')  
        sshjdm.prompt()
        jdmtrace = removefirstlastline(sshjdm.before)
        print '---------------'
        print 'jdm OAM traceroute to poller :\n'
        print jdmtrace

    except pxssh.ExceptionPxssh, e:
        print "jdm failed on login."
        print str(e)
        sys.exit()
        
#Get virsh list and jdm arp table and xml files
def jdmcheck():

    try: 
        sshjdm = pxssh.pxssh()
        print ('Checking JDM...')
        jdmvirsh = 'virsh list'
        sshjdm.PROMPT = '\#'
        sshjdm.login (jdmip,jdmusername,password=jdmpassword, port=22,auto_prompt_reset=False,original_prompt='\#')
        #Get virsh list
        sshjdm.sendline (jdmvirsh)  # run a command
        sshjdm.prompt()             # match the prompt
        virshfile = open("ucpetmp/tmpfilevirsh", "w")
        virshfile.write(sshjdm.before)
        virshfile.close()
        sshjdm.sendline('arp -a')
        sshjdm.prompt()
        arpfile = open("ucpetmp/tmpfilejdmarp", "w")
        arpfile.write(sshjdm.before)
        arpfile.close
        
        sshjdm.sendline('ip -6 neighbor show')
        sshjdm.prompt()
        v6file = open("ucpetmp/tmpfilev6", "w")
        v6file.write(sshjdm.before)
        v6file.close

        sshjdm.sendline('cat /var/third-party/vFW_fortigate.xml')
        sshjdm.prompt()
        fwxmlfile = open("ucpetmp/tmpfilefwxml", "w")
        fwxmlfile.write(sshjdm.before)
        fwxmlfile.close

        sshjdm.sendline('cat /var/third-party/vwanx/rvbdvsh.xml')
        sshjdm.prompt()
        rbxmlfile = open("ucpetmp/tmpfilerbxml", "w")
        rbxmlcontent = sshjdm.before
        rbxmlcontent = removefirstlastline(rbxmlcontent)
        rbxmlfile.write(rbxmlcontent)
        rbxmlfile.flush()
        rbxmlfile.close

        if not os.path.isfile('ucpetmp/tmpfilevirsh'):
            print ('something is wrong, cant find virsh file.')
            sys.exit()
        grepvirsh = os.popen('cat ucpetmp/tmpfilevirsh | grep running').read()
        splitlinevirsh = grepvirsh.splitlines()

        virshlis = []
        for linevirsh in splitlinevirsh:
            splitvirsh = linevirsh.split()
            virsh = splitvirsh[1]
            #dump xml for each virsh
            sshjdm.sendline('virsh dumpxml ' + virsh)
            sshjdm.prompt()
            virshfile = open("ucpetmp/tmpfilexml-"+virsh, "w")
            virshfile.write(sshjdm.before)
            virshfile.close
            #interface list for each virsh
            sshjdm.sendline('virsh domiflist ' + virsh)
            sshjdm.prompt()
            virshiffile = open("ucpetmp/tmpfileif-"+virsh, "w")
            virshiffile.write(sshjdm.before)
            virshiffile.close            
            virshlis.append(virsh)
        #dump xml for jdm
        sshjdm.sendline('jhost virsh -c lxc:///  dumpxml jdm')
        sshjdm.prompt()
        dumpjdmfile = open("ucpetmp/tmpfilexml-jdm", "w")
        dumpjdmfile.write(sshjdm.before)
        dumpjdmfile.close
        #interface list for jdm
        sshjdm.sendline('jhost virsh -c lxc:/// domiflist jdm')
        sshjdm.prompt()
        jdmiffile = open("ucpetmp/tmpfileif-jdm", "w")
        jdmiffile.write(sshjdm.before)
        jdmiffile.close
        #host bridge list
        sshjdm.sendline('jhost brctl show')
        sshjdm.prompt()
        bridgelist = open("ucpetmp/tmpfilebridge", "w")
        bridgelist.write(sshjdm.before)
        bridgelist.close       
        
        
        sshjdm.logout()
    except pxssh.ExceptionPxssh, e:
        print "jdm failed on login."
        print str(e)
        sys.exit()
    return    virshlis
#option -a checkall
def checkall():
    print 'option -a check all JDM virsh list:'
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')

    nlistfile = os.system('nlist > ucpetmp/tmpfilenlist')
    nlistgrep = os.popen('cat ucpetmp/tmpfilenlist | grep -A 1 ANT').read()
    print 'All Accounts list:'
    print nlistgrep
    ifcontinue = raw_input('Continue to check every uCPE? y/n: ')
    if not ifcontinue.strip() == 'y':
        sys.exit()
    nlistall  = open('ucpetmp/tmpfilenlist', 'r').read()
    for line in nlistall.splitlines():
        if 'JDM01' in line or 'ZZ01' in line:
            wordlist = line.split()
            for word in wordlist:
                if 'JDM01' in word or 'ZZ01' in word:
                    jdmname = word
                    jdmip = resolvename(jdmname)
                    ping = os.system('ping6 ' + jdmip +' -c 1 > ucpetmp/tmpfileping')
                    pingresult = os.popen('cat ucpetmp/tmpfileping | grep -i from').read()
                    if 'bytes' not in pingresult:
                        print 'ping jdm failed:' + jdmname
                    else:
                        try: 
                            sshjdm = pxssh.pxssh()
                            print ('Checking JDM...') + jdmname
                            jdmvirsh = 'virsh list'
                            sshjdm.PROMPT = '\#'
                            sshjdm.login (jdmip,jdmusername,password=jdmpassword, port=22,auto_prompt_reset=False,original_prompt='\#')
                            #Get virsh list
                            sshjdm.sendline (jdmvirsh)  # run a command
                            sshjdm.prompt()             # match the prompt
                            print jdmname + sshjdm.before
                            sshjdm.logout()
                            
                            
                        except pxssh.ExceptionPxssh, e:
                            print jdmname + "jdm failed on login."
                            print str(e)
                            continue
                        except pxssh.TIMEOUT, e:
                            print str(e)
                            continue
#option -i isshowint
#show interface stats for a host interface, usefule for RB or FW we don't have access to.
def showint():
    print 'option -i show interface stats for a host interface'
    virshlis = jdmcheck()
    try: 
        sshjdm = pxssh.pxssh()
        print 'You can view any vm interface stats, one at a time, useful when you don\'t have access to some vm... \n'
        sshjdm.PROMPT = '\#'
        sshjdm.login (jdmip,jdmusername,password=jdmpassword, port=22,auto_prompt_reset=False,original_prompt='\#')    
        i = 1
        print 'vm list:'
        for line in virshlis:
            print line
        vmselect = raw_input('Input vm name, copy one from above list :').strip()
        print 'interface list:'
        interfacelist = os.popen('cat ucpetmp/tmpfileif-' + vmselect).read()
        print removefirstlastline(interfacelist)
        ifselect = raw_input('Input interface name, copy one from above list, such as vnetX :').strip()
        
        sshjdm.sendline ('virsh domifstat ' + vmselect + ' ' + ifselect )  # run a command
        sshjdm.prompt()             # match the prompt       
        ifstat = sshjdm.before
        print removefirstlastline(ifstat)
        countlist = {}
        
        for line in ifstat.split('\n'):                    
            if len(line.split()) == 3:
                key = line.split()[1]
                count = line.split()[2]  
                countlist.update({key : count})
                #print countlist
        ifmonitor = raw_input('Continue to monitor every 10 secs, until Ctrl-C ? y/n: [n]') or 'n'
        if ifmonitor == 'y':            
                newcountlist1 = {}                
                newcountlist2 = countlist                
            
                i = 0
                
                while i < 99999:
                    try:
                        time.sleep(10)
                        i += 1
                        sshjdm.sendline ('virsh domifstat ' + vmselect + ' ' + ifselect )  
                        sshjdm.prompt()                   
                        ifstat = sshjdm.before
                        for line in ifstat.split('\n'):                            
                            if len(line.split()) == 3:
                                key = line.split()[1]
                                count = line.split()[2]
                                newcountlist1.update({key : count})
                        print '-----------------------'
                        print 'VM: ' + vmselect + ' Int: ' + ifselect + ' Stats:    ' + str(i*10) + 'seconds passed'
                        print '-----------------------'
                        
                        for key in newcountlist1:                       
                            
                            delta2 = int(newcountlist1[key]) - int(newcountlist2[key])                            
                            print key + ' ' *(12-len(key))+ newcountlist1[key] + ' '*(12-len(newcountlist1[key])) + '10sec Delta: ' + str(delta2) \
 + ' '*(12-len(str(delta2))) + 'rate:'  + str(delta2/10) + '/sec'        
                                               
                        
                        time.sleep(10)
                        i += 1
                        sshjdm.sendline ('virsh domifstat ' + vmselect + ' ' + ifselect )  
                        sshjdm.prompt()                   
                        ifstat = sshjdm.before
                        for line in ifstat.split('\n'):                            
                            if len(line.split()) == 3:
                                key = line.split()[1]
                                count = line.split()[2]
                                newcountlist2.update({key : count})                               
                                
                        print '-----------------------'
                        print 'VM: ' + vmselect + ' Int: ' + ifselect + '  Stats:    ' + str(i*10) + 'seconds passed'
                        print '-----------------------'
                        for key in newcountlist2:                       
                            
                            delta2 = int(newcountlist2[key]) - int(newcountlist1[key])                            
                            print key + ' ' *(12-len(key))+ newcountlist2[key] + ' '*(12-len(newcountlist2[key])) + '10sec Delta: ' + str(delta2) \
 + ' '*(12-len(str(delta2))) + 'rate:'  + str(delta2/10) + '/sec'
                         
                    except KeyboardInterrupt:
                        print 'Exiting..'
                        sys.exit(0)
                         
            
        else:
            print interfacelist
            ifselectagain = raw_input('Input another interface name to check or q to quit: [q]') or 'q'
            while ifselectagain <> 'q':

                sshjdm.sendline ('virsh domifstat ' + vmselect + ' ' + ifselectagain )  
                sshjdm.prompt()                    
                ifstat = sshjdm.before
                print removefirstlastline(ifstat)
                print '-------'
                print removefirstlastline(interfacelist)
                ifselectagain = raw_input('Input another interface name, q to quit: [q]') or 'q'
            print 'Exiting..'
            sys.exit()

        
    except pxssh.ExceptionPxssh, e:
        print "jdm failed on login."
        print str(e)
        sys.exit()
        
#option: -b isbridge
#print a mac table for each bridge, trying to add VM and Vinterface information to the originale mac table
def jdmcheckmore():
    virshlis = jdmcheck()
    try: 
        sshjdm = pxssh.pxssh()
        print 'This output is trying to interpret original MAC table by adding VM name and Vnet interface name to it. \n\
2 management bridges:\n\
1>internal management IP:192.168.0.x \n\
JDM:bme1 JCP:em2 vSRX:fxp0 BRIDGE name:virbr0 \n\n\
\
2>OAM management IP:12.x or IPV6  \n\
JDM eth0 JCP:em0 vSRX:ge-0/0/0 BRIDGE name:eth0br0 \n'
        
        print ('Checking JDM for more...')
        sshjdm.PROMPT = '\#'
        sshjdm.login (jdmip,jdmusername,password=jdmpassword, port=22,auto_prompt_reset=False,original_prompt='\#')

            

        #get bridge list
        fp = open("ucpetmp/tmpfilebridge")
        bridges = []
        for i, line in enumerate(fp):
            if i > 1 and len(line.split()) > 1:
                bridges.append(line.split()[0])
        fp.close()
        #print bridges
        
        #Get virsh list domain/vm mapping to vnet
        domainvnetmapping = dict()
        for virsh in virshlis:
            iffilename = "ucpetmp/tmpfileif-"+virsh
            iffile = open(iffilename)
            
            for line in iffile.read().split('\n'):
                if len(line.split()) == 5:
                    source = line.split()[2]
                    ifname = line.split()[0]
                    MAC = line.split()[4]
                    #print source,ifname,MAC
                    if source in bridges:
                        domainvnetmapping.update({ifname : virsh})

        #Get JDM domain/vm mapping to vnet    
        jdmiffile = open('ucpetmp/tmpfileif-jdm')
        
        for line in jdmiffile.read().split('\n'):
            if len(line.split()) == 5:
                source = line.split()[2]
                ifname = line.split()[0]
                MAC = line.split()[4]
                #print source,ifname,MAC
                if source in bridges:
                    domainvnetmapping.update({ifname : 'JDM'})   
        #print domainvnetmapping                        
       
        vnetportmapping = dict()
        for name in bridges:
            
            sshjdm.sendline ('jhost brctl showstp ' + name )  # run a command
            sshjdm.prompt()             # match the prompt       
            stp = sshjdm.before
            #stp = removefirstlastline(stp)
            sshjdm.sendline ('jhost brctl showmacs ' + name )
            sshjdm.prompt()             # match the prompt       
            macs = sshjdm.before
            macfilename = "ucpetmp/tmpfilemac-" + name
            macfile = open(macfilename, "w")
            macfile.write(macs)
            macfile.flush()            
            macfile.close

            print '------------------------------'
            print '\nMAC table for bridge:' + name + ' :\n'
            #get vnet mapping to port
            for line in stp.split('\n'):
                if "(" in line:
                    port = line.split()[1].replace("(","").replace(")","")
                    vnet = line.split()[0]
                    #print port

                    update = vnetportmapping.update({port : vnet})
            
            #print vnetportmapping
            macfile2 = open(macfilename).read()
            macfile2 = removefirstlastline(macfile2)
            #Print the mac table line by line, if a port can be mapped to vnet or vm name, preppend to mac table.              
            for line2 in macfile2.split('\n'):
                if len(line2.split()) > 0:
                    space = 32
                    key = line2.split()[0]
                    if key in vnetportmapping:                    
                        vnet = vnetportmapping[key]
                        line2 =  vnet + ':' + line2                 #adding vnet information
                        space = 31 - len(vnet)
                        if vnet in domainvnetmapping:                                                      
                            domain = domainvnetmapping[vnet]
                            space = space - 1 - len(domain)
                            line2 =  domain + ':' + ' '*space + line2 #adding vm information
                            
                            print line2
                        else:
                            print ' '*space + line2
                    else:
                        print ' '*space + line2                
    
        sshjdm.logout()
    except pxssh.ExceptionPxssh, e:
        print "jdm failed on login."
        print str(e)
        sys.exit()
    

def guessjcpip():
    jcpip = jdmip[:-1] + '4'
    return jcpip

#Get JCP MAC table
def jcpfile():
    jcpip = guessjcpip()
    try:  
        sshjcp = pxssh.pxssh()    
        jcpip = raw_input('Input JCP IP address: else enter to accept best guess:' + jcpip + ' : ') or jcpip
        print('Checking JCP...')
        sshjcp.PROMPT = '\>'
        sshjcp.login (jcpip,jcpusername,password=jcppassword, port=22,auto_prompt_reset=False,original_prompt='\>')
        time.sleep(10)
        sshjcp.sendline ('show ethernet-switching table | no-more')  # run a command

        
        sshjcp.prompt()             # match the prompt
        macfile = open("ucpetmp/tmpfilemac", "w")
        macfilecontent = sshjcp.before
        macfilecontent = macfilecontent.replace('---(more)---','')
        macfilecontent = macfilecontent.replace('---(more 100%)---','')        
        macfile.write(macfilecontent)
        macfile.close()    
        sshjcp.logout()
    except pxssh.ExceptionPxssh, e:
        print "jcp failed on login."
        print str(e)
        sys.exit()
        
#Get ARP table from Juniper router
def srxfile():
    try: 
        sshsrx = pxssh.pxssh()
        srxusername = jcpusername
        srxpassword = jcppassword
        sshsrx.PROMPT = '\>'
        sshsrx.login (srxhostname,srxusername,password=srxpassword, port=22,auto_prompt_reset=False,original_prompt='\>')
        #time.sleep(20)
        sshsrx.sendline ('show arp | no-more')  # run a command
        sshsrx.sendline (' ')
        sshsrx.sendline (' ')
        sshsrx.sendline (' ')
        sshsrx.prompt()             # match the prompt     
        macfile = open("ucpetmp/tmpfilesrxarp", "w")
        macfile.write(sshsrx.before)      
        macfile.close()        
        sshsrx.logout()
        time.sleep(5)
    except pxssh.ExceptionPxssh, e:
        print "SRX failed on login."
        print str(e)
        sys.exit()
#Get BGP neighbor       
def srxfile2():
    try: 
        sshsrx = pxssh.pxssh()
        srxusername = jcpusername
        srxpassword = jcppassword
        sshsrx.PROMPT = '\>'
        sshsrx.login (srxhostname,srxusername,password=srxpassword, port=22,auto_prompt_reset=False,original_prompt='\>')


        sshsrx.PROMPT = '\>'
        #sshsrx.sendline ('show configuration \| display set \| match neighb \| match BGP_WAN_V4')
        sshsrx.sendline ('show bgp summary')
        sshsrx.prompt()
        bgpfile = open("ucpetmp/tmpfilesrxbgp", "w")
        bgpfile.write(sshsrx.before)
        bgpfile.close()      
        
        sshsrx.logout()
    except pxssh.ExceptionPxssh, e:
        print "SRX failed on login."
        print str(e)
        sys.exit()

        
#Get ARP table from Cisco router
def csrfile():
    try: 
        sshcsr = pxssh.pxssh()
        csrusername = jcpusername
        csrpassword = jcppassword
        sshcsr.PROMPT = '\>'
        sshcsr.login (csrhostname,csrusername,password=csrpassword, port=22,auto_prompt_reset=False,original_prompt='\>')
        #Get ARP table
        sshcsr.sendline ('ter len 0')
        sshcsr.prompt() 
        sshcsr.sendline ('show ip arp')  # run a command
        sshcsr.sendline (' ')
        sshcsr.sendline (' ')
        sshcsr.sendline (' ')
        sshcsr.prompt()             # match the prompt            
        csrarpfile = open("ucpetmp/tmpfilecsrarp", "w")
        csrarpfile.write(sshcsr.before)
        csrarpfile.close()

 
        sshcsr.logout()
    except pxssh.ExceptionPxssh, e:
        print "CSR failed on login."
        print str(e)
        sys.exit()

#Get BGP neighbor for CSR
   
def csrfile2():
    try: 
        sshcsr = pxssh.pxssh()
        csrusername = jcpusername
        csrpassword = jcppassword
        sshcsr.PROMPT = '\>'
        sshcsr.login (csrhostname,csrusername,password=csrpassword, port=22,auto_prompt_reset=False,original_prompt='\>')
        sshcsr.sendline ('show ip bgp sum')  
        sshcsr.prompt()                
        bgpfile = open("ucpetmp/tmpfilecsrbgp", "w")
        bgpfile.write(sshcsr.before)
        bgpfile.close() 
        sshcsr.logout()
    except pxssh.ExceptionPxssh, e:
        print "CSR failed on login."
        print str(e)
        sys.exit()
#Get BGP neighbor Internet vrf    for CSR
def csrfileinet():      
    try: 
        sshcsr = pxssh.pxssh()
        #csrhostname = raw_input('CSR IP address: ')
        csrusername = jcpusername
        csrpassword = jcppassword
        sshcsr.PROMPT = '\>'
        sshcsr.login (csrhostname,csrusername,password=csrpassword, port=22,auto_prompt_reset=False,original_prompt='\>')
        sshcsr.sendline ('show ip bgp vpnv4 vrf _INTERNET_ sum')  
        sshcsr.prompt()                
        bgpfile = open("ucpetmp/tmpfilecsrinetbgp", "w")
        bgpfile.write(sshcsr.before)
        bgpfile.close() 
        sshcsr.logout()
    except pxssh.ExceptionPxssh, e:
        print "CSR failed on login."
        print str(e)
        sys.exit()       



        
#Convert Cisco format to Juniper format if c2j, convert juniper to cisco if j2c
def convertmac (form,addr):
       if "." in addr:
          delimiter = "."
       elif ":" in addr:
          delimiter = ":"
       elif "-" in addr:
          delimiter = "-"

       # Eliminate the delimiter
       m = addr.replace(delimiter, "")
       m = m.lower()
       u = m.upper()

       # convert!
       cisco= ".".join(["%s%s%s%s" % (m[i], m[i+1], m[i+2], m[i+3]) for i in range(0,12,4)])
       eui= ":".join(["%s%s" % (m[i], m[i+1]) for i in range(0,12,2)])
       ms= "-".join(["%s%s" % (u[i], u[i+1]) for i in range(0,12,2)])
       if form == 'c2j':
           return eui
       if form == 'j2c':
           return cisco


def guesscsrip():
    csrip = jdmip[:-1] + '3'
    return csrip
def guesssrxip():
    srxip = jdmip[:-1] + '3'
    return srxip
def guessjcpip():
    jcpip = jdmip[:-1] + '4'
    return jcpip


def getcsrpeip():
    if not os.path.getsize('ucpetmp/tmpfilecsrbgp') > 50:
       print ('something is wong, cant find bgp sum.')
       sys.exit()    
    greppeip = os.popen('cat ucpetmp/tmpfilecsrbgp | egrep -h "13979|21302|21326|8034|8035"').read()
    peip = greppeip.split()[0]
    return peip
def getcsrinetpeip():
    if not os.path.getsize('ucpetmp/tmpfilecsrinetbgp') > 70:
       print ('something is wong, cant find Internet vrf bgp sum.')
       sys.exit()    
    greppeip = os.popen('cat ucpetmp/tmpfilecsrinetbgp | egrep -h "13979|21302|21326|8034|8035"').read()
    peip = greppeip.split()[0]
    return peip
def getsrxpeip():
    peip = ''
    if not os.path.getsize('ucpetmp/tmpfilesrxbgp') > 33:
       print ('something is wong, cant find bgp sum.')
       sys.exit()
    greppeip =os.popen('cat ucpetmp/tmpfilesrxbgp | egrep -h "13979|21302|21326|8034|8035" | grep -v 2001:').read()
    if not len(greppeip) > 0:
        print "failed to get PE IP address."
        peip = 'not found'
    if peip <> 'not found':
        peip = greppeip.split()[0]
    return peip

def getsrxlanint(srxlanintmain):
    try: 
        sshsrx = pxssh.pxssh()
        srxusername = jcpusername
        srxpassword = jcppassword
        sshsrx.PROMPT = '\>'
        sshsrx.login (srxhostname,srxusername,password=srxpassword, port=22,auto_prompt_reset=False,original_prompt='\>')
        #print srxlanintmain
        sshsrx.sendline ('show int '+ srxlanintmain)  # run a command
        sshsrx.sendline (' ')
        sshsrx.sendline (' ')        
        sshsrx.prompt()             # match the prompt
        #print sshjcp.before        
        lanfile = open("ucpetmp/tmpfilelanint", "w")
        lanfile.write(sshsrx.before)
        lanfile.close()
        sshsrx.logout()
        time.sleep(4)

    except pxssh.ExceptionPxssh, e:
        print "SRX failed on login."
        print str(e)
        sys.exit()
        
def getsrxwanint(srxwanintmain):
    try: 
        sshsrx = pxssh.pxssh()
        srxusername = jcpusername
        srxpassword = jcppassword
        sshsrx.PROMPT = '\>'
        sshsrx.login (srxhostname,srxusername,password=srxpassword, port=22,auto_prompt_reset=False,original_prompt='\>')


        #print srxwanintmain
        sshsrx.sendline ('show int '+ srxwanintmain)
        sshsrx.sendline (' ')
        sshsrx.sendline (' ')
        sshsrx.prompt()                
        wanfile = open("ucpetmp/tmpfilewanint", "w")
        wanfile.write(sshsrx.before)        
        wanfile.close()      
        
        sshsrx.logout()
    except pxssh.ExceptionPxssh, e:
        print "SRX failed on login."
        print str(e)
        sys.exit()







#Print bridge name, description and vnet name   
def fwxml(): #tested

    #assume initial xml file is at /var/third-party/vFW_fortigate.xml
    if not os.path.getsize('ucpetmp/tmpfilefwxml') > 200:
       print os.path.getsize('ucpetmp/tmpfilefwxml')
       print ('something is wong, cant find firewall thirdparty xml.')
       sys.exit()
    #print os.path.getsize('ucpetmp/tmpfilefwxml')
    os.system('cat ucpetmp/tmpfilefwxml |  grep \'source bridge\' -B 2 -A 1 >  ucpetmp/tmpfilefwxmlgrep')
    print ("\nHere is vFW bridge descriptions learned from 3rd party xml:\n")
    print open('ucpetmp/tmpfilefwxmlgrep', 'r').read()


    grepxml = os.popen('cat ucpetmp/tmpfilefwxmlgrep | grep source').read()
    bridgenames = re.findall(r"'(.*?)'", grepxml, re.DOTALL)

    i = 0
    print ('Here is interface information learned from dumped xml')
    print ('vFW bridgename -- Vnetname -- interface MAC address')
    while (i < len(bridgenames)):           
       grepfwiflist = os.popen('cat ' + fwiffilename + ' | grep ' + bridgenames[i]).read()
       fwvnetname = grepfwiflist.split()[0]
       fwmac = grepfwiflist.split()[-1]
       print (bridgenames[i] + '       -- ' + fwvnetname + ' -- '+ fwmac)
       i += 1




        

#Print RB Lan interface and WAN interface bridge  
def rbxml():
    if not os.path.getsize('./ucpetmp/tmpfilerbxml') > 200:
        #print os.path.getsize('./ucpetmp/tmpfilerbxml')
        print ('something is wong, cant find RB xml file.')
        sys.exit()
        
    xml = "ucpetmp/tmpfilerbxml"
    doc = libxml2.parseFile(xml) 
    ctxt = doc.xpathNewContext() 
    record_nodes = ctxt.xpathEval('/domain/devices/interface')

    bridgenames = {}
    for node in record_nodes:
        ctxt.setContextNode(node)
        bridgename = ctxt.xpathEval('source')[0].prop('bridge')
        interfacename = ctxt.xpathEval('alias')[0].prop('name')
        if  interfacename == 'lan':
            print '---RB LAN interface bridge name is: ' + bridgename
            bridgenames.update({interfacename : bridgename})
        if  interfacename == 'wan':
            bridgename = ctxt.xpathEval('source')[0].prop('bridge')
            print '---RB WAN interface bridge name is: ' + bridgename
            bridgenames.update({interfacename : bridgename})
        if  interfacename == 'primary':
            bridgename = ctxt.xpathEval('source')[0].prop('bridge')
            print '---RB Primary interface bridge name is: ' + bridgename
            bridgenames.update({interfacename : bridgename})
    rblanint = bridgenames['lan']
    rbwanint = bridgenames['wan']
    return rblanint,rbwanint
    
    
    
def tracesrx():  #tested

    if not os.path.getsize('ucpetmp/tmpfilesrxarp') > 0 or (not os.path.isfile('ucpetmp/tmpfilesrxarp')):
       print ('something is wong, cant find csr arp file.')
       sys.exit()
    if not os.path.getsize('ucpetmp/tmpfilemac') > 0 or (not os.path.isfile('ucpetmp/tmpfilemac')):
       print ('something is wong, cant find mac file.')
       sys.exit()    

    if LANMAC: #need to get LAN IP fro LAN MAC
        lanmac = guesslanmac
        greplanip = os.popen('cat ucpetmp/tmpfilesrxarp | grep ' + lanmac).read()
        if len(greplanip) > 0:
            lanip = greplanip.strip().split()[1]
        else:
            print 'First MAC has no valid ARP...'
            lanip = 'noip'
            sys.exit() #this should be checked already in case it still happens, just exit.
            
        
       

    #print lanip    
    greplan = os.popen('cat ucpetmp/tmpfilesrxarp | grep ' + lanip).read().strip()
    if not LANMAC:    #we will have LAN IP but no LAN MAC   
        lanmac = greplan[0:18]
    greplanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + lanmac).read()
    splitlan = greplan.split()
    splitlanmac = greplanmac.split()    
    
    
    grepwan = os.popen('cat ucpetmp/tmpfilesrxarp | grep ' + peip).read().strip()
    wanmac = grepwan[0:18]
    grepwanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + wanmac).read()    
    splitwan = grepwan.split()    
    splitwanmac = grepwanmac.split()


    jcplanin = splitlanmac[4] 
    srxlanint = splitlan[3]
    srxwanint = splitwan[3]
    jcpwanout = splitwanmac[4]

    srxlanintmain = srxlanint.split('.')[0]
    srxwanintmain = srxwanint.split('.')[0]
    print('Checking path...')
    getsrxlanint(srxlanintmain)
    getsrxwanint(srxwanintmain)
    print('Checking path done.')


    srxlanintmac = os.popen('cat ucpetmp/tmpfilelanint | grep Hardware').read().strip()[-17:]
    srxwanintmac = os.popen('cat ucpetmp/tmpfilewanint | grep Hardware').read().strip()[-17:]
    

    stringjcp2srx = cmdline('cat ucpetmp/tmpfilemac | grep ' + srxlanintmac)
    splitjcp2srx = stringjcp2srx.split()
    splitsrx2jcp = os.popen('cat ucpetmp/tmpfilemac | grep ' + srxwanintmac).read().split()
    #print splitjcp2srx
    jcp2srx = splitjcp2srx[4]
    srx2jcp = splitsrx2jcp[4]
    jcp2srxvlanid = splitjcp2srx[0]
    srx2jcpvlanid = splitsrx2jcp[0]    
    return jcplanin,jcpwanout,srxlanint,srxwanint,jcp2srx,jcp2srxvlanid,srx2jcp,srx2jcpvlanid,lanip



def tracesrxnoip():  #tested?
    #greplan = os.popen('cat ucpetmp/tmpfilesrxarp | grep ' + lanip).read().strip()
    grepwan = os.popen('cat ucpetmp/tmpfilesrxarp | grep ' + peip).read().strip()
    #lanmac = greplan[0:18]
    wanmac = grepwan[0:18]
    #greplanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + lanmac).read()
    grepwanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + wanmac).read()


    #splitlan = greplan.split()
    splitwan = grepwan.split()
    #splitlanmac = greplanmac.split()
    splitwanmac = grepwanmac.split()


    #jcplanin = splitlanmac[4] 
    #srxlanint = splitlan[3]
    srxwanint = splitwan[3]
    jcpwanout = splitwanmac[4]

    #srxlanintmain = srxlanint.split('.')[0]
    srxwanintmain = srxwanint.split('.')[0]
    print('Checking WAN path...')
    #getsrxlanint(srxlanintmain)
    getsrxwanint(srxwanintmain)
    print('Checking WAN path done.')


    #srxlanintmac = os.popen('cat ucpetmp/tmpfilelanint | grep Hardware').read().strip()[-17:]
    srxwanintmac = os.popen('cat ucpetmp/tmpfilewanint | grep Hardware').read().strip()[-17:]


    #splitjcp2srx = os.popen('cat ucpetmp/tmpfilemac | grep ' + srxlanintmac).read().split()
    splitsrx2jcp = os.popen('cat ucpetmp/tmpfilemac | grep ' + srxwanintmac).read().split()
    #jcp2srx = splitjcp2srx[4]
    srx2jcp = splitsrx2jcp[4]
    #print jcplanin,jcpwanout,srxlanint,srxwanint,jcp2srx,srx2jcp
    #return jcplanin,jcpwanout,srxlanint,srxwanint,jcp2srx,srx2jcp
    return jcpwanout,srxwanint,srx2jcp



def tracecsrmacfwnoip(): #not tested

    greppe = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + peip).read()
    splitpe = greppe.split()
    pemacciscoformat = splitpe[3]
    greppemac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',pemacciscoformat)).read()
    splitpemac = greppemac.split()
    jcpwanout = splitpemac[4]

    grepfw = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + fwip).read()
    splitfw = grepfw.split()
    csrlanint = splitfw[5]
    csrwanint = splitpe[5]
    grepcsrwanint = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + csrwanint + ' | grep -').read()
    splitcsrwanint = grepcsrwanint.split()
    wanmacciscoformat = splitcsrwanint[3]
    
    grepwanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',wanmacciscoformat)).read()
    splitsrxwanint = grepwanmac.split()
    csr2jcp = splitcsrwanint[4]
    csr2jcpvlanid = splitcsrwanint[0]

    #for Internet vrf

    grepIpe = os.popen('cat ucpetmp/tmpfilecsrIarp | grep ' + inetpeip).read()
    splitIpe = grepIpe.split()
    Ipemacciscoformat = splitIpe[3]
    grepIpemac = os.popen('cat ucpetmp/tmpfilemac | grep ' +   ac('c2j',Ipemacciscoformat)).read()
    splitIpemac = grepIpemac.split()
    jcpIwanout = splitIpemac[4]

    grepIfw = os.popen('cat ucpetmp/tmpfilecsrIarp | grep ' + inetfwip).read()
    splitIfw = grepIfw.split()
    csrIlanint = splitIfw[5]
    csrIwanint = splitIpe[5]


    csrI2jcpvlanid = splitIpemac[0]
    return jcpwanout,csrlanint,csrwanint,csr2jcp, csr2jcpvlanid,jcpIwanout,csrIlanin,csrIwanint,csrI2jcpvlanid

def tracecsrip(): # Return 6 interface names #
    #jcp int facing PE
    if not os.path.getsize('ucpetmp/tmpfilecsrarp') > 0:
       print ('something is wong, cant find csr arp file.')
       exit()
    if not os.path.getsize('ucpetmp/tmpfilemac') > 0:
       print ('something is wong, cant find mac file.')
       exit()
    greppe = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + peip).read()
    if not len(greppe)>0:
        print len(greppe)
        print 'can\'t find arp for PE'
        sys.exit()
    splitpe = greppe.split()
    pemacciscoformat = splitpe[3]
    greppemac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',pemacciscoformat)).read()
    splitpemac = greppemac.split()
    jcpwanout = splitpemac[4]

    #csr lanint and wanint
    greplan = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + lanip).read()
    splitlan = greplan.split()
    csrlanint = splitlan[5]
    csrwanint = splitpe[5]

    #jcp int facing csr wan int
    grepcsrwanint = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + csrwanint + ' | grep -').read()
    splitcsrwanint = grepcsrwanint.split()
    wanmacciscoformat = splitcsrwanint[3]
    grepwanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',wanmacciscoformat)).read()
    splitcsrwanint = grepwanmac.split()
    csr2jcp = splitcsrwanint[4]
    csr2jcpvlanid = splitcsrwanint[0]

    #jcp  int facing customer
    greplan = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + lanip).read()
    splitlan = greplan.split()
    lanmacciscoformat = splitlan[3]
    greplanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',lanmacciscoformat)).read()
    splitlanmac = greplanmac.split()
    jcplanin = splitlanmac[4]

    #jcp int facing csr lan int
    grepcsrlanint = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + csrlanint + ' | grep -').read()
    splitcsrlanint = grepcsrlanint.split()
    llanmacciscoformat = splitcsrlanint[3]
    greplanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',llanmacciscoformat)).read()
    splitcsrlanint = greplanmac.split()
    jcp2csr = splitcsrlanint[4]
    #jcp2csrvlanid = splitcsrlanint[0]
    jcp2csrvlanid = 'Vlan:' + csrlanint.split('.')[1]

    return jcpwanout,csrlanint,csrwanint,csr2jcp,csr2jcpvlanid,jcplanin,jcp2csr,jcp2csrvlanid

def tracecsrmac(): # Return 6 interface names #not tested
    #jcp int facing PE
    if not os.path.getsize('ucpetmp/tmpfilecsrarp') > 0:
       print ('something is wong, cant find csr arp file.')
       exit()
    if not os.path.getsize('ucpetmp/tmpfilemac') > 5:
       print ('something is wong, cant find mac file.')
       exit()
    greppe = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + peip).read()



    lanmac = guesslanmac
    lanmacciscoformat = convertmac('j2c',lanmac)
    #print lanmacciscoformat
    lanip = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + lanmacciscoformat).read().strip().split()[1]
    greplan = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + lanip).read().strip()
        
       
    
    if not len(greppe)>0:
        print len(greppe)
        print 'can\'t find arp for PE'
        sys.exit()
    splitpe = greppe.split()
    pemacciscoformat = splitpe[3]
    greppemac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',pemacciscoformat)).read()
    splitpemac = greppemac.split()
    jcpwanout = splitpemac[4]

    #csr lanint and wanint
    greplan = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + lanip).read()
    splitlan = greplan.split()
    csrlanint = splitlan[5]
    csrwanint = splitpe[5]

    #jcp int facing csr wan int
    grepcsrwanint = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + csrwanint + ' | grep -').read()
    splitcsrwanint = grepcsrwanint.split()
    wanmacciscoformat = splitcsrwanint[3]
    grepwanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',wanmacciscoformat)).read()
    splitsrxwanint = grepwanmac.split()
    csr2jcp = splitsrxwanint[4]
    csr2jcpvlanid = splitsrxwanint[0]

    #jcp  int facing customer
    greplanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',lanmacciscoformat)).read()
    splitlanmac = greplanmac.split()
    jcplanin = splitlanmac[4]
    #jcp int facing csr lan int
    grepcsrlanint = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + csrlanint + ' | grep -').read()
    splitcsrlanint = grepcsrlanint.split()
    llanmacciscoformat = splitcsrlanint[3]
    grepllanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',llanmacciscoformat)).read()
    
    splitsrxlanint = grepllanmac.split()
    jcp2csr = splitsrxlanint[4]
    #jcp2csrvlanid = splitsrxlanint[0]
    jcp2csrvlanid = 'Vlan:' + csrlanint.split('.')[1]

    return lanip,jcpwanout,csrlanint,csrwanint,csr2jcp,csr2jcpvlanid,jcplanin,jcp2csr,jcp2csrvlanid

def tracecsrnoip(): # Return 3 interface names #not tested
    #jcp int facing PE
    if not os.path.getsize('ucpetmp/tmpfilecsrarp') > 0:
       print ('something is wong, cant find csr arp file.')
       exit()
    if not os.path.getsize('ucpetmp/tmpfilemac') > 0:
       print ('something is wong, cant find mac file.')
       exit()
    greppe = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + peip).read()
    splitpe = greppe.split()
    pemacciscoformat = splitpe[3]
    greppemac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',pemacciscoformat)).read()
    splitpemac = greppemac.split()
    jcpwanout = splitpemac[4]

    #csr lanint and wanint
    #greplan = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + lanip).read()
    #splitlan = greplan.split()
    #csrlanint = splitlan[5]
    csrwanint = splitpe[5]

    #jcp int facing csr wan int
    grepcsrwanint = os.popen('cat ucpetmp/tmpfilecsrarp | grep ' + csrwanint + ' | grep -').read()
    splitcsrwanint = grepcsrwanint.split()
    wanmacciscoformat = splitcsrwanint[3]
    grepwanmac = os.popen('cat ucpetmp/tmpfilemac | grep ' + convertmac('c2j',wanmacciscoformat)).read()
    splitsrxwanint = grepwanmac.split()
    csr2jcp = splitsrxwanint[4]
    csr2jcpvlanid = splitsrxwanint[0]
    return jcpwanout,csrwanint,csr2jcp,csr2jcpvlanid

#main


tmpdir = 'ucpetmp'
if not os.path.exists(tmpdir):
            os.makedirs(tmpdir)
inittempfile = os.system('rm -f ucpetmp/tmpfile*')
            
#option -a check all jdm in nlist
if options.ischeckall:
    checkall()
    sys.exit()


#options.isprogress : check script completion
if options.isprogress:
    os.system('cat ucpe.py | egrep -h "Next|working" | grep -v grep')
    sys.exit()
    
#checks if input has zz01 jdm01 or 2001: else will quit
print ('JDM hostname format xxxJDM01 or xxxZZ01, temp files will be created in ./ucpetmp.')
jdmhostname = raw_input('Input JDM IP/hostname: ')
if 'ZZ01' in jdmhostname or 'zz01' in jdmhostname or 'JDM01' in jdmhostname or 'jdm01' in jdmhostname:
    jdmip = resolvename(jdmhostname).strip()
elif '2001:' in jdmhostname:
    jdmip = jdmhostname.strip()
else:
    print ('Wrong jdm hostname/IP, exiting..')
    sys.exit()
    
#if not skip ping
    
if not options.isskipping:
    pingjdm()


#option -q : save me from qos headache
if options.issrxqos:
    srxqos()
    sys.exit()



    
#option -v : print sysinfo
if options.isshowver:
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')
    showver()
    sys.exit()

#option -V : print more sysinfo
if options.isshowvermore:
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')
    showvermore()
    sys.exit()

#options.isbridge : print anvanced mac tables 
if options.isbridge:
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')
    jdmcheckmore()
    sys.exit()
    
#options.isshowint : print interface stats
if options.isshowint:
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')
    showint()
    sys.exit()

    

#option:nojdm : skip jdm if no access to jdm or want to test script
skipjdm = options.isnojdm
if skipjdm:
    SRX = False
    CSR = False
    SRXFW = False
    CSRFW = False
    SRXRB = False
    CSRRB = False
    SRXFWRB = False
    CSRFWRB = False
    print('Select from following vnf profiles:')
    print('1> Only SRX, no FW or RB')
    print('2> Only CSR, no FW or RB')
    print('3> SRX + FW')
    print('4> CSR + FW')
    print('5> SRX + RB')
    print('6> CSR + RB')
    print('7> SRX + FW + RB')
    print('8> CSR + FW + RB')
    print('9> Check XML files')
    print('11>SRX + Internet vrf')
    print('22>CSR + Internet vrf')
    print('33>SRX + FW + Internet vrf')
    print('44>CSR + FW + Internet vrf')
    vmselect = raw_input ('Select setup options[1-8]:')
    if vmselect == '1':
        SRX = True
    if vmselect == '2':
        CSR = True
    if vmselect == '3' or vmselect == '33' :
        SRXFW = True
    if vmselect == '4':
        CSRFW = True
    if vmselect == '5':
        SRXRB = True
    if vmselect == '6':
        CSRRB = True
    if vmselect == '7':
        SRXFWRB = True
    if vmselect == '8':
        CSRFWRB = True
    if vmselect == '9':
        XMLONLY = True
    else:
        print ('not valid option')
        sys.exit()
    skipxml = True
    
#by default not skipping jdm check
#finding vm information from virsh list    
elif not skipjdm:
    skipxml = False
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')
    
    virshlis = jdmcheck()   #getting virsh list and other files from JDM
    print('Virsh list result:')
    ISSRX = False
    ISCSR = False
    if 'vsrx' in virshlis:
        ISSRX = True
        print "---We have vSRX"    
    if 'vcsr' in virshlis:
        ISCSR = True
        print "---We have vCSR"
    ISFW = False
    ISRB = False
    XMLONLY = False
    virsh = ''
    for virsh in virshlis:
        if 'FW0' in virsh or 'vFW' in virsh or 'vfw' in virsh:
            ISFW = True
            fwdomain = virsh
            fwfilename = "ucpetmp/tmpfilexml-"+virsh
            fwiffilename = "ucpetmp/tmpfileif-"+virsh
            print "---We have vFW"
        if 'WX0' in virsh:
            ISRB = True
            rbdomain = virsh
            rbfilename = "ucpetmp/tmpfilexml-"+virsh
            rbiffilename = "ucpetmp/tmpfileif-"+virsh
            print "---We have Riverbed"
    ifcontinue = raw_input('Continue further? y/n: ')
    if not ifcontinue.strip() == 'y':
        sys.exit()
    SRX = ISSRX and (not ISFW) and (not ISRB)
    CSR = ISCSR and (not ISFW) and (not ISRB)
    SRXFW = ISSRX and ISFW and (not ISRB)
    CSRFW = ISCSR and ISFW and (not ISRB)
    SRXRB = ISSRX and (not ISFW) and ISRB
    CSRRB = ISCSR and (not ISFW) and ISRB
    SRXFWRB = ISSRX and ISFW and ISRB
    CSRFWRB = ISCSR and ISFW and ISRB
else :
    print ('something wrong')
    sys.exit()
jcpusername = raw_input('JCP GTAC username: ') 
jcppassword = getpass.getpass('JCP GTAC password: ')    
ARPALREADY = False   
arrow = ' -> '
bigarrow = '--->'
ba = bigarrow
boxspacing = 1 #box space size default 1 before and after
sp = ' ' * boxspacing

#so far only 3 cases tested: OnlyCSR OnlySRX and CSRRB, CSRFW half tested
if SRX:#tested working
    #tested with JPINTBFSH000101UJDM01 client IP:9.188.150.3 PEIP:9.188.63.49
    #no valid arp example USTESQCHIIL0101UJDM01
    jcpfile() #getting MAC table from JCP
    try:
        guesslanmac = os.popen('cat ucpetmp/tmpfilemac | grep ge-0/0/0.0' ).read().split()[1]
    except IndexError, e:
        print "Failed to find LAN MAC..."
        guesslanmac = None      
       
    if guesslanmac is not None: #First LAN MAC found, verify if it has valid ARP:
        lanmac = guesslanmac 
        srxhostname = raw_input('Input vSRX IP address, else enter to accept best guess:' + guesssrxip() + ' : ') or guesssrxip()
        print('Checking SRX ARP table...')
        srxfile()
        ARPALREADY = True
        greplanip = os.popen('cat ucpetmp/tmpfilesrxarp | grep ' + lanmac).read()
        if len(greplanip) > 0: # valid ARP for first MAC, continue LAN WAN trace
            lanip = greplanip.strip().split()[1]
            print 'Assume first MAC on JCP ge-0/0/0.0 as customer MAC: ' + guesslanmac
            LANMAC = True
        else:# No valid ARP for first MAC, continue only WAN trace.
            
            print 'First MAC has no valid ARP...'
            lanip = 'noip'
            print('Finding PE IP address..')
            srxfile2() #Getting bgp sum from router
            peip = getsrxpeip()
            peip = raw_input('Input PE IP address, else enter to accept best guess:' + peip + ' : ') or peip
            peip = peip.strip()
            jcpwanout,srxwanint,srx2jcp = tracesrxnoip() #trace path
            path = 'How it goes(without LAN side trace):\n' + 'Customer'  + arrow + 'JCP:'  + arrow + 'JCP:'   + 'trunk' + arrow + 'SRX:' \
            + arrow + 'SRX:' + srxwanint  + 'trunk' + arrow + 'JCP:' + srx2jcp + arrow + 'JCP:' + jcpwanout + arrow + 'PE:'+ peip
            virshfile = open(("resultnoip-" + jdmhostname), "w")
            virshfile.write(path)
            virshfile.close()
            print path

            sys.exit()
            
        

    else:#First LAN MAC not found, manual input
        
        lanip = raw_input('we only have vSRX,trying to trace path..\nPlease provide a live IP address in customer LAN, enter "noip" to trace without LAN side IP,enter "arp" if you need a hint to find LAN side IP:')
        if lanip == 'arp':
            srxhostname = raw_input('Input vSRX IP address, else enter to accept best guess:' + guesssrxip() + ' : ') or guesssrxip()
            print('Checking SRX ARP table...')
            srxfile()
            print ('\nHere is your clue: see anything in vlan 1XXX 3XXX ?')
            print os.popen('cat ucpetmp/tmpfilesrxarp').read()
            lanip = raw_input('Now you seen the ARP. Please provide a live IP address in customer LAN,enter "noip" to trace without LAN side IP:')
            ARPALREADY = True


    #valid ARP for first MAC, continue LAN WAN trace
    
    if not ARPALREADY:
        srxhostname = raw_input('Input vSRX OAM IP address, else enter to accept best guess:' + guesssrxip() + ' : ') or guesssrxip()
        print('Checking SRX ARP table...')
        srxfile() #Getting ARP table from router
    print('Finding PE IP address..')
    srxfile2() #Getting bgp sum from router
    peip = getsrxpeip()
    peip = raw_input('Input PE IP address, else enter to accept best guess:' + peip + ' : ') or peip
    
    if lanip == 'noip':     # only WAN trace      
        jcpwanout,srxwanint,srx2jcp = tracesrxnoip() #trace path
        path = 'How it goes(without LAN side trace):\n' + 'Customer'  + arrow + 'JCP:'  + arrow + 'JCP:'   + 'trunk' + arrow + 'SRX:' \
        + arrow + 'SRX:' + srxwanint  + 'trunk' + arrow + 'JCP:' + srx2jcp + arrow + 'JCP:' + jcpwanout + arrow + 'PE:'+ peip
        virshfile = open(("result-" + jdmhostname), "w")
        virshfile.write(path)
        virshfile.close()
        print path
    else:               #LAN WAN trace

        jcplanin,jcpwanout,srxlanint,srxwanint,jcp2srx,jcp2srxvlanid,srx2jcp,srx2jcpvlanid,lanip = tracesrx() #trace path
        path = 'How it goes:\n' + 'Customer: ' + lanip + arrow + 'JCP:' + jcplanin + arrow + 'JCP:' + jcp2srx + ':trunk:' + jcp2srxvlanid  + arrow + 'SRX:' \
+ srxlanint + arrow + 'SRX:' + srxwanint  + ':trunk'  + arrow + 'JCP:' + srx2jcp + ':' + srx2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE:' + peip
        virshfile = open(("result-" + jdmhostname), "w")
        virshfile.write(path)
        virshfile.close()
        #print path
        

        
        #ba:bigarrow sp:boxspace boxspacing:boxspacenumber 
        path2 = 'Cust' + ba + jcplanin + '|' + sp + bcolors.BOLD + 'JCP' + bcolors.ENDC + sp + '|' + jcp2srx + ba + srxlanint + '|' + sp + bcolors.BOLD + 'SRX'\
+ bcolors.ENDC + sp + '|' + srxwanint + ba + srx2jcp + '|' + sp + bcolors.BOLD  + 'JCP' + bcolors.ENDC + sp + '|' + jcpwanout + ba + 'PE'
        path2top = ' ' * (4 + len(ba) + len (jcplanin)) + '+' + '-'*(boxspacing*2 + 3) + '+' + ' ' * (len(jcp2srx)+ len(ba) + len(srxlanint))\
+ '+' + '-'*(boxspacing*2 + 3) + '+' + ' ' * (len(srxwanint) + len(ba) + len(srx2jcp)) + '+' + '-'*(boxspacing*2 + 3) + '+'
        
        print bcolors.WARNING + '\n---Packet Flow---Between Customer IP:' + lanip + ' and PE IP: ' + peip + '\n'+ bcolors.ENDC
        print path2top
        print path2
        print path2top
        print '\n'

        

      
    
if CSR:#tested working
    #testing with SGTES9SIN000104UJDM01 no client IP bad pass
    #testing with AUCOMSSYD000101UJDM01 client IP 20.253.23.3 20.253.24.3 multiple vlans
    jcpfile() #getting MAC table from JCP
    try:
        guesslanmac = os.popen('cat ucpetmp/tmpfilemac | grep ge-0/0/0.0' ).read().split()[1]
    except IndexError, e:
        print "failed to find LAN MAC."
        guesslanmac = None
    lanip = ''
    if guesslanmac is not None:
         print 'Assume first MAC on JCP ge-0/0/0.0 as customer MAC: ' + guesslanmac
         LANMAC = True
    else:
         LANMAC = False
    #print islanip
    if LANMAC == False or options.islanip: #Use IP to trace
        lanip = raw_input('we only have vCSR,  please provide a live IP address in customer LAN,enter "noip" to trace without LAN side \
IP,enter "arp" if you need a hint to find LAN side IP:')
        if lanip == 'arp':
            csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
            print('Checking CSR ARP table...')
            csrfile() #Getting ARP table from router
            print ('\nHere is your clue: see anything in vlan 1XXX 3XXX ?')
            print os.popen('cat ucpetmp/tmpfilecsrarp').read()
            lanip = raw_input('Now you seen the ARP. Please provide a live IP address in customer LAN,enter "noip" to trace without \
            LAN side IP:')
            ARPALREADY = True
        if lanip == 'noip':
            csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
            print('Checking CSR...')
            csrfile() #Getting ARP table from router
            print('Finding PE IP address..')
            csrfile2() #Getting bgp sum from router
            peip = raw_input('Input PE IP address, else enter to accept best guess:' + getcsrpeip() + ' : ') or getcsrpeip()
        
            jcpwanout,csrwanint,csr2jcp,csr2jcpvlanid = tracecsrnoip()
            path = '\nHow it goes(without LAN side trace):\n' + 'Customer' + arrow + 'JCP:'  + arrow + 'JCP:' + arrow   + 'CSR:'  \
            + csrwanint + arrow + 'JCP:' + csr2jcp  + ':' + csr2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE' + peip + '\n'
            
            print path
        csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
        if not ARPALREADY:            
            print('Checking CSR...')
            csrfile() #Getting ARP table from router
        print('Finding PE IP address..')
        csrfile2() #Getting bgp sum from router
        peip = raw_input('Input PE IP address, else enter to accept best guess:' + getcsrpeip() + ' : ') or getcsrpeip()
        
        jcpwanout,csrlanint,csrwanint,csr2jcp,csr2jcpvlanid,jcplanin,jcp2csr,jcp2csrvlanid = tracecsrip()
        path = '\nHow it goes:\n' + 'Customer: '  + lanip + arrow + 'JCP:' + jcplanin + arrow + 'JCP:' + jcp2csr + ':' + jcp2csrvlanid + arrow   \
        + 'CSR:' +csrlanint + arrow + 'CSR:' +\
        csrwanint + arrow + 'JCP:' + csr2jcp  + ':' + csr2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE:' + peip + '\n'
        #save result to a file
        virshfile = open(("result-" + jdmhostname), "w")
        virshfile.write(path)
        virshfile.close()        
        print path
    if LANMAC == True: #Use MAC to trace
        csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
        print('Checking CSR...')
        csrfile() #Getting ARP table from router
        print('Finding PE IP address..')
        csrfile2() #Getting bgp sum from router
        peip = raw_input('Input PE IP address, else enter to accept best guess:' + getcsrpeip() + ' : ') or getcsrpeip()

    
        lanip,jcpwanout,csrlanint,csrwanint,csr2jcp,csr2jcpvlanid,jcplanin,jcp2csr,jcp2csrvlanid = tracecsrmac()
        path = '\nHow it goes:\n' + 'Customer: ' + guesslanmac + '=' + lanip + arrow + 'JCP:' + jcplanin + arrow + 'JCP:' + jcp2csr + ':' + jcp2csrvlanid + arrow   \
        + 'CSR:' +csrlanint + arrow + 'CSR:' +\
        csrwanint + arrow + 'JCP:' + csr2jcp  + ':' + csr2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE:' + peip + '\n'
        #save result to a file
        virshfile = open(("result-" + jdmhostname), "w")
        virshfile.write(path)
        virshfile.close()        
        #print path

        #ba:bigarrow sp:boxspace boxspacing:boxspacenumber 
        path2 = 'Cust' + ba + jcplanin + '|' + sp + bcolors.BOLD + 'JCP' + bcolors.ENDC + sp + '|' + jcp2csr + ba + csrlanint + '|' + sp + bcolors.BOLD + 'CSR'\
+ bcolors.ENDC + sp + '|' + csrwanint + ba + csr2jcp + '|' + sp + bcolors.BOLD  + 'JCP' + bcolors.ENDC + sp + '|' + jcpwanout + ba + 'PE'
        path2top = ' ' * (4 + len(ba) + len (jcplanin)) + '+' + '-'*(boxspacing*2 + 3) + '+' + ' ' * (len(jcp2csr)+ len(ba) + len(csrlanint))\
+ '+' + '-'*(boxspacing*2 + 3) + '+' + ' ' * (len(csrwanint) + len(ba) + len(csr2jcp)) + '+' + '-'*(boxspacing*2 + 3) + '+'
        
        print bcolors.WARNING + '\n---Packet Flow---Between Customer IP:' + lanip + ' and PE IP: ' + peip + '\n'+ bcolors.ENDC
        print path2top
        print path2
        print path2top
        print '\n'
       
        

      
    
if SRXFW:#working progress
    #testing with CATESCTHOON0113UJDM01 , USTESQCHIIL0101UJDM01 config problem
    if skipxml == False:
        fwxml()   
  
    jcpfile() #getting MAC table from JCP

    lanip = raw_input('vSRX+vFW...Please provide Firewall WAN address, enter "noip" to trace only WAN,enter "arp" to view ARP, else just\
enter to accept best guess: 192.268.1.2:') or '192.168.1.2' 
    if lanip == 'arp':
        srxhostname = raw_input('Input vSRX IP address, else enter to accept best guess:' + guesssrxip() + ' : ') or guesssrxip()
        print('Checking SRX ARP table...')
        srxfile()
        print ('\nHere is your clue: see anything in vlan 4XXX ?')
        print os.popen('cat ucpetmp/tmpfilesrxarp').read()
        lanip = raw_input('Now you seen the ARP. Please provide Firewall WAN IP,enter "noip" to trace without LAN side IP:')
        ARPALREADY = True
            
    srxhostname = raw_input('Input vSRX OAM IP address, else enter to accept best guess:' + guesssrxip() + ' : ') or guesssrxip()
    if not ARPALREADY:
        print('Checking SRX...')
        srxfile() #Getting ARP table from router
    print('Finding PE IP address..')
    srxfile2() #Getting bgp sum from router
    peip = getsrxpeip()
    peip = raw_input('Input PE IP address, else enter to accept best guess:' + peip + ' : ') or peip
    
    if lanip == 'noip':          
        jcpwanout,srxwanint,srx2jcp = tracesrxnoip() #trace only WAN
        path = 'How it goes(without LAN side trace):\n' + 'Customer'  + arrow + 'JCP:'  + arrow + 'JCP:'   + ':trunk' + arrow + 'SRX:' \
        + arrow + 'SRX:' + srxwanint  + 'trunk' + arrow + 'JCP:' + srx2jcp + arrow + 'JCP:' + jcpwanout + arrow + 'PE:'+ peip
        virshfile = open(("result-" + jdmhostname), "w")
        virshfile.write(path)
        virshfile.close()
        print path
    else: 
        jcplanin,jcpwanout,srxlanint,srxwanint,jcp2srx,jcp2srxvlanid,srx2jcp,srx2jcpvlanid,lanip = tracesrx() #trace path
        path = 'How it goes:\n' + 'Customer: ' + lanip + arrow + 'JCP:' + jcplanin + arrow + 'JCP:' + jcp2srx + ':trunk:' + jcp2srxvlanid  + arrow + 'SRX:' \
+ srxlanint + arrow + 'SRX:' + srxwanint  + ':trunk'  + arrow + 'JCP:' + srx2jcp + ':' + srx2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE:' + peip
        virshfile = open(("result-" + jdmhostname), "w")
        virshfile.write(path)
        virshfile.close()
        print path

        
if CSRFW:#working progress
    #tested with USTESBBROGA0107UJDM01 FWIP:192.168.1.2 CSR 2001:1890:e00e:fffe::1743  InetFWIP:192.168.2.2
    #Avpn PEIP:10.46.232.254 InetPEIP:12.122.124.2 no client IP/now bad passwd/now no internet PE
    if skipxml == False:
        fwxml()
    jcpfile()
    lanip = raw_input('we only have vCSR and vFW, please provide a live IP address in customer LAN,enter "noip" to trace without LAN side \
    IP,enter "arp" if you need a hint to find LAN side IP:')
    if lanip == 'arp':
        csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
        print('Checking CSR ARP table...')
        csrfile()
        print ('\nHere is your clue: see anything in vlan 1XXX 3XXX ?')
        print os.popen('cat ucpetmp/tmpfilecsrarp').read()
        lanip = raw_input('Now you seen the ARP. Please provide a live IP address in customer LAN,enter "noip" to trace without \
LAN side IP:')
        ARPALREADY = True
    csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
    if not ARPALREADY:
        print('Checking CSR...')
        csrfile()
    print('Finding PE IP address..')
    csrfile2()
    csrfileinet()
    guesspeip = getcsrpeip()
    peip = raw_input('Input PE IP address, else enter to accept best guess:' + guesspeip + ' : ') or guesspeip
    inetpeip = raw_input("please enter Internet PE IP, default for this box is 12.122.124.2:") or '12.122.124.2'
    fwip = raw_input('Input FW WAN IP address, else enter to accept best guess: 192.268.1.2'  ' : ') or '192.168.1.2'
    guessinetpeip = getcsrinetpeip()
    inetfwip = raw_input('Input FW Internet WAN IP address, else enter to accept best guess:' + guessinetpeip +  ' : ') or guessinetpeip
    lanip = lanip.strip()
    if lanip <> 'noip': 
        print('unfinised...exit')
        sys.exit()
    if lanip == 'noip':
        jcpwanout,csrlanint,csrwanint,csr2jcp, csr2jcpvlanid,jcpIwanout,csrIlanin,csrIwanint,csrI2jcpvlanid = tracecsrmacfwnoip()
        path1 = '\n\nHow AVPN goes:\n' + 'Customer --> JCP-->'  + ' vFW ---> linuxbridge'  + arrow + 'SRX:' + srxlanint + arrow + 'SRX:' + srxwanint + \
        arrow + 'JCP:' + srx2jcp + ' Vlan:' + srx2jcpvlanid +arrow + 'JCP:' + jcpwanout + ' Vlan:' + srx2jcpvlanid + arrow + peip + '-PE\n\n'
      
        path2 = 'How Internet vrf goes:\n' + 'Customer --> JCP-->' + ' vFW ---> linuxbridge' + arrow + 'SRX:' + srxIlanint + arrow + 'SRX:' + srxIwanint + \
        arrow + 'JCP:' + srx2jcp + ' Vlan:' + srxI2jcpvlanid +arrow + 'JCP:' + jcpIwanout + ' Vlan:' + srxI2jcpvlanid + arrow + inetpeip + '-PE\n\n'
        
        print path1
        print path2

if SRXRB:#working progress
    # testing with CATESMTHOON0110UJDM01  USTESGAAIGA0203UJDM01
    print ('we have vSRX and RB,-script not tested- :')
    if skipxml == False:
        rbxml()
    #srxfile()
if CSRRB:#working progress
    #tested with USCROMLYFWA0102UJDM01 client IP: 10.22.129.59 PEIP:10.9.0.1
    if skipxml == False:
        rblanint,rbwanint = rbxml()
    jcpfile()
    LANMAC =  False
    lanip = raw_input('we only have vCSR and Riverbed, please provide a live IP address in customer LAN,enter "noip" to trace without \
LAN side IP, enter "arp" if you need a hint to find LAN side IP:')
    if lanip.strip() == 'arp':
        csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
        print('Checking CSR ARP table...')
        csrfile()
        print ('Here is your clue: see anything in vlan 1XXX 3XXX ?')
        print os.popen('cat ucpetmp/tmpfilecsrarp').read()
        lanip = raw_input('Now you seen the ARP. Please provide a live IP address in customer LAN,enter "noip" to trace without \
        LAN side IP:')
    
    csrhostname = raw_input('Input vCSR IP address, else enter to accept best guess:' + guesscsrip() + ' : ') or guesscsrip()
    print('Checking CSR...')
    csrfile()
    print('Finding PE IP address..')
    csrfile2()
    peip = raw_input('Input PE IP address, else enter to accept best guess:' + getcsrpeip() + ' : ') or getcsrpeip()
    if skipxml:
        print ('noxml')
    if not skipxml:        
        if lanip.strip() <> 'noip': 
            jcpwanout,csrlanint,csrwanint,csr2jcp,csr2jcpvlanid,jcplanin,jcp2csr,jcp2csrvlanid = tracecsrip()
            #print ('\njcpfacingcustomer->jcp2srxlan:vlanid->RBlanbridge->RBlan->RB->RBwan->RBwanbridge->srxlanint->srxwanint>jcp2srxwan:vlanid->jcpfacingPE\n')
            path = '\nHow it goes:\n' + 'Customer:' + lanip + arrow + 'JCP:' + jcplanin + arrow + 'JCP:' + jcp2csr + ':' + jcp2csrvlanid + arrow   \
            + 'Linuxbridge:' + rblanint + arrow + 'RB' + arrow + 'Linuxbridge:' + rbwanint + arrow + 'CSR:' +csrlanint + arrow + 'CSR:' +\
            csrwanint + arrow + 'JCP:' + csr2jcp  + ':' + csr2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE:' + peip +'\n'
            #save result to a file
            virshfile = open(("result-" + jdmhostname), "w")
            virshfile.write(path)
            virshfile.close()
            
            print path
            boxspacing = 0
            sp = ' ' * boxspacing
            arrow = '->'
            #ba:bigarrow sp:boxspace boxspacing:boxspacenumber 
            path2 = 'C' + arrow + jcplanin + '|' + sp + bcolors.BOLD + 'JCP' + bcolors.ENDC + sp + '|' + jcp2csr + arrow + \
rblanint + '|' + sp + bcolors.BOLD + 'RB' + bcolors.ENDC + sp + '|' + rbwanint + arrow + csrlanint + '|' + sp + bcolors.BOLD + 'CSR'\
+ bcolors.ENDC + sp + '|' + csrwanint + arrow + csr2jcp + '|' + sp + bcolors.BOLD  + 'JCP' + bcolors.ENDC + sp + '|' + jcpwanout + arrow + 'PE'
            
            path2top = ' ' * (1 + len(arrow) + len (jcplanin)) + '+' + '-'*(boxspacing*2 + 3) + '+' + ' ' * (len(jcp2csr)+ len(arrow) + len(rblanint)) \
+ '+' + '-'*(boxspacing*2 + 2) + '+' + ' ' * (len(rbwanint) + len(arrow) + len(csrlanint)) +'+' + '-'*(boxspacing*2 + 3) + '+' + ' ' * (len(csrwanint) + len(arrow) \
+ len(csr2jcp)) + '+' + '-'*(boxspacing*2 + 3) + '+'
            
            print bcolors.WARNING + '\n---Packet Flow---Between Customer IP:' + lanip + ' and PE IP: ' + peip + '\n'+ bcolors.ENDC
            print path2top
            print path2
            print path2top
            print '\n'

            
        if lanip.strip() == 'noip':
            jcpwanout,csrwanint,csr2jcp,csr2jcpvlanid = tracecsrnoip()
            path = '\nHow it goes:\n' + 'Customer' + arrow + 'JCP:'  + arrow + 'JCP:' + arrow+ 'Linuxbridge:'  + 'CSR ' + arrow + 'CSR:'  \
            + csrwanint + arrow + 'JCP:' + csr2jcp  + ':' + csr2jcpvlanid + arrow + 'JCP:' + jcpwanout + arrow + 'PE\n'
            print path       
if SRXFWRB:#working progress
    #CATESMTHOON0101UJDM01
    print('we have vSRX and FW and RB,-script not tested-,partial info printed:')
    if skipxml == False:
        rbxml()
        fwxml()
    #srxfile()
if CSRFWRB:#working progress
    #USTESOCHIIL0102UJDM01-csr-fw USTESGBROGA0108UJDM01-srx fw
    print('we have vCSR and FW and RB,-script not tested--, partial info printed:')
    if skipxml == False:
        rbxml()
        fwxml()
        
    #csrfile()

# this will check initial xml for FW and RB from thirdparty dir        
if XMLONLY:
    print('this will check xml for FW and RB :')
    jdmusername = raw_input('JDM username [root]: ') or 'root'
    jdmpassword = getpass.getpass('JDM password: ')
    
    virshlis = jdmcheck() 
    rbxml()
    fwxml()




