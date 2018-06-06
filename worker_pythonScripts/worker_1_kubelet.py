#!/usr/bin/python
import os, sys, pwd
import commands


check_2_1_1="2.1.1  - Ensure that the --allow-privileged argument is set to false"
check_2_1_2="2.1.2  - Ensure that the --anonymous-auth argument is set to false"
check_2_1_3="2.1.3  - Ensure that the --authorization-mode argument is not set to AlwaysAllow"
check_2_1_4="2.1.4  - Ensure that the --client-ca-file argument is set as appropriate"
check_2_1_5="2.1.5  - Ensure that the --read-only-port argument is set to 0"
check_2_1_6="2.1.6  - Ensure that the --streaming-connection-idle-timeout argument is not set to 0"
check_2_1_7="2.1.7  - Ensure that the --protect-kernel-defaults argument is set to true"
check_2_1_8="2.1.8  - Ensure that the --make-iptables-util-chains argument is set to true"
check_2_1_9="2.1.9  - Ensure that the --keep-terminated-pod-volumes argument is set to false"
check_2_1_10="2.1.10  - Ensure that the --hostname-override argument is not set"
check_2_1_11="2.1.11  - Ensure that the --event-qps argument is set to 0"
check_2_1_12="2.1.12  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"
check_2_1_13="2.1.13  - Ensure that the --cadvisor-port argument is set to 0"
check_2_1_14="2.1.14  - Ensure that the RotateKubeletClientCertificate argument is not set to false"
check_2_1_15="2.1.15  - Ensure that the RotateKubeletServerCertificate argument is set to true"


def compliance_status(flag, compliance_type):
    bldRED    = '\033[1;31m'
    bldGREEN  = '\033[1;32m'
    bldBLUE   = '\033[1;34m'
    bldYELLOW = '\033[1;33m'
    END    = '\033[0m'

    if flag.upper() == 'FAIL':
        print bldRED + '[FAIL] ' + END + compliance_type
    elif flag.upper() == 'PASS':
        print bldGREEN + '[PASS] ' + END + compliance_type
    elif flag.upper() == 'INFO':
        print bldBLUE + '[INFO] ' + END + compliance_type
    else:
        print bldYELLOW + '[WARN] ' + END + compliance_type
    return

def fileExists(filePath):
    return os.path.isfile(filePath)

def pathExists(path):
    return os.path.exists(path)

def mySearchReturn(mySearch):
    return commands.getoutput(mySearch)


def allow_privileged():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "allow-privileged"'
		searchReturn = mySearchReturn(textSearch)

		if('--allow-privileged=false' in searchReturn):
			if('--allow-privileged=true' not in searchReturn):
				compliance_status('PASS', check_2_1_1)
		else:
			compliance_status('FAIL', check_2_1_1)
	except:
		compliance_status('WARN', check_2_1_1)


def anonymous_auth():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "anonymous-auth"'
		searchReturn = mySearchReturn(textSearch)

		if('--anonymous-auth=false' in searchReturn):
			compliance_status('PASS', check_2_1_2)
		else:
			compliance_status('FAIL', check_2_1_2)
	except:
		compliance_status('WARN', check_2_1_2)


def authorization_mode():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "authorization-mode"'
		searchReturn = mySearchReturn(textSearch)

		if('--authorization-mode=' in searchReturn):
			searchReturn = searchReturn.replace('--authorization-mode=', '')
			ReturnList = searchReturn.split(',')
			for mode in ReturnList:
				if('AlwaysAllow' in mode):
					compliance_status('FAIL', check_2_1_3)
					return
					compliance_status('PASS', check_2_1_3)
		else:
			compliance_status('FAIL', check_2_1_3)
	except:
		compliance_status('WARN', check_2_1_3)


def client_ca_file():
    try:
        textSearch = 'ps -ef | grep kubelet | grep "client-ca-file"'
        searchReturn = mySearchReturn(textSearch)
       
        if('--client-ca-file=' in searchReturn):
            count = 1
            certAuthList = []
            ReturnList = searchReturn.split(' ')
           
            for item in ReturnList:
                if('--client-ca-file=' in item):
                    certAuthList.append('2.1.4  *   {'+ str(count)+'} ' + item.replace('--',''))
                    count = count + 1
                    certAuth = item.replace('--client-ca-file=','')
                    tempList = certAuthFile.split('\n')
                    certAuthFile = tempList[0]
                    
                    if(fileExists(certAuthFile)== False):
                        compliance_status('FAIL', check_2_1_4)
                        for auth in certAuthList:
                            compliance_status('INFO', auth)
                        return
                       
            compliance_status('PASS', check_2_1_4)
            for auth in certAuthList:
                compliance_status('INFO', auth)
        else:       
            compliance_status('FAIL', check_2_1_4)

    except:
        compliance_status('WARN', check_2_1_4)



def read_only_port():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "read-only-port"'
		searchReturn = mySearchReturn(textSearch)

		if('--read-only-port=0' in searchReturn):
			compliance_status('PASS', check_2_1_5)
		else:
			compliance_status('FAIL', check_2_1_5)

	except:
		compliance_status('WARN', check_2_1_5)


def streaming_idle_timeout():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "streaming-connection-idle-timeout"'
		searchReturn = mySearchReturn(textSearch)
		if('--streaming-connection-idle-timeout=0' in searchReturn):
			compliance_status('FAIL', check_2_1_6)
		else:
			compliance_status('PASS', check_2_1_6)

	except:
		compliance_status('WARN', check_2_1_5)


def protect_kernel_defaults():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "protect-kernel-defaults"'
		searchReturn = mySearchReturn(textSearch)
		if('--protect-kernel-defaults=true' in searchReturn):
			compliance_status('PASS', check_2_1_7)
		else:
			compliance_status('FAIL', check_2_1_7)

	except:
		compliance_status('WARN', check_2_1_7)


def make_iptables_util_chains():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "make-iptables-util-chains"'
		searchReturn = mySearchReturn(textSearch)
		if('--make-iptables-util-chains=true' in searchReturn):
			compliance_status('PASS', check_2_1_8)
		else:
			compliance_status('FAIL', check_2_1_8)
	except:
		compliance_status('WARN', check_2_1_8)


def terminated_pod_volumes():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "keep-terminated-pod-volumes"'
		searchReturn = mySearchReturn(textSearch)
		if('--keep-terminated-pod-volumes=false' in searchReturn):
			compliance_status('PASS', check_2_1_9)
		else:
			compliance_status('FAIL', check_2_1_9)
	except:
		compliance_status('WARN', check_2_1_9)


def hostname_override():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "hostname-override"'
		searchReturn = mySearchReturn(textSearch)
		if('--hostname-override' not in searchReturn):
			compliance_status('PASS', check_2_1_10)
		else:
			compliance_status('FAIL', check_2_1_10)
	except:
		compliance_status('WARN', check_2_1_10)


def event_qps():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "event-qps"'
		searchReturn = mySearchReturn(textSearch)
		if('--event-qps=0' in searchReturn):
			compliance_status('PASS', check_2_1_11)
		else:
			compliance_status('FAIL', check_2_1_11)
	except:
		compliance_status('WARN', check_2_1_11)


def privateKeyHelper(certFile):
    try:
        textSearch = 'ps -ef | grep kubelet | grep "tls-private-key-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--tls-private-key-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--tls-private-key-file=' in item):
                    tempFile = item.replace('--tls-private-key-file','')
                    tempFileList = tempFile.split('\n')
                    keyFile = tempFileList[0]

                    if(fileExists(privateKeyFile)):
                    	compliance_status('PASS', check_2_1_12)
                    	compliance_status('INFO', '  *    ' + certfile)
                    	compliance_status('INFO', '  *    ' + keyFile)
                    	return
                    else:
                        compliance_status('FAIL', check_2_1_12)

        compliance_status('FAIL', check_2_1_12)
    except:
        compliance_status('WARN', check_2_1_12)


def tls_cert_and_privateKey_file():
    try:
        textSearch = 'ps -ef | grep kubelet | grep "tls-cert-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--tls-cert-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--tls-cert-file=' in item):
                    tempFile = item.replace('--tls-cert-file=','')
                    tempFileList = tempFile.split('\n')
                    certFile = tempFileList[0]

                    if(fileExists(certFile)):
                    	privateKeyHelper(certFile)
                    	return
                    else:
                        compliance_status('FAIL', check_2_1_12)

        else:
        	compliance_status('FAIL', check_2_1_12)
    except:
        compliance_status('WARN', check_2_1_4)


def cadvisor_port():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "cadvisor-port"'
		searchReturn = mySearchReturn(textSearch)
		if('--cadvisor-port=0' in searchReturn):
			compliance_status('PASS', check_2_1_13)
		else:
			compliance_status('FAIL', check_2_1_13)
	except:
		compliance_status('WARN', check_2_1_13)



def rotateKubeletClientCertificate():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "RotateKubeletClientCertificate"'
		searchReturn = mySearchReturn(textSearch)
		if('RotateKubeletClientCertificate=false' not in searchReturn):
			compliance_status('PASS', check_2_1_14)
		else:
			compliance_status('FAIL', check_2_1_14)
	except:
		compliance_status('WARN', check_2_1_14)


def rotateKubeletServerCertificate():
	try:
		textSearch = 'ps -ef | grep kubelet | grep "RotateKubeletServerCertificate"'
		searchReturn = mySearchReturn(textSearch)
		if('RotateKubeletServerCertificate=true' in searchReturn):
			compliance_status('PASS', check_2_1_15)
		else:
			compliance_status('FAIL', check_2_1_15)
	except:
		compliance_status('WARN', check_2_1_15)


def main():
	compliance_status('INFO', '2 - Worker_Node CIS_Benchmark compliance')
	compliance_status('INFO', '2.1 - Checking Kubelet')
	compliance_status('INFO', 'LEVEL 1')

	allow_privileged(), anonymous_auth(), authorization_mode()
	client_ca_file(), read_only_port(), streaming_idle_timeout()
	protect_kernel_defaults(), make_iptables_util_chains()
	terminated_pod_volumes(), hostname_override()
	event_qps(), tls_cert_and_privateKey_file(), cadvisor_port()
	rotateKubeletClientCertificate(), rotateKubeletServerCertificate()

main()