#!/usr/bin/python
import os, sys, pwd
import commands

check_3_1_1="3.1.1 	Ensure that the --anonymous-auth argument is set to false"
check_3_1_2="3.1.2 	Ensure that the --basic-auth-file argument is not set"
check_3_1_3="3.1.3 	Ensure that the --insecure-allow-any-token argument is not set"
check_3_1_4="3.1.4 	Ensure that the --insecure-bind-address argument is not set"
check_3_1_5="3.1.5 	Ensure that the --insecure-port argument is set to 0"
check_3_1_6="3.1.6 	Ensure that the --secure-port argument is not set to 0"
check_3_1_7="3.1.7 	Ensure that the --profiling argument is set to false"
check_3_1_8="3.1.8 	Ensure that the admission control policy is not set to AlwaysAdmit"
check_3_1_9="3.1.9 	Ensure that the admission control policy is set to NamespaceLifecycle"
check_3_1_10="3.1.10 	Ensure that the --audit-log-path argument is set as appropriate"
check_3_1_11="3.1.11 	Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
check_3_1_12="3.1.12 	Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
check_3_1_13="3.1.13 	Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
check_3_1_14="3.1.14 	Ensure that the --authorization-mode argument is not set to AlwaysAllow"
check_3_1_15="3.1.15 	Ensure that the --token-auth-file parameter is not set"
check_3_1_16="3.1.16 	Ensure that the --service-account-lookup argument is set to true"
check_3_1_17="3.1.17 	Ensure that the --service-account-key-file argument is set as appropriate"
check_3_1_18="3.1.18 	Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"
check_3_1_19="3.1.19 	Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"


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

def anonymous_auth():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "anonymous-auth"'
		searchReturn = mySearchReturn(textSearch)

		if('--anonymous-auth=false' in searchReturn):
			if('--anonymous-auth=true' not in searchReturn):
				compliance_status('PASS', check_3_1_1)
			else:
				compliance_status('FAIL', check_3_1_1)
		else:
			compliance_status('FAIL', check_3_1_1)
	except:
		compliance_status('WARN', check_3_1_1)


def basic_auth_file():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "basic-auth-file"'
		searchReturn = mySearchReturn(textSearch)

		if('--basic-auth-file=' not in searchReturn):
			compliance_status('PASS', check_3_1_2)
		else:
			compliance_status('FAIL', check_3_1_2)
	except:
		compliance_status('WARN', check_3_1_2)



def insecure_allow_any_token():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "insecure-allow-any-token"'
		searchReturn = mySearchReturn(textSearch)

		if('--insecure-allow-any-token=' not in searchReturn):
			compliance_status('PASS', check_3_1_3)
		else:
			compliance_status('FAIL', check_3_1_3)
	except:
		compliance_status('WARN', check_3_1_3)


def insecure_bind_address():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "insecure-bind-address"'
		searchReturn = mySearchReturn(textSearch)

		bind_1 = '--insecure-bind-address='
		bind_2 = '--insecure-bind-address=127.0.0.1'

		if((bind_1 not in searchReturn) or (bind_2 in searchReturn)):
			compliance_status('PASS', check_3_1_4)
		else:
			compliance_status('FAIL', check_3_1_4)
	except:
		compliance_status('WARN', check_3_1_4)


def insecure_port():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "insecure-port"'
		searchReturn = mySearchReturn(textSearch)

		if('--insecure-port=0' in searchReturn):
			compliance_status('PASS', check_3_1_5)
		else:
			compliance_status('FAIL', check_3_1_5)
	except:
		compliance_status('WARN', check_3_1_5)


def secure_port():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "secure-port"'
		searchReturn = mySearchReturn(textSearch)

		if('--secure-port=0' not in searchReturn):
			compliance_status('PASS', check_3_1_6)
		else:
			compliance_status('FAIL', check_3_1_6)
	except:
		compliance_status('WARN', check_3_1_6)


def profiling():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "profiling"'
		searchReturn = mySearchReturn(textSearch)

		if('--profiling=false' in searchReturn):
			if('--profiling=true' not in searchReturn):
				compliance_status('PASS', check_3_1_7)
			else:
				compliance_status('FAIL', check_3_1_7)
		else:
			compliance_status('FAIL', check_3_1_7)
	except:
		compliance_status('WARN', check_3_1_7)


def admin_ctrl_always_admit():
    try:
        searchCommand = 'ps -ef | grep federation-apiserver | grep "admission-control"'
        searchReturn = mySearchReturn(searchCommand)

        if('--admission-control=' in searchReturn):
        	if('AlwaysAdmit' in searchReturn):
        		compliance_status('FAIL', check_3_1_8)
        	else:
        		compliance_status('PASS', check_3_1_8)
        else:
        	compliance_status('FAIL', check_3_1_8)
    except:
        compliance_status('WARN', check_3_1_8)


def admin_ctrl_namespace():
    try:
        searchCommand = 'ps -ef | grep federation-apiserver | grep "admission-control"'
        searchReturn = mySearchReturn(searchCommand)

        if('--admission-control=' in searchReturn):
        	if('NamespaceLifecycle' in searchReturn):
        		compliance_status('PASS', check_3_1_9)
        	else:
        		compliance_status('FAIL', check_3_1_9)
        else:
        	compliance_status('FAIL', check_3_1_9)
    except:
        compliance_status('WARN', check_3_1_9)


def audit_log_path():
    try:
        textSearch = 'ps -ef | grep federation-apiserver | grep "audit-log-path"'
        searchReturn = mySearchReturn(textSearch)
       
        if('--audit-log-path=' in searchReturn):
            ReturnList = searchReturn.split(' ')       
            for item in ReturnList:
                if('--audit-log-path=' in item):
                    lofFile = item.replace('--audit-log-path=','')
                    logFileClean = logFile.split('\n')
                    fileName = logFileClean[0]
                    
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_3_1_10)
                        return
                    else:
                    	compliance_status('FAIL', check_3_1_10)
                    	compliance_status('INFO', '  *   "'+fileName+ '" was not found')
                    	return

        else:
        	compliance_status('FAIL', check_3_1_10)
    except:
      compliance_status('INFO', check_3_1_10)


def audit_log_maxage():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "audit-log-maxage"'
		searchReturn = mySearchReturn(textSearch)


		if('--audit-log-maxage=' in searchReturn):
			compliance_status('PASS', check_3_1_11)
		else:
			compliance_status('FAIL', check_3_1_11)
	except:
		compliance_status('WARN', check_3_1_11)


def audit_log_maxbackup():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "audit-log-maxbackup"'
		searchReturn = mySearchReturn(textSearch)

		if('--audit-log-maxbackup=' in searchReturn):
			compliance_status('PASS', check_3_1_12)
		else:
			compliance_status('FAIL', check_3_1_12)
	except:
		compliance_status('WARN', check_3_1_12)


def audit_log_maxsize():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "audit-log-maxsize"'
		searchReturn = mySearchReturn(textSearch)

		if('--audit-log-maxsize=' in searchReturn):
			compliance_status('PASS', check_3_1_13)
		else:
			compliance_status('FAIL', check_3_1_13)
	except:
		compliance_status('WARN', check_3_1_13)


def authorization_mode():
    try:
        searchCommand = 'ps -ef | grep federation-apiserver | grep "authorization-mode"'
        searchReturn = mySearchReturn(searchCommand)

        if('--authorization-mode=' not in searchReturn):
        	compliance_status('FAIL', check_3_1_14)
        	return

        if('AlwaysAllow' in searchReturn):
        	compliance_status('FAIL', check_3_1_14)
        	return
        
        compliance_status('PASS', check_3_1_14)
    except:
        compliance_status('WARN', check_3_1_14)



def token_auth_file():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "token-auth-file"'
		searchReturn = mySearchReturn(textSearch)

		if('--token-auth-file=' not in searchReturn):
			compliance_status('PASS', check_3_1_15)
		else:
			compliance_status('FAIL', check_3_1_15)
	except:
		compliance_status('WARN', check_3_1_15)


def service_account_lookup():
	try:
		textSearch = 'ps -ef | grep federation-apiserver | grep "service-account-lookup"'
		searchReturn = mySearchReturn(textSearch)

		if('--service-account-lookup=true' in searchReturn):
			compliance_status('PASS', check_3_1_16)
		else:
			compliance_status('FAIL', check_3_1_16)
	except:
		compliance_status('WARN', check_3_1_16)



def service_account_key_file():
    try:
        textSearch = 'ps -ef | grep federation-apiserver | grep "service-account-key-file"'
        searchReturn = mySearchReturn(textSearch)
       
        if('--service-account-key-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')       
            for item in ReturnList:
                if('--service-account-key-file=' in item):
                    keyFile = item.replace('--service-account-key-file=','')
                    keyFileClean = keyFile.split('\n')
                    fileName = keyFileClean[0]
                    
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_3_1_17)
                        return
                    else:
                    	compliance_status('FAIL', check_3_1_17)
                    	compliance_status('INFO', '  *   "'+fileName+ '" was not found')
                    	return

        else:
        	compliance_status('FAIL', check_3_1_17)
    except:
      compliance_status('INFO', check_3_1_17)



def keyFileHelper(certFile):
    try:
        textSearch = 'ps -ef | grep federation-apiserver | grep "etcd-keyfile"'
        searchReturn = mySearchReturn(textSearch)

        if('--etcd-keyfile=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--etcd-keyfile=' in item):
                    tempFile = item.replace('--etcd-keyfile=','')
                    tempFileList = tempFile.split('\n')
                    keyFile = tempFileList[0]

                    if(fileExists(keyFile)):
                    	compliance_status('PASS', check_3_1_18)
                    	compliance_status('INFO', '  *    ' + certFile)
                    	compliance_status('INFO', '  *    ' + keyFile)
                    	return
                    else:
                        compliance_status('FAIL', check_3_1_18)
                        compliance_status('INFO', '  *   "'+keyFile+ '" was not found')
                        return

        compliance_status('FAIL', check_3_1_18)
    except:
        compliance_status('WARN', check_3_1_18)



def etcd_cert_and_Key_file():
    try:
        textSearch = 'ps -ef | grep federation-apiserver | grep "etcd-certfile"'
        searchReturn = mySearchReturn(textSearch)

        if('--etcd-certfile=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--etcd-certfile=' in item):
                    tempFile = item.replace('--etcd-certfile=','')
                    tempFileList = tempFile.split('\n')
                    certFile = tempFileList[0]

                    if(fileExists(certFile)):
                    	keyFileHelper(certFile)
                    	return
                    else:
                        compliance_status('FAIL', check_3_1_18)
                        compliance_status('INFO', '  *   "'+certFile+ '" was not found')
                        return

        else:
        	compliance_status('FAIL', check_3_1_18)
    except:
        compliance_status('WARN', check_3_1_18)



def privateKeyHelper(certFile):
    try:
        textSearch = 'ps -ef | grep kubelet | grep "tls-private-key-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--tls-private-key-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--tls-private-key-file=' in item):
                    tempFile = item.replace('--tls-private-key-file=','')
                    tempFileList = tempFile.split('\n')
                    keyFile = tempFileList[0]

                    if(fileExists(privateKeyFile)):
                    	compliance_status('PASS', check_2_1_12)
                    	compliance_status('INFO', '  *    ' + certfile)
                    	compliance_status('INFO', '  *    ' + keyFile)
                    	return
                    else:
                        compliance_status('FAIL', check_3_1_19)
                        compliance_status('INFO', '  *   "'+privateKeyFile+ '" was not found')
                        return

        compliance_status('FAIL', check_3_1_19)
    except:
        compliance_status('WARN', check_3_1_19)


def tls_cert_and_privateKey_file():
    try:
        textSearch = 'ps -ef | grep federation-apiserver | grep "tls-cert-file"'
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
                        compliance_status('FAIL', check_3_1_19)
                        compliance_status('INFO', '  *   "'+certFile+ '" was not found')
                        return

        else:
        	compliance_status('FAIL', check_3_1_19)
    except:
        compliance_status('WARN', check_3_1_19)


def main():
    compliance_status('INFO', '3 - Federation CIS_Benchmark compliance')
    compliance_status('INFO', '3.1 - Checking Federation API Server')
    compliance_status('INFO', 'LEVEL 1')
    anonymous_auth(), basic_auth_file(), insecure_allow_any_token()
    insecure_bind_address(), insecure_port(), secure_port()
    profiling(), admin_ctrl_always_admit(), admin_ctrl_namespace()
    audit_log_path(), audit_log_maxage(), audit_log_maxbackup()
    audit_log_maxsize(), authorization_mode(), token_auth_file()
    service_account_lookup(), service_account_key_file()
    etcd_cert_and_Key_file(), tls_cert_and_privateKey_file()

main()
