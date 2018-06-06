#!/usr/bin/python
import os, sys
import commands

AUDIT_LOG_EXIST = False
REQUEST_TIMEOUT = 60

check_1_1_1="1.1.1  - Ensure that the --anonymous-auth argument is set to false"
check_1_1_2="1.1.2  - Ensure that the --basic-auth-file argument is not set"
check_1_1_3="1.1.3  - Ensure that the --insecure-allow-any-token argument is not set"
check_1_1_4="1.1.4  - Ensure that the --kubelet-https argument is set to true"
check_1_1_5="1.1.5  - Ensure that the --insecure-bind-address argument is not set"
check_1_1_6="1.1.6  - Ensure that the --insecure-port argument is set to 0"
check_1_1_7="1.1.7  - Ensure that the --secure-port argument is not set to 0"
check_1_1_8="1.1.8  - Ensure that the --profiling argument is set to false"
check_1_1_9="1.1.9  - Ensure that the --repair-malformed-updates argument is set to false"
check_1_1_10="1.1.10  - Ensure that the admission control policy is not set to AlwaysAdmit"
check_1_1_11="1.1.11  - Ensure that the admission control policy is set to AlwaysPullImages"
check_1_1_12="1.1.12  - Ensure that the admission control policy is set to DenyEscalatingExec"
check_1_1_13="1.1.13  - Ensure that the admission control policy is set to SecurityContextDeny"
check_1_1_14="1.1.14  - Ensure that the admission control policy is set to NamespaceLifecycle"
check_1_1_15="1.1.15  - Ensure that the --audit-log-path argument is set as appropriate"
check_1_1_16="1.1.16  - Ensure that the --audit-log-maxage argument is set to 30 or as appropriate"
check_1_1_17="1.1.17  - Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate"
check_1_1_18="1.1.18  - Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate"
check_1_1_19="1.1.19  - Ensure that the --authorization-mode argument is not set to AlwaysAllow"
check_1_1_20="1.1.20  - Ensure that the --token-auth-file parameter is not set"
check_1_1_21="1.1.21  - Ensure that the --kubelet-certificate-authority argument is set as appropriate"
check_1_1_22="1.1.22  - Ensure that the --kubelet-client-certificate and --kubelet-client-key arguments are set as appropriate"
check_1_1_23="1.1.23  - Ensure that the --service-account-lookup argument is set to true"
check_1_1_24="1.1.24  - Ensure that the admission control policy is set to PodSecurityPolicy"
check_1_1_25="1.1.25  - Ensure that the --service-account-key-file argument is set as appropriate"
check_1_1_26="1.1.26  - Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate"
check_1_1_27="1.1.27  - Ensure that the admission control policy is set to ServiceAccount"
check_1_1_28="1.1.28  - Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate"
check_1_1_29="1.1.29  - Ensure that the --client-ca-file argument is set as appropriate"
check_1_1_30="1.1.30  - Ensure that the --etcd-cafile argument is set as appropriate"
check_1_1_31="1.1.31  - Ensure that the --authorization-mode argument is set to Node"
check_1_1_32="1.1.32  - Ensure that the admission control policy is set to NodeRestriction"
check_1_1_33="1.1.33  - Ensure that the --experimental-encryption-provider-config argument is set as appropriate"
check_1_1_34="1.1.34  - Ensure that the encryption provider is set to aescbc"
check_1_1_35="1.1.35  - Ensure that the admission control policy is set to EventRateLimit"
check_1_1_36="1.1.36  - Ensure that the AdvancedAuditing argument is not set to false"
check_1_1_37="1.1.37  - Ensure that the --request-timeout argument is set as appropriate"



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


def api_serverCheck():
    try:
        apiserver ='ps -ef | grep kube-apiserver'
        textReturn = commands.getoutput(apiserver)
        textReturn = textReturn.replace(apiserver,'')
        myText = textReturn.replace('--color=auto','').translate(None,"{}<>&;")

        textArray = myText.split(" ")
        largestIndex = len(textArray)-1

        if((textArray.index('kube-apiserver') < largestIndex) and (len(textArray) >= 20)):
            compliance_status('INFO', '1.1  -  Checking API Server')
            return
        else:
            compliance_status('INFO', '1.1  -  Checking API Server')
            compliance_status('WARN', '  *     CIS_Benchmark compliance script for apiserver will abort')
            exit()
    except:
        info = "  *     kube-apiserver is not responding. Check logs or perform 'ps -ef | grep kube-apiserver'"
        compliance_status('WARN', info)
        compliance_status('WARN', '  *     CIS_Benchmark compliance script for apiserver has aborted')
        exit()    


def mySearchReturn(mySearch):
    return commands.getoutput(mySearch)

def fileExists(filePath):
    return os.path.isfile(filePath)

def pathExists(path):
    return os.path.exists(path)

def checkFilesKeys(retList, cis_param, checkNum):
    try: 
        for item in retList:
            if(cis_param in item):
                fileName = item.replace(cis_param,'')
                if(fileExists(fileName)):
                    return 'FOUND_FILE'
                else:
                    compliance_status('FAIL', checkNum)
                    compliance_status('INFO', '  *     Compliance failed because {'+fileName+'} was not found')
                    return 'ERROR'

        compliance_status('FAIL', checkNum)
        return 'ERROR'
    except:
        compliance_status('WARN', checkNum)
        return 'ERROR'


def anonymous_auth():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "anonymous-auth"'
        searchReturn = mySearchReturn(searchCommand)

        if ("--anonymous-auth=false" in searchReturn):
            compliance_status('PASS', check_1_1_1)
        else:
            compliance_status('FAIL', check_1_1_1)
    except:
        compliance_status('WARN', check_1_1_1)


def basic_auth_file():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "basic-auth-file"'
        searchReturn = mySearchReturn(searchCommand)

        if ('--basic-auth-file' in searchReturn):
            searchReturn = searchReturn.replace('\n', ' ')
            ReturnList = searchReturn.split(' ')  

            for item in ReturnList:
                if('--basic-auth-file=' in item):
                    fileName = item.replace('--basic-auth-file=','')
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_1_1_2)
                        return
                    else:
                        compliance_status('FAIL', check_1_1_2)
                        compliance_status('INFO', '  *   "'+fileName+ '" was not found')
                        return

            compliance_status('PASS', check_1_1_2)
        else:
            compliance_status('FAIL', check_1_1_2)
    except:
        compliance_status('WARN', check_1_1_2)



def insecure_allow_token():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "insecure-allow-any-token"'
        searchReturn = mySearchReturn(searchCommand)

        if ("--insecure-allow-any-token" not in searchReturn):
            compliance_status('PASS', check_1_1_3)
        else:
            compliance_status('FAIL', check_1_1_3)
    except:
        compliance_status('WARN', check_1_1_3)



def kubelet_https():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "kubelet-https"'
        searchReturn = mySearchReturn(searchCommand)

        if ("--kubelet-https=" not in searchReturn):
            compliance_status('PASS', check_1_1_4)
        elif ("--kubelet-https=true" in searchReturn):
            compliance_status('PASS', check_1_1_4)
        else:
            compliance_status('FAIL', check_1_1_4)
    except:
        compliance_status('WARN', check_1_1_4)



def insecure_bind_address():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "insecure-bind-address"'
        searchReturn = mySearchReturn(searchCommand)

        if ("--insecure-bind-address" not in searchReturn):
            compliance_status('PASS', check_1_1_5)
        elif ("--insecure-bind-address=127.0.0.1" in searchReturn):
            compliance_status('PASS', check_1_1_5)
        else:
            compliance_status('FAIL', check_1_1_5)
    except:
        compliance_status('WARN', check_1_1_5)


def insecure_port():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "insecure-port"'
        searchReturn = mySearchReturn(searchCommand)

        if ("--insecure-port=0" in searchReturn):
            compliance_status('PASS', check_1_1_6)
        else:
            compliance_status('FAIL', check_1_1_6)
    except:
        compliance_status('WARN', check_1_1_6)


def secure_port():
    try:
        searchCommand = 'ps -ef | grep kube-apiserver | grep "secure-port"'
        searchReturn = mySearchReturn(searchCommand)

        if('--secure-port' not in searchReturn):
            compliance_status('PASS', check_1_1_7)
            return

        if('--secure-port=0' in searchReturn):
            compliance_status('FAIL', check_1_1_7)
        else:
            compliance_status('PASS', check_1_1_7)
    except:
        compliance_status('WARN', check_1_1_7)



def profiling():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "profiling"'
        searchReturn = mySearchReturn(textSearch)

        if('--profiling=false' in searchReturn):
            compliance_status('PASS', check_1_1_8)
        else:
            compliance_status('FAIL', check_1_1_8)
    except:
        compliance_status('WARN', check_1_1_8)



def repair_malformed_updates():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "repair-malformed-updates"'
        searchReturn = mySearchReturn(textSearch)

        if('--prepair-malformed-updates=false' in searchReturn):
            compliance_status('PASS', check_1_1_9)
        else:
            compliance_status('FAIL', check_1_1_9)
    except:
        compliance_status('WARN', check_1_1_9)


def admission_control():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "admission-controls"'
        searchReturn = mySearchReturn(textSearch)
        
        if('AlwaysAdmit' in searchReturn):
            compliance_status('FAIL', check_1_1_10)
        else:
            compliance_status('PASS', check_1_1_10)
        if('AlwaysPullImages' in searchReturn):
            compliance_status('PASS', check_1_1_11)
        else:
            compliance_status('FAIL', check_1_1_11)
        if('DenyEscalatingExec' in searchReturn):
            compliance_status('PASS', check_1_1_12)
        else:
            compliance_status('FAIL', check_1_1_12)
        if('SecurityContextDeny' in searchReturn):
            compliance_status('PASS', check_1_1_13)
        else:
            compliance_status('FAIL', check_1_1_13)
        if('NamespaceLifecycle' in searchReturn):
            compliance_status('PASS', check_1_1_14)
        else:
            compliance_status('FAIL', check_1_1_14)      
    except:
        compliance_status('WARN', '1.1.10 - 1.1.14: Check admission control settings in kube-apiserver.yaml')


def audit_log_path():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "audit-log-path"'
        searchReturn = mySearchReturn(textSearch)

        if ('--audit-log-path=' in searchReturn):
            searchReturn = searchReturn.replace('\n', ' ')
            ReturnList = searchReturn.split(' ')  

            for item in ReturnList:
                if('--audit-log-path=' in item):
                    fileName = item.replace('--audit-log-path=','')
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_1_1_15)
                        AUDIT_LOG_EXIST = True
                        return
                    else:
                        compliance_status('FAIL', check_1_1_15)
                        compliance_status('INFO', '  *     NOTE: 1.1.15 failed because audit log file {'+fileName+'} was not found')
                        return
            compliance_status('FAIL', check_1_1_15)
        else:
            compliance_status('FAIL', check_1_1_15)
    except:
        compliance_status('WARN', check_1_1_15)



def audit_log_maxage():
    try:
        if(AUDIT_LOG_EXIST == False):
            compliance_status('WARN', check_1_1_16)
            info2 = '--audit-log-maxage compliance was not checked because 1.1.15 (--audit-log-path) failed'
            compliance_status('INFO', '  *       '+info2)
            return

        textSearch = 'ps -ef | grep grep kube-apiserver | grep "audit-log-maxage"'
        searchReturn = mySearchReturn(textSearch)

        if ('--audit-log-maxage=30' in searchReturn):
            compliance_status('PASS', check_1_1_16)
        else:
            compliance_status('FAIL', check_1_1_16)
    except:
        compliance_status('WARN', check_1_1_16)


def audit_log_maxbackup():
    try:
        if(AUDIT_LOG_EXIST == False):
            compliance_status('WARN', check_1_1_17)
            info2 = '--audit-log-maxbackup compliance was not checked because 1.1.15 (--audit-log-path) failed'
            compliance_status('INFO', '  *       '+info2)
            return

        textSearch = 'ps -ef | grep grep kube-apiserver | grep "audit-log-maxbackup"'
        searchReturn = mySearchReturn(textSearch)

        if ('--aaudit-log-maxbackup=10' in searchReturn):
            compliance_status('PASS', check_1_1_17)
        else:
            compliance_status('FAIL', check_1_1_17)
    except:
        compliance_status('WARN', check_1_1_17)


def audit_log_maxsize():
    try:
        if(AUDIT_LOG_EXIST == False):
            compliance_status('WARN', check_1_1_18)
            info2 = '--audit-log-maxsize compliance was not checked because 1.1.15 (--audit-log-path) failed'
            compliance_status('INFO', '  *       '+info2)
            return

        textSearch = 'ps -ef | grep grep kube-apiserver | grep "audit-log-maxsize"'
        searchReturn = mySearchReturn(textSearch)

        if ('--audit-log-maxsize=100' in searchReturn):
            compliance_status('PASS', check_1_1_18)
        else:
            compliance_status('FAIL', check_1_1_18)
    except:
        compliance_status('WARN', check_1_1_18)


def authorization1():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "authorization-mode"'
        searchReturn = mySearchReturn(textSearch)

        if ('--authorization-mode=' in searchReturn):
            if('AlwaysAllow' in searchReturn):
                compliance_status('FAIL', check_1_1_19)
            else:
                compliance_status('PASS', check_1_1_19)
        else:
            compliance_status('FAIL', check_1_1_19)
    except:
        compliance_status('WARN', check_1_1_19)


def token_auth_file():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "token-auth-file"'
        searchReturn = mySearchReturn(textSearch)

        if ('--token-auth-file' in searchReturn):
            compliance_status('FAIL', check_1_1_20)
        else:
            compliance_status('PASS', check_1_1_20)
    except:
        compliance_status('WARN', check_1_1_20)


def kubelet_certificate_authority():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "kubelet-certificate-authority"'
        searchReturn = mySearchReturn(textSearch)

        if ('--kubelet-certificate-authority=' in searchReturn):
            searchReturn = searchReturn.replace('\n', ' ')
            ReturnList = searchReturn.split(' ')  

            for item in ReturnList:
                if('--kubelet-certificate-authority=' in item):
                    fileName = item.replace('--kubelet-certificate-authority=','')
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_1_1_21)
                        return
                    else:
                        compliance_status('FAIL', check_1_1_21)
                        info2 = '  *     NOTE: 1.1.21 failed because {'+fileName+'} was not found'
                        compliance_status('INFO', info2)
                        return
            compliance_status('FAIL', check_1_1_21)
        else:
            compliance_status('FAIL', check_1_1_21)
    except:
        compliance_status('WARN', check_1_1_21)


def kubelet_client_cert_and_key():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver'
        searchReturn = mySearchReturn(searchCommand)

        if('--kubelet-client-key=' not in searchReturn):
            compliance_status('FAIL',check_1_1_22)
            return
        if('--kubelet-client-certificate=' not in searchReturn):
            compliance_status('FAIL',check_1_1_22)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')

        ret1 = checkFilesKeys(ReturnList, '--kubelet-client-certificate=', check_1_1_22)
        ret2 = checkFilesKeys(ReturnList, '--kubelet-client-key=', check_1_1_22)

        if(ret1 == 'ERROR' or ret2 == 'ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_22)
    except:
        compliance_status('WARN', check_1_1_22)


def service_account_lookup():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "service-account-lookup"'
        searchReturn = mySearchReturn(textSearch)

        if ('--service-account-lookup=true' in searchReturn):
            compliance_status('PASS', check_1_1_23)
        else:
            compliance_status('FAIL', check_1_1_23)
    except:
        compliance_status('WARN', check_1_1_23)



def admin_ctrl_PodSec():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "admission-controls"'
        searchReturn = mySearchReturn(textSearch)
        
        if('PodSecurityPolicy' in searchReturn):
            compliance_status('PASS', check_1_1_24)
        else:
            compliance_status('FAIL', check_1_1_24)
    except:
        compliance_status('WARN', check_1_1_24)


def service_account_key_file():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver | grep "service-account-key-file"'
        searchReturn = mySearchReturn(searchCommand)

        if('--kubelet-client-key=' not in searchReturn):
            compliance_status('FAIL',check_1_1_25)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')

        ret = checkFilesKeys(ReturnList, '--service-account-key-file=', check_1_1_25)
        if(ret == 'ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_25)
    except:
        compliance_status('WARN', check_1_1_25)


def etcd_certfile_and_keyfile():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver'
        searchReturn = mySearchReturn(searchCommand)

        if('--etcd-certfile=' not in searchReturn):
            compliance_status('FAIL',check_1_1_26)
            return
        if('--etcd-keyfile=' not in searchReturn):
            compliance_status('FAIL',check_1_1_26)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')

        ret1 = checkFilesKeys(ReturnList, '--etcd-certfile=', check_1_1_26)
        ret2 = checkFilesKeys(ReturnList, '--etcd-keyfile=', check_1_1_26)

        if(ret1 == 'ERROR' or ret2 == 'ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_26)
    except:
        compliance_status('WARN', check_1_1_26)



def admin_ctrl_ServAcc():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "admission-controls"'
        searchReturn = mySearchReturn(textSearch)
        
        if('ServiceAccount' in searchReturn):
            compliance_status('PASS', check_1_1_27)
        else:
            compliance_status('FAIL', check_1_1_27)
    except:
        compliance_status('WARN', check_1_1_27)


def tls_cert_and_private_key_file():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver'
        searchReturn = mySearchReturn(searchCommand)

        if('--tls-cert-file=' not in searchReturn):
            compliance_status('FAIL',check_1_1_28)
            return
        if('--tls-private-key-file=' not in searchReturn):
            compliance_status('FAIL',check_1_1_28)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')

        ret1 = checkFilesKeys(ReturnList, '--tls-cert-file=', check_1_1_28)
        ret2 = checkFilesKeys(ReturnList, '--tls-private-key-file=', check_1_1_28)

        if(ret1 == 'ERROR' or ret2 == 'ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_28)
    except:
        compliance_status('WARN', check_1_1_28)


def client_ca_file():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver | grep "client-ca-file"'
        searchReturn = mySearchReturn(searchCommand)

        if('--client-ca-file=' not in searchReturn):
            compliance_status('FAIL',check_1_1_29)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')
        ret = checkFilesKeys(ReturnList, '--client-ca-file=', check_1_1_29)

        if(ret =='ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_29)
    except:
        compliance_status('WARN', check_1_1_29)


def etcd_cafile():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver | grep "etcd-cafile"'
        searchReturn = mySearchReturn(searchCommand)

        if('--etcd-cafile=' not in searchReturn):
            compliance_status('FAIL',check_1_1_30)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')
        ret = checkFilesKeys(ReturnList, '--etcd-cafile=', check_1_1_30)

        if(ret =='ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_30)
    except:
        compliance_status('WARN', check_1_1_30)  


def authorization2():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "authorization-mode"'
        searchReturn = mySearchReturn(textSearch)

        if ('--authorization-mode=' in searchReturn):
            if('Node' in searchReturn):
                compliance_status('PASS', check_1_1_31)
            else:
                compliance_status('FAIL', check_1_1_31)
        else:
            compliance_status('FAIL', check_1_1_31)
    except:
        compliance_status('WARN', check_1_1_31)


def admin_ctrl_NodeRstrict():
    try:
        textSearch = 'ps -ef | grep grep kube-apiserver | grep "admission-controls"'
        searchReturn = mySearchReturn(textSearch)
        
        if('NodeRestriction' in searchReturn):
            compliance_status('PASS', check_1_1_32)
        else:
            compliance_status('FAIL', check_1_1_32)
    except:
        compliance_status('WARN', check_1_1_32)


def exp_encrypt_prvd_config():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver'
        searchReturn = mySearchReturn(searchCommand)
        cis_param = '--experimental-encryption-provider-config='

        if(cis_param not in searchReturn):
            compliance_status('FAIL',check_1_1_33)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')
        ret = checkFilesKeys(ReturnList, cis_param, check_1_1_33)

        if(ret =='ERROR'):
            return
        else:
            compliance_status('PASS', check_1_1_33)
    except:
        compliance_status('WARN', check_1_1_33)



def encryption_provider():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver'
        searchReturn = mySearchReturn(searchCommand)
        cis_param = '--experimental-encryption-provider-config='

        if (cis_param not in searchReturn):
            compliance_status('FAIL', check_1_1_34)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ') 

        encryptConfigFile =''
        for item in ReturnList:
            if(cis_param in item):
                encryptConfigFile = item.replace(cis_param,'')
                break

        if fileExists(encryptConfigFile):
            searchWord = "'\- aescbc:'"
            grepCommand = "grep" + " " + searchWord + " "+ encryptConfigFile
            grepReturn = mySearchReturn(grepCommand)
            if('aescbc:' in grepReturn):
                compliance_status('PASS', check_1_1_34)
            else:
                compliance_status('FAIL', check_1_1_34)
        else:
            compliance_status('FAIL', check_1_1_34)
    except:
        compliance_status('WARN', check_1_1_34)


def admin_Ctrl_Event():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver | grep "admission-control="'
        searchReturn = mySearchReturn(searchCommand)

        if('EventRateLimit' in searchReturn):
            compliance_status('PASS', check_1_1_35)
        else:
            compliance_status('FAIL', check_1_1_35)         
    except:
        compliance_status('WARN', check_1_1_35)


def advancedAuditing():
    try:
        searchCmd = 'ps -ef | grep grep kube-apiserver | grep "feature-gates"'
        searchRet = mySearchReturn(searchCmd)

        if('AdvancedAuditing=false' in searchRet):
            compliance_status('FAIL', check_1_1_36)
            return

        searchCommand = 'ps -ef | grep grep kube-apiserver | grep "audit-policy-file="'
        searchReturn = mySearchReturn(searchCommand)

        if('--audit-policy-file=' not in searchReturn):
            compliance_status('FAIL', check_1_1_36)
            compliance_status('INFO', '  *       NOTE: 1.1.36 failed because --audit-policy-file argument was not set')
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')
       
        for item in ReturnList:
            if('--audit-policy-file=' in item):
                policyFile = item.replace('--audit-policy-file=','')
                if(fileExists(policyFile)):
                    policyRet = mySearchReturn('grep level: '+policyFile)
                    if('- level:' not in policyRet):
                        compliance_status('WARN', check_1_1_36)
                        info2 ='The minimum policy "rules: -level: Metadata" required to pass was not found in {'+policyFile+'}'
                        compliance_status('INFO', '  *       '+info2)
                        return
                    else:
                        compliance_status('PASS', check_1_1_36)
                        return
                else:
                    compliance_status('FAIL', check_1_1_36)
                    compliance_status('INFO', '  *       NOTE: 1.1.36 failed because audit-policy-file {'+policyFile+'} was not found')
                    return
  
        compliance_status('FAIL', check_1_1_36)
        compliance_status('INFO', '  *       NOTE: check --audit-policy-file argument')        
    except:
        compliance_status('WARN', check_1_1_36)


def request_timeout():
    try:
        searchCommand = 'ps -ef | grep grep kube-apiserver | grep "request-timeout"'
        searchReturn = mySearchReturn(searchCommand)

        if('--request-timeout=' not in searchReturn):
            compliance_status('PASS', check_1_1_37)
            return

        searchReturn = searchReturn.replace('\n', ' ')
        ReturnList = searchReturn.split(' ')

        for item in ReturnList:
            if('--request-timeout=' in item):
                timeOut = item.replace('--request-timeout=','')
                if (int(timeOut) >= REQUEST_TIMEOUT):
                    compliance_status('PASS', check_1_1_37)
                    return
                else:
                    compliance_status('FAIL', check_1_1_37)
                    info3 = 'NOTE: 1.1.37 failed because "--request-timeout" argument is less than '+REQUEST_TIMEOUT
                    compliance_status('INFO', '  *       '+info3)
                    return

        compliance_status('WARN', check_1_1_37)
    except:
        compliance_status('WARN', check_1_1_37)


def main():
    compliance_status('INFO', '1 - Master_Node CIS_Benchmark compliance')
    compliance_status('INFO', 'LEVEL 1')
    api_serverCheck() 

    anonymous_auth(), basic_auth_file(), insecure_allow_token()
    kubelet_https(), insecure_bind_address(), insecure_port()
    secure_port(), profiling(), repair_malformed_updates()
    admission_control(), audit_log_path(), audit_log_maxage()
    audit_log_maxbackup(), audit_log_maxsize(), authorization1()
    token_auth_file(), kubelet_certificate_authority()
    kubelet_client_cert_and_key(), service_account_lookup()
    admin_ctrl_PodSec(), service_account_key_file()
    etcd_certfile_and_keyfile(), admin_ctrl_ServAcc()
    tls_cert_and_private_key_file(), client_ca_file()
    etcd_cafile(), authorization2(), admin_ctrl_NodeRstrict()
    exp_encrypt_prvd_config(), encryption_provider()
    admin_Ctrl_Event(), advancedAuditing(), request_timeout()
main()
