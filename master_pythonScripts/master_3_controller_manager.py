#!/usr/bin/python
import os, sys
import subprocess
import commands

# GLOBAL VARIABLES
TERMINATED_POD_GARBAGE_THRESHOLD = 5000

check_1_3_1="1.3.1  - Ensure that the --terminated-pod-gc-threshold argument is set as appropriate"
check_1_3_2="1.3.2  - Ensure that the --profiling argument is set to false"
check_1_3_3="1.3.3  - Ensure that the --use-service-account-credentials argument is set to true"
check_1_3_4="1.3.4  - Ensure that the --service-account-private-key-file argument is set as appropriate"
check_1_3_5="1.3.5  - Ensure that the --root-ca-file argument is set as appropriate"
check_1_3_6="1.3.6  - Apply Security Context to Your Pods and Containers (Not Scored)"
check_1_3_7="1.3.7  - Ensure that the RotateKubeletServerCertificate argument is set to true"


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

def mySearchReturn(mySearch):
	return commands.getoutput(mySearch)
    
print('')

def contrl_manager_Check():
    try:
        ctrl_manager ='pps -ef | grep kube-controller-manager'
        textReturn = commands.getoutput(ctrl_manager)
        textReturn = textReturn.replace(ctrl_manager,'')
        myText = textReturn.replace('--color=auto','').translate(None,"{}<>&;")

        textArray = myText.split(" ")

        if( len(textArray) >= 57):
            compliance_status('INFO', '1.3  - Checking Controller Manager')
        else:
        	compliance_status('INFO', '1.3 - Checking Controller Manager')
        	compliance_status('WARN', '  *     CIS_Benchmark compliance script for kube-controller-manager will abort')
        	exit()
    except:
        info = "  *     kube-controller-manager didn't respond. Check logs or perform 'ps -ef | grep for kube-controller-manager'"
        compliance_status('WARN', info)
        compliance_status('WARN', '  *     CIS_Benchmark compliance script for kube-controller-manager has aborted')
        exit()    


def terminated_pod_gc_threshold():
    try:
        searchCommand = 'ps -ef | grep kube-controller-manager | grep "terminated-pod-gc-threshold"'
        searchReturn = mySearchReturn(searchCommand)

        Threshold = str(TERMINATED_POD_GARBAGE_THRESHOLD)
        passText = '--terminated-pod-gc-threshold='+Threshold

        if (passText in searchReturn):
            compliance_status('PASS', check_1_3_1)
        else:
            compliance_status('FAIL', check_1_3_1)
    except:
        compliance_status('WARN', check_1_3_1)


def profiling():
    try:
        searchCommand = 'ps -ef | grep kube-controller-manager'
        searchReturn = mySearchReturn(searchCommand)

        if ('--profiling=false' in searchReturn):
            compliance_status('PASS', check_1_3_2)
        else:
            compliance_status('FAIL', check_1_3_2)
    except:
        compliance_status('WARN', check_1_3_2)


def use_service_account_credentials():
    try:
        searchCommand = 'ps -ef | grep kube-controller-manager'
        searchReturn = mySearchReturn(searchCommand)

        if('--use-service-account-credentials=true' in searchReturn):
            compliance_status('PASS', check_1_3_3)
        else:
            compliance_status('FAIL', check_1_3_3)
    except:
        compliance_status('WARN', check_1_3_3)


def service_account_private_key_file():
    try:
        searchCommand = 'ps -ef | grep kube-controller-manager'
        searchReturn = mySearchReturn(searchCommand)

        if ('--service-account-private-key-file=' in searchReturn):
            searchReturn = searchReturn.replace('\n', ' ')
            ReturnList = searchReturn.split(' ')  

            for item in ReturnList:
                if('--service-account-private-key-file=' in item):
                    fileName = item.replace('--service-account-private-key-file=','')
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_1_3_4)
                        return
                    else:
                        compliance_status('FAIL', check_1_3_4)
                        compliance_status('INFO', '  *   "'+fileName+ '" was not found')
                        return

            compliance_status('PASS', check_1_3_4)
        else:
            compliance_status('FAIL', check_1_3_4)
    except:
        compliance_status('WARN', check_1_3_4)


def root_ca_file():
    try:
        searchCommand = 'ps -ef | grep kube-controller-manager'
        searchReturn = mySearchReturn(searchCommand)

        if ('--root-ca-file=' in searchReturn):
            searchReturn = searchReturn.replace('\n', ' ')
            ReturnList = searchReturn.split(' ')  

            for item in ReturnList:
                if('--root-ca-file=' in item):
                    fileName = item.replace('--root-ca-file=','')
                    if(fileExists(fileName)):
                        compliance_status('PASS', check_1_3_5)
                        return
                    else:
                        compliance_status('FAIL', check_1_3_5)
                        compliance_status('INFO', '  *   "'+fileName+ '" was not found')
                        return

            compliance_status('PASS', check_1_3_5)
        else:
            compliance_status('FAIL', check_1_3_5)
    except:
        compliance_status('WARN', check_1_3_5)


def security_context():
    # LEVEL 2
    # TODO
    pass


def RotateKubeletServerCertificate():
    try:
        searchCommand = 'ps -ef | grep kube-controller-manager'
        searchReturn = mySearchReturn(searchCommand)

        if('RotateKubeletServerCertificate=true' in searchReturn):
            compliance_status('PASS', check_1_3_7)
        else:
            compliance_status('FAIL', check_1_3_7)
    except:
        compliance_status('WARN', check_1_3_7)


def main():
    compliance_status('INFO', 'LEVEL 1')
    contrl_manager_Check()

    terminated_pod_gc_threshold()
    profiling()
    use_service_account_credentials()
    service_account_private_key_file()
    root_ca_file()
    security_context()
    RotateKubeletServerCertificate()
main()