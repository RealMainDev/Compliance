#!/usr/bin/python
import os, sys
import subprocess
import commands

check_1_2_1="1.2.1  - Ensure that the --profiling argument is set to false"

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

def kube_scheduler_Check():
    try:
        kubeScheduler ='ps -ef | grep kube-scheduler'
        textReturn = commands.getoutput(kubeScheduler)
        textReturn = textReturn.replace(kubeScheduler,'')
        myText = textReturn.replace('--color=auto','').translate(None,"{}<>&;")

        textArray = myText.split(" ")
        largestIndex = len(textArray)-1

        if(textArray.index('kube-scheduler') < largestIndex and len(textArray) >= 20):
            compliance_status('INFO', '1.2  -  Checking Scheduler')
        else:
        	compliance_status('INFO', '1.2  -  Checking Scheduler')
        	compliance_status('WARN', '  *     CIS_Benchmark compliance script for kube-scheduler will abort')
        	exit()
    except:
        info = "  *     kube-scheduler didn't respond. Check logs or perform 'ps -ef | grep for kube-scheduler'"
        compliance_status('WARN', info)
        compliance_status('WARN', '  *     CIS_Benchmark compliance script for kube-scheduler has aborted')
        exit()    


def profiling():
    try:
        textSearch = 'ps -ef | grep kube-scheduler | grep "profiling"'
        searchReturn = mySearchReturn(textSearch)

        if('--profiling=false' in searchReturn):
            compliance_status('PASS', check_1_2_1)
        else:
            compliance_status('FAIL', check_1_2_1)
    except:
        compliance_status('WARN', check_1_2_1)


def main():
    compliance_status('INFO', 'LEVEL 1')
    kube_scheduler_Check()
    profiling()

main()