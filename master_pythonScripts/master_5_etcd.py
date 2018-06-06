#!/usr/bin/python
import os, sys, pwd
import commands


check_1_5_1="1.5.1  - Ensure that the --cert-file and --key-file arguments are set as appropriate (Scored)"
check_1_5_2="1.5.2  - Ensure that the --client-cert-auth argument is set to true (Scored)"
check_1_5_3="1.5.3  - Ensure that the --auto-tls argument is not set to true (Scored)"
check_1_5_4="1.5.4  - Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate (Scored)"
check_1_5_5="1.5.5  - Ensure that the --peer-client-cert-auth argument is set to true (Scored)"
check_1_5_6="1.5.6  - Ensure that the --peer-auto-tls argument is not set to true (Scored)"
check_1_5_7="1.5.7  - Ensure that the --wal-dir argument is set as appropriate (Scored)"
check_1_5_8="1.5.8  - Ensure that the --max-wals argument is set to 0 (Scored)"
check_1_5_9="1.5.9  - Ensure that a unique Certificate Authority is used for etcd (Not Scored)"


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

print('')

def keyFileHelper(certFile):
    try:
        textSearch = 'ps -ef | grep etcd | grep "key-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--key-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--key-file=' in item):
                    tempFile = item.replace('--key-file=','')
                    tempFileList = tempFile.split('\n')
                    keyFile = tempFileList[0]

                    if(fileExists(keyFile)):
                        compliance_status('PASS', check_1_5_1)
                        compliance_status('INFO', '  *     ' + certFile)
                        compliance_status('INFO', '  *     ' + keyFile)
                        return
                    else:
                        compliance_status('FAIL', check_1_5_1)
                        return

        compliance_status('FAIL', check_1_5_1)
    except:
        compliance_status('WARN', check_1_5_1)


def cert_and_Key_file():
    try:
        textSearch = 'ps -ef | grep etcd | grep "cert-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--cert-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--cert-file=' in item):
                    tempFile = item.replace('--cert-file=','')
                    tempFileList = tempFile.split('\n')
                    certFile = tempFileList[0]

                    if(fileExists(certFile)):
                        keyFileHelper(certFile)
                        return
                    else:
                        compliance_status('FAIL', check_1_5_1)
                        return
        else:
            compliance_status('FAIL', check_1_5_1)
    except:
        compliance_status('WARN', check_1_5_1)


def client_cert_auth():
    try:
        textSearch = 'ps -ef | grep etcd | grep "client-cert-auth"'
        searchReturn = mySearchReturn(textSearch)

        if('--client-cert-auth=true' in searchReturn):
            compliance_status('PASS', check_1_5_2)
        else:
            compliance_status('FAIL', check_1_5_2)
    except:
        compliance_status('WARN', check_1_5_2)


def auto_tls():
    try:
        textSearch = 'ps -ef | grep etcd | grep "auto-tls"'
        searchReturn = mySearchReturn(textSearch)

        if('--auto-tls=true' in searchReturn):
            compliance_status('FAIL', check_1_5_3)
        else:
            compliance_status('PASS', check_1_5_3)
    except:
        compliance_status('WARN', check_1_5_3)



def peerFileHelper(certFile):
    try:
        textSearch = 'ps -ef | grep etcd | grep "peer-key-file"'
        searchReturn = mySearchReturn(textSearch)

        note = "  *      Note: 1.5.4 is applicable only for etcd clusters. Disregard if your environment has only one etcd sever"

        if('--peer-key-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--peer-key-file=' in item):
                    tempFile = item.replace('--peer-key-file=','')
                    tempFileList = tempFile.split('\n')
                    keyFile = tempFileList[0]

                    if(fileExists(keyFile)):
                        compliance_status('PASS', check_1_5_4)
                        compliance_status('INFO', '  *     ' + certFile)
                        compliance_status('INFO', '  *     ' + keyFile)
                        return
                    else:
                        compliance_status('FAIL', check_1_5_4)
                        compliance_status('INFO', note)
                        return

        compliance_status('FAIL', check_1_5_4)
        compliance_status('INFO', note)
    except:
        compliance_status('WARN', check_1_5_4)


def peer_Cert_Key_file():
    try:
        textSearch = 'ps -ef | grep etcd | grep "peer-cert-file"'
        searchReturn = mySearchReturn(textSearch)

        note = "  *      Note: 1.5.4 is applicable only for etcd clusters. Disregard if your environment has only one etcd sever"

        if('--peer-cert-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--peer-cert-file=' in item):
                    tempFile = item.replace('--peer-cert-file=','')
                    tempFileList = tempFile.split('\n')
                    certFile = tempFileList[0]

                    if(fileExists(certFile)):
                        peerFileHelper(certFile)
                        return
                    else:
                        compliance_status('FAIL', check_1_5_4)
                        compliance_status('WARN', note)
                        return

        else:
            compliance_status('FAIL', check_1_5_4)
            compliance_status('INFO', note)
    except:
        compliance_status('WARN', check_1_5_4)


def peer_client_cert_auth():
    try:
        textSearch = 'ps -ef | grep etcd | grep "peer-client-cert-auth"'
        searchReturn = mySearchReturn(textSearch)

        note = "  *      Note: 1.5.5 is applicable only for etcd clusters. Disregard if your environment has only one etcd sever"
        if('--peer-client-cert-auth=true' in searchReturn):
            compliance_status('PASS', check_1_5_5)
        else:
            compliance_status('FAIL', check_1_5_5)
            compliance_status('INFO', note)
    except:
        compliance_status('WARN', check_1_5_5)


def peer_auto_tls():
    try:
        textSearch = 'ps -ef | grep etcd | grep "peer-auto-tls"'
        searchReturn = mySearchReturn(textSearch)

        if('--ppeer-auto-tls=true' in searchReturn):
            compliance_status('FAIL', check_1_5_6)
        else:
            compliance_status('PASS', check_1_5_6)
    except:
        compliance_status('WARN', check_1_5_6)


def walDirHelper(wal_dir):
    try:
        textSearch = 'ps -ef | grep etcd | grep "data-dir"'
        searchReturn = mySearchReturn(textSearch)

        if('--data-dir=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--data-dir=' in item):
                    tempDir = item.replace('--data-dir=','')
                    tempDirList = tempDir.split('\n')
                    data_dir = tempDirList[0]

                    if(pathExists(data_dir)):
                        if(data_dir != wal_dir):
                            compliance_status('PASS', check_1_5_7)
                            return
                        else:
                            compliance_status('FAIL', check_1_5_7)
                            info1 = '   *      1.5.7 failed because the same directory {'+data_dir+'} is being used for log data and etcd data'
                            compliance_status('INFO', info1)
                            return
                    else:
                        compliance_status('PASS', check_1_5_7)
                        return

        compliance_status('PASS', check_1_5_7)
    except:
        compliance_status('WARN', check_1_5_7)


def wal_dir():
    try:
        textSearch = 'ps -ef | grep etcd | grep "wal-dir"'
        searchReturn = mySearchReturn(textSearch)

        if('--wal-dir=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--wal-dir=' in item):
                    tempDir = item.replace('--wal-dir=','')
                    tempDirList = tempDir.split('\n')
                    wal_dir = tempDirList[0]

                    if(pathExists(wal_dir)):
                        walDirHelper(wal_dir)
                        return
                    else:
                        compliance_status('FAIL', check_1_5_7)
                        compliance_status('INFO', '  *     the directory "'+keyFile+'" does not exist')
                        return
        else:
            compliance_status('FAIL', check_1_5_7)
    except:
        compliance_status('WARN', check_1_5_7)


def max_wals():
    try:
        textSearch = 'ps -ef | grep etcd | grep "max-wals"'
        searchReturn = mySearchReturn(textSearch)

        if('--max-wals=0' in searchReturn):
            compliance_status('PASS', check_1_5_8)
        else:
            compliance_status('FAIL', check_1_5_8)
    except:
        compliance_status('WARN', check_1_5_8)


def uniqueCAhelper(ca_file):
    try:
        textSearch = 'ps -ef | grep etcd | grep "client-ca-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--client-ca-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--client-ca-file=' in item):
                    tempCA = item.replace('--client-ca-file=','')
                    tempCAList = tempCA.split('\n')
                    clientCA = tempCAList[0]

                    if(fileExists(clientCA)):
                        if(clientCA != ca_file):
                            compliance_status('PASS', check_1_5_9)
                            return
                        else:
                            compliance_status('FAIL', check_1_5_9)
                            info1 = '   *      1.5.9 failed because the same CA file {'+clientCA+'} is being used for etcd and K8s cluster'
                            compliance_status('INFO', info1)
                            return
                    else:
                        compliance_status('PASS', check_1_5_9)
                        return

        compliance_status('PASS', check_1_5_9)
    except:
        compliance_status('WARN', check_1_5_9)


def unique_Certificate():
    try:
        textSearch = 'ps -ef | grep etcd | grep "trusted-ca-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--trusted-ca-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--trusted-ca-file=' in item):
                    tempCA = item.replace('--trusted-ca-file=','')
                    tempCAList = tempCA.split('\n')
                    ca_file = tempCAList[0]

                    if(fileExists(ca_file)):
                        uniqueCAhelper(ca_file)
                        return
                    else:
                        compliance_status('FAIL', check_1_5_9)
                        compliance_status('INFO', '  *     the file "'+ca_file+'" does not exist')
                        return
        else:
            compliance_status('FAIL', check_1_5_9)
    except:
        compliance_status('WARN', check_1_5_9)


def main():
    compliance_status('INFO', '1.5 - Checking etcd')
    compliance_status('INFO', 'LEVEL 1')
    cert_and_Key_file(), client_cert_auth()
    auto_tls(), peer_Cert_Key_file() 
    peer_client_cert_auth(), peer_auto_tls()
    wal_dir(), max_wals()
    compliance_status('INFO', 'LEVEL 2')
    unique_Certificate()

main()


