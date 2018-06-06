#!/usr/bin/python
import os, sys, pwd
import commands


check_2_2_1="2.2.1  - Ensure that the kubelet.conf file permissions are set to 644 or more restrictive"
check_2_2_2="2.2.2  - Ensure that the kubelet.conf file ownership is set to root:root"
check_2_2_3="2.2.3  - Ensure that the kubelet service file permissions are set to 644 or more restrictive"
check_2_2_4="2.2.4  - Ensure that the kubelet service file ownership is set to root:root"
check_2_2_5="2.2.5  - Ensure that the proxy kubeconfig file permissions are set to 644 or more restrictive"
check_2_2_6="2.2.6  - Ensure that the proxy kubeconfig file ownership is set to root:root"
check_2_2_7="2.2.7  - Ensure that the certificate authorities file permissions are set to 644 or more restrictive"
check_2_2_8="2.2.8  - Ensure that the client certificate authorities file ownership is set to root:root"

kubeletFile = "/etc/kubernetes/kubelet.conf"
kubeletServiceFile = "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"

print('\n')

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



def kubelet_config_file():
    try:
        if(not fileExists(kubeletFile)):
            compliance_status('FAIL', check_2_2_1)
            compliance_status('INFO', '  *     "{}" was not found' .format(kubeletFile))
            compliance_status('FAIL', check_2_2_2)
            compliance_status('INFO', '  *     "{}" was not found' .format(kubeletFile))
            return

        getPerm = os.stat(kubeletFile)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_2_2_1)
        else:
            compliance_status('FAIL', check_2_2_1)
            compliance_status('INFO', '  *     "'+ kubeletFile+'" current permission is '+last_3_digits)


        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_2_2_2)
        else:
            compliance_status('FAIL', check_2_2_2)
            compliance_status('INFO', '  *     "'+ kubeletFile+'" current ownership is '+userinfo.pw_name)
    except:
        compliance_status('WARN', check_2_2_1)
        compliance_status('WARN', check_2_2_2)


def kubelet_service_file():
    try:
        if(not fileExists(kubeletServiceFile)):
            compliance_status('FAIL', check_2_2_3)
            compliance_status('INFO', '  *     "{}" was not found' .format(kubeletServiceFile))
            compliance_status('FAIL', check_2_2_4)
            compliance_status('INFO', '  *     "{}" was not found' .format(kubeletServiceFile))
            return

        getPerm = os.stat(kubeletServiceFile)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_2_2_3)
        else:
            compliance_status('FAIL', check_2_2_3)
            compliance_status('INFO', '  *     "'+ kubeletServiceFile+'" current permission is '+last_3_digits)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_2_2_4)
        else:
            compliance_status('FAIL', check_2_2_4)
            compliance_status('INFO', '  *     "'+ kubeletServiceFile+'" current ownership is '+userinfo.pw_name)
    except:
        compliance_status('WARN', check_2_2_3)
        compliance_status('WARN', check_2_2_4)


def proxy_kubeconfig_perm():
    try:
        textSearch = 'ps -ef | grep kube-proxy | grep "config="'
        searchReturn = mySearchReturn(textSearch)


        if('--kubeconfig=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--kubeconfig=' in item):
                    kubeProxy = item.replace('--kubeconfig=','')
                    kubeProxyList = kubeProxy.split('\n')
                    kubeProxyFile = kubeProxyList[0]

                    if(fileExists(kubeProxyFile)):
                        getPerm = os.stat(kubeProxyFile)
                        octal_perm = oct(getPerm.st_mode)
                        last_3_digits = str(octal_perm[-3:])
                        if(last_3_digits != '644' and last_3_digits != '640' and last_3_digits != '600'):
                            compliance_status('FAIL', check_2_2_5)
                            compliance_status('INFO', '  *     "'+ kubeProxyFile+'" current permission is '+last_3_digits)
                            return
                    else:
                        compliance_status('FAIL', check_2_2_5)
                        compliance_status('INFO', '  *     "{}" was not found' .format(kubeProxyFile))
                        return
            compliance_status('PASS', check_2_2_5)

        elif('--config=' in searchReturn):
            ReturnList2 = searchReturn.split(' ')

            for item in ReturnList2:
                if('--config=' in item):
                    kubeProxy = item.replace('--config=','')
                    kubeProxyList = kubeProxy.split('\n')
                    kubeProxyFile = kubeProxyList[0]

                    if(fileExists(kubeProxyFile)):
                        getPerm = os.stat(kubeProxyFile)
                        octal_perm = oct(getPerm.st_mode)
                        last_3_digits = str(octal_perm[-3:])
                        if(last_3_digits != '644' and last_3_digits != '640' and last_3_digits != '600'):
                            compliance_status('FAIL', check_2_2_5)
                            compliance_status('INFO', '  *     "'+ kubeletFile+'" current permission is '+last_3_digits)
                            return
                    else:
                        compliance_status('FAIL', check_2_2_5)
                        compliance_status('INFO', '  *     "{}" was not found' .format(kubeProxyFile))
                        return
            compliance_status('PASS', check_2_2_5)
             
        else:
          compliance_status('FAIL', check_2_2_5)
          compliance_status('INFO', '  *     "--kubeconfig" parameter for kube-proxy was not set')
    except:
        compliance_status('WARN', check_2_2_5)


def proxy_kubeconfig_ownership():
    try:
        textSearch = 'ps -ef | grep kube-proxy | grep "config="'
        searchReturn = mySearchReturn(textSearch)

        if('--kubeconfig=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--kubeconfig=' in item):
                    kubeProxy = item.replace('--kubeconfig=','')
                    kubeProxyList = kubeProxy.split('\n')
                    kubeProxyFile = kubeProxyList[0]

                    if(fileExists(kubeProxyFile)):
                        getPerm = os.stat(kubeProxyFile)
                        uid = getPerm.st_uid
                        userinfo = pwd.getpwuid(getPerm.st_uid)

                        if (userinfo.pw_name != 'root'):
                            compliance_status('FAIL', check_2_2_6)
                            compliance_status('INFO', '  *     "'+ kubeProxyFile+'" current ownership is '+userinfo.pw_name)
                            return
                    else:
                        compliance_status('FAIL', check_2_2_6)
                        compliance_status('INFO', '  *     "{}" was not found' .format(kubeProxyFile))
                        return
            compliance_status('PASS', check_2_2_6)
        
        elif('--config=' in searchReturn):
            ReturnList2 = searchReturn.split(' ')

            for item in ReturnList2:
                if('--config=' in item):
                    kubeProxy = item.replace('--config=','')
                    kubeProxyList = kubeProxy.split('\n')
                    kubeProxyFile = kubeProxyList[0]
                  
                    if(fileExists(kubeProxyFile)):
                        getPerm = os.stat(kubeProxyFile)
                        uid = getPerm.st_uid
                        userinfo = pwd.getpwuid(getPerm.st_uid)

                        if (userinfo.pw_name != 'root'):
                            compliance_status('FAIL', check_2_2_6)
                            compliance_status('INFO', '  *     "'+ kubeProxyFile+'" current ownership is '+userinfo.pw_name)
                            return
                    else:
                        compliance_status('FAIL', check_2_2_6)
                        compliance_status('INFO', '  *     "{}" was not found' .format(kubeProxyFile))
                        return
            compliance_status('PASS', check_2_2_6)
             
        else:
          compliance_status('FAIL', check_2_2_6)
          compliance_status('INFO', '  *     "--kubeconfig" parameter for kube-proxy was not set')
    except:
        compliance_status('WARN', check_2_2_6) 


def certificate_authorities():
    try:
        textSearch = 'ps -ef | grep kubelet | grep "client-ca-file"'
        searchReturn = mySearchReturn(textSearch)
       
        if('--client-ca-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')
           
            for item in ReturnList:
                if('--client-ca-file=' in item):
                    certAuthFile = item.replace('--client-ca-file=','')               
                    if(fileExists(certAuthFile)== False):
                        compliance_status('FAIL', check_2_2_7)
                        compliance_status('INFO', '  *     "{}" was not found' .format(certAuthFile))
                        return
                    else:
                        getPerm = os.stat(certAuthFile)
                        octal_perm = oct(getPerm.st_mode)
                        last_3_digits = str(octal_perm[-3:])
                        if(last_3_digits != '644' and last_3_digits != '640' and last_3_digits != '600'):
                            compliance_status('FAIL', check_2_2_7)
                            compliance_status('INFO', '  *     "'+ certAuthFile+'" current permission is '+last_3_digits)
                            return
                    
            compliance_status('PASS', check_2_2_7)
        else:       
            compliance_status('FAIL', check_2_2_7)
    except:
        compliance_status('WARN', check_2_2_7)


def client_certificate():
    try:
        textSearch = 'ps -ef | grep kubelet | grep "client-ca-file"'
        searchReturn = mySearchReturn(textSearch)
       
        if('--client-ca-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')       
            for item in ReturnList:
                if('--client-ca-file=' in item):
                    certAuthFile = item.replace('--client-ca-file=','')
                    
                    if(fileExists(certAuthFile)== False):
                        compliance_status('FAIL', check_2_2_8)
                        compliance_status('INFO', '  *     "{}" was not found' .format(certAuthFile))
                        return
                    else:
                        getPerm = os.stat(certAuthFile)
                        uid = getPerm.st_uid
                        userinfo = pwd.getpwuid(getPerm.st_uid)

                        if(userinfo.pw_name != 'root'):
                            compliance_status('FAIL', check_2_2_8)
                            compliance_status('INFO', '  *     "'+ certAuthFile+'" current ownership is '+userinfo.pw_name)
                            return                  
            compliance_status('PASS', check_2_2_8)
        else:       
            compliance_status('FAIL', check_2_2_8)
    except:
      compliance_status('INFO', check_2_2_8)


def privateKeyHelper(certFile):
    try:
        textSearch = 'ps -ef | grep kubelet | grep "tls-private-key-file"'
        searchReturn = mySearchReturn(textSearch)

        if('--tls-private-key-file=' in searchReturn):
            ReturnList = searchReturn.split(' ')

            for item in ReturnList:
                if('--tls-private-key-file=' in item):
                    privateKeyFile = item.replace('--tls-private-key-file','')

                    if(fileExists(privateKeyFile)):
                        compliance_status('PASS', check_2_1_12)
                        compliance_status('INFO', '  *    ' + certfile)
                        compliance_status('INFO', '  *    ' + item)
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
                    certFile = item.replace('--tls-cert-file=','')

                    if(fileExists(certFile)):
                        privateKeyHelper(item)
                        return
                    else:
                        compliance_status('FAIL', check_2_1_12)

        else:
            compliance_status('FAIL', check_2_1_12)
    except:
        compliance_status('WARN', check_2_1_4)



def main():
  compliance_status('INFO', '2.2 - Checking Configuration Files')
  compliance_status('INFO', 'LEVEL 1')
  kubelet_config_file()
  kubelet_service_file()
  proxy_kubeconfig_perm()
  proxy_kubeconfig_ownership()
  certificate_authorities()
  client_certificate()

main()
