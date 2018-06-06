#!/usr/bin/python
import os, sys, pwd
import commands

kube_apiserver_yaml_path = "/etc/kubernetes/manifests/kube-apiserver.yaml"
kube_ctrl_manager_yaml_path = "/etc/kubernetes/manifests/kube-controller-manager.yaml"
kube_scheduler_yaml_path = "/etc/kubernetes/manifests/kube-scheduler.yaml"
etcd_pod_yaml_file_path = "/etc/kubernetes/manifests/etcd.yaml"
container_network_dir_path = "/etc/kubernetes/manifests"
etcd_data_directory_path = "/var/lib/etcd"
admin_conf_file_path = "/etc/kubernetes/admin.conf"
scheduler_conf_path = "/etc/kubernetes/scheduler.conf"
ctrl_manager_conf_path = "/etc/kubernetes/controller-manager.conf"


check_1_4_1="1.4.1  - Ensure that the API server pod specification file permissions are set to 644 or more restrictive"
check_1_4_2="1.4.2  - Ensure that the API server pod specification file ownership is set to root:root"
check_1_4_3="1.4.3  - Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive"
check_1_4_4="1.4.4  - Ensure that the controller manager pod specification file ownership is set to root:root"
check_1_4_5="1.4.5  - Ensure that the scheduler pod specification file permissions are set to 644 or more restrictive"
check_1_4_6="1.4.6  - Ensure that the scheduler pod specification file ownership is set to root:root"
check_1_4_7="1.4.7  - Ensure that the etcd pod specification file permissions are set to 644 or more restrictive"
check_1_4_8="1.4.8  - Ensure that the etcd pod specification file ownership is set to root:root"
check_1_4_9="1.4.9  - Ensure that the Container Network Interface file permissions are set to 644 or more restrictive"
check_1_4_10="1.4.10  - Ensure that the Container Network Interface file ownership is set to root:root"
check_1_4_11="1.4.11  - Ensure that the etcd data directory permissions are set to 700 or more restrictive"
check_1_4_12="1.4.12  - Ensure that the etcd data directory ownership is set to etcd:etcd"
check_1_4_13="1.4.13  - Ensure that the admin.conf file permissions are set to 644 or more restrictive"
check_1_4_14="1.4.14  - Ensure that the admin.conf file ownership is set to root:root"
check_1_4_15="1.4.15  - Ensure that the scheduler.conf file permissions are set to 644 or more restrictive"
check_1_4_16="1.4.16  - Ensure that the scheduler.conf file ownership is set to root:root"
check_1_4_17="1.4.17  - Ensure that the controller-manager.conf file permissions are set to 644 or more restrictive"
check_1_4_18="1.4.18  - Ensure that the controller-manager.conf file ownership is set to root:root"


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
    searchReturn = commands.getoutput(mySearch)
    return searchReturn.strip().replace(' ', '')

print('')

def kube_apiserver_yaml():
    try:
        if(fileExists(kube_apiserver_yaml_path) == False):
            compliance_status('WARN', '  *     "' + kube_apiserver_yaml_path + '" was not found')
            exit()
    except:
        compliance_status('WARN', '  *      Aborting Configuration_files compliance script')
        compliance_status('WARN', '  *      Configuration_files compliance script has aborted')
        exit()


def api_server_file():
    try:
        getPerm = os.stat(kube_apiserver_yaml_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_1)
        else:
            compliance_status('FAIL', check_1_4_1)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_2)
        else:
            compliance_status('FAIL', check_1_4_2)
    except:
        compliance_status('WARN', check_1_4_1)
        compliance_status('WARN', check_1_4_2)



def control_manager_file():
    try:
        getPerm = os.stat(kube_ctrl_manager_yaml_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_3)
        else:
            compliance_status('FAIL', check_1_4_3)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_4)
        else:
            compliance_status('FAIL', check_1_4_4)
    except:
        compliance_status('WARN', check_1_4_3)
        compliance_status('WARN', check_1_4_4)



def scheduler_file():
    try:
        getPerm = os.stat(kube_scheduler_yaml_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_5)
        else:
            compliance_status('FAIL', check_1_4_5)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_6)
        else:
            compliance_status('FAIL', check_1_4_6)
    except:
        compliance_status('WARN', check_1_4_5)
        compliance_status('WARN', check_1_4_6)



def etcd_pod_file():
    try:
        if(fileExists(etcd_pod_yaml_file_path)== False):
            compliance_status('FAIL', check_1_4_7)
            compliance_status('WARN', '  *       "' + etcd_pod_yaml_file_path + '" was not found')
            return

        getPerm = os.stat(etcd_pod_yaml_file_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_7)
        else:
            compliance_status('FAIL', check_1_4_7)
            info = '  *       "'+ etcd_pod_yaml_file_path + '" permission is ' +last_3_digits+ '. Permission must be set to 644, 640, or 600'
            compliance_status('WARN', info)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_8)
        else:
            compliance_status('FAIL', check_1_4_8)
            info = '  *       "' + etcd_pod_yaml_file_path + '" ownership is "' + userinfo.pw_name +'". Ownership must be set to "root"'
            compliance_status('WARN', info)
    except:
        compliance_status('WARN', check_1_4_7)
        compliance_status('WARN', check_1_4_8)



def container_ntwk_file_permissions():
    try:
        if(pathExists(container_network_dir_path)== False):
            compliance_status('FAIL', check_1_4_9)
            compliance_status('WARN', '  *       The path "' + container_network_dir_path + '" was not found')
            return

        Perm = False
        fileList = os.listdir(container_network_dir_path)

        for filename in fileList:
            filePath = container_network_dir_path +'/'+filename
            getPerm = os.stat(filePath)
            octal_perm = oct(getPerm.st_mode)
            last_3_digits = str(octal_perm[-3:])
           
            if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
                Perm = True
            else:
                compliance_status('FAIL', check_1_4_9)
                info = '  *       "'+ filePath + '" permission is ' +last_3_digits+ '. permission must be set to 644, 640, or 600'
                compliance_status('WARN', info)
                return

        compliance_status('PASS', check_1_4_9)
    except:
        compliance_status('WARN', check_1_4_9)


def container_ntwk_file_ownership():
    try:
        if(pathExists(container_network_dir_path)== False):
            compliance_status('FAIL', check_1_4_10)
            compliance_status('WARN', '  *       The path "' + container_network_dir_path + '" was not found')
            return

        fileList = os.listdir(container_network_dir_path)
        for filename in fileList:
            filePath = container_network_dir_path +'/'+filename
            getPerm = os.stat(filePath)
            uid = getPerm.st_uid
            userinfo = pwd.getpwuid(getPerm.st_uid)
            userName = userinfo.pw_name
           
            if (userName != 'root'):
                compliance_status('FAIL', check_1_4_10)
                fileInfo = '  *       "' + filePath + '" ownership is "' + userName +'". Ownership must be set to "root"'
                compliance_status('WARN', fileInfo)
                return

        compliance_status('PASS', check_1_4_10)
    except:
        compliance_status('WARN', check_1_4_10)


def etcd_data_dir():
    try:
        if(pathExists(etcd_data_directory_path)== False):
            compliance_status('FAIL', check_1_4_11)
            compliance_status('FAIL', check_1_4_12)
            compliance_status('WARN', '  *       The path "' + etcd_data_directory_path + '" was not found')
            return

        getPerm = os.stat(etcd_data_directory_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '700'):
            compliance_status('PASS', check_1_4_11)
        else:
            compliance_status('FAIL', check_1_4_11)
            info = '  *       "'+ etcd_data_directory_path + '" permission is ' +last_3_digits+ '. Permission must be set to 700'
            compliance_status('WARN', info)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'etcd'):
            compliance_status('PASS', check_1_4_12)
        else:
            compliance_status('FAIL', check_1_4_12)
            info = '  *       "' + etcd_data_directory_path + '" ownership is "' + userinfo.pw_name +'". Ownership must be set to "etcd"'
            compliance_status('WARN', info)
    except:
        compliance_status('WARN', check_1_4_11)
        compliance_status('WARN', check_1_4_12)



def admin_conf():
    try:
        if(fileExists(admin_conf_file_path)== False):
            compliance_status('FAIL', check_1_4_13)
            compliance_status('FAIL', check_1_4_14)
            compliance_status('WARN',  '  *       "' + admin_conf_file_path + '" was not found')
            return
        getPerm = os.stat(admin_conf_file_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])
        
        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_13)
        else:
            compliance_status('FAIL', check_1_4_13)
            info = '  *       "'+ admin_conf_file_path + '" permission is ' +last_3_digits+ '. Permission must be set to 644, 640, or 600'
            compliance_status('WARN', info)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_14)
        else:
            compliance_status('FAIL', check_1_4_14)
            info = '  *       "' + admin_conf_file_path + '" ownership is "' + userinfo.pw_name +'". Ownership must be set to "root"'
            compliance_status('WARN', info)
    except:
        compliance_status('WARN', check_1_4_13)
        compliance_status('WARN', check_1_4_14)



def scheduler_conf():
    try:
        if(fileExists(scheduler_conf_path)== False):
            compliance_status('FAIL', check_1_4_15)
            compliance_status('FAIL', check_1_4_16)
            compliance_status('WARN',  '  *       "' + scheduler_conf_path + '" was not found')
            return
        getPerm = os.stat(scheduler_conf_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_15)
        else:
            compliance_status('FAIL', check_1_4_15)
            info = '  *       "'+ scheduler_conf_path + '" permission is ' +last_3_digits+ '. Permission must be set to 644, 640, or 600'
            compliance_status('WARN', info)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_16)
        else:
            compliance_status('FAIL', check_1_4_16)
            info = '  *       "' + scheduler_conf_path + '" ownership is "' + userinfo.pw_name +'". Ownership must be set to "root"'
            compliance_status('WARN', info)
    except:
        compliance_status('WARN', check_1_4_15)
        compliance_status('WARN', check_1_4_16)


def control_manager_conf():
    try:
        if(fileExists(ctrl_manager_conf_path)== False):
            compliance_status('FAIL', check_1_4_17)
            compliance_status('FAIL', check_1_4_18)
            compliance_status('WARN',  '  *       "' + ctrl_manager_conf_path + '" was not found')
            return
        getPerm = os.stat(ctrl_manager_conf_path)
        octal_perm = oct(getPerm.st_mode)
        last_3_digits = str(octal_perm[-3:])

        if(last_3_digits == '644' or last_3_digits == '640' or last_3_digits == '600'):
            compliance_status('PASS', check_1_4_17)
        else:
            compliance_status('FAIL', check_1_4_17)
            info = '  *       "'+ scheduler_conf_path + '" permission is ' +last_3_digits+ '. Permission must be set to 644, 640, or 600'
            compliance_status('WARN', info)

        uid = getPerm.st_uid
        userinfo = pwd.getpwuid(getPerm.st_uid)

        if (userinfo.pw_name == 'root'):
            compliance_status('PASS', check_1_4_18)
        else:
            compliance_status('FAIL', check_1_4_18)
            info = '  *       "' + ctrl_manager_conf_path + '" ownership is "' + userinfo.pw_name +'". Ownership must be set to "root"'
            compliance_status('WARN', info)
    except:
        compliance_status('WARN', check_1_4_17)
        compliance_status('WARN', check_1_4_18)


def main():
    compliance_status('INFO', '1.4  - Checking Configuration Files')
    compliance_status('INFO', 'LEVEL 1')
    kube_apiserver_yaml()
    api_server_file(), control_manager_file(), scheduler_file()
    etcd_pod_file(), container_ntwk_file_permissions() 
    container_ntwk_file_ownership(), etcd_data_dir()
    admin_conf(), scheduler_conf(), control_manager_conf()
main()




