#!/usr/bin/python
import os, sys, pwd
import commands

kube_apiserver_yaml_path = "/etc/kubernetes/manifests/kube-apiserver.yaml"

check_1_6_1="1.6.1  - Ensure that the cluster-admin role is only used where required(Not Scored)"
check_1_6_2="1.6.2  - Create Pod Security Policies for your cluster (Not Scored)"
check_1_6_3="1.6.3  - Create administrative boundaries between resources using namespaces (Not Scored)"
check_1_6_4="1.6.4  - Create network segmentation using Network Policies (Not Scored)"
check_1_6_5="1.6.5  - Ensure that the seccomp profile is set to docker/default in your pod definitions (Originally Not Scored)"
check_1_6_6="1.6.6  - Apply Security Context to Your Pods and Containers (Not Scored)"
check_1_6_7="1.6.7  - Configure Image Provenance using ImagePolicyWebhook admission controller (Not Scored)"
check_1_6_8="1.6.8  - Configure Network policies as appropriate (Not Scored)"
check_1_6_9="1.6.9  - Place compensating controls in the form of PSP and RBAC for privileged containers usage (Not Scored)"


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


def cluster_admin():
    try:
        adminSearch = "kubectl get clusterrolebindings -o=custom-columns="
        adminSearch2 = "NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:"
        adminSearch3 = ".subjects[*].name | grep cluster-admin"

        textSearch = adminSearch + adminSearch2 + adminSearch3
        searchReturn = mySearchReturn(textSearch)

        if 'The connection to the server localhost:' in searchReturn:
                info = '  *       Unable to access "cluster-admin" roles. ' + searchReturn
                compliance_status('FAIL', check_1_6_1)
                compliance_status('FAIL', info)
                return

        searchReturn = searchReturn.replace('\n', '').replace(' ','')
        principal_List = searchReturn.split('cluster-admin')
        for principal in principal_List:
            if(principal != 'system:masters' and principal != ''):
                compliance_status('FAIL', check_1_6_1)
                info1 = '  *      cluster-admin role was assigned to: "' +principal +'"'
                info2 = '  *      For security, "cluster-admin" role should only be assigned to "system:master"'
                compliance_status('INFO', info1)
                compliance_status('INFO', info2)
                return

        compliance_status('PASS', check_1_6_1)

    except:
        compliance_status('WARN', check_1_6_1)


def pod_Security_Policies():
    try:
        pspSearch = "kubectl get psp"
        searchReturn = mySearchReturn(pspSearch)

        print('')
        compliance_status('INFO', check_1_6_2)
        compliance_status('INFO', '1.6.2  - Pod security policies listed below:')

        searchReturn = searchReturn.split('\n')
        for policy in searchReturn:
            compliance_status('INFO', '  *      ' + policy)

    except:
        compliance_status('WARN', check_1_6_2)


def administrative_boundaries():
    try:
        namespaceSearch = "kubectl get namespaces"
        searchReturn = mySearchReturn(namespaceSearch)

        print('')
        compliance_status('INFO', check_1_6_3)
        compliance_status('INFO', '1.6.3  - namespaces for administrative boundaries listed below:')

        searchReturn = searchReturn.split('\n')
        for namespace in searchReturn:
            compliance_status('INFO', '  *      ' + namespace)

    except:
        compliance_status('WARN', check_1_6_3)


def network_segmentation():
    try:
        ntwSearch = "kubectl get pods --namespace=kube-system"
        searchReturn = mySearchReturn(ntwSearch)

        print('')
        compliance_status('INFO', check_1_6_4)
        compliance_status('INFO', '1.6.4  - Below is the list of NetworkPolicy objects created in the cluster:')

        networkPolicyList = searchReturn.split('\n')
        for ntwPolicyObject in networkPolicyList:
            compliance_status('INFO', '  *      ' + ntwPolicyObject)

    except:
        compliance_status('WARN', check_1_6_4)


def seccomp_profile():
    try:
        seccompSearch = "seccomp.security.alpha.kubernetes.io/pod:"
        searchCommand = "ps -ef | grep" + " " + seccompSearch + " "+kube_apiserver_yaml_path
        searchReturn = mySearchReturn(searchCommand)

        if 'docker/default' in searchReturn:
            compliance_status('PASS', check_1_6_5)
        else:
            compliance_status('FAIL', check_1_6_5)
    except:
        compliance_status('WARN', check_1_6_5)


def pod_security_context():
	try:
		compliance_status('INFO', check_1_6_6)
	except:
		compliance_status('WARN', check_1_6_6)

def config_image_provenance():
	try:
		compliance_status('INFO', check_1_6_7)
		info ="1.6.7  - Review the pod definitions in your cluster and verify"
		info2 =" that image provenance is configured as appropriate"
		compliance_status('INFO', info + info2)
	except:
		compliance_status('WARN', check_1_6_7)


def config_network_policies():
    try:
        ntwSearch = "kubectl get NetworkPolicy"
        searchReturn = mySearchReturn(ntwSearch)

        print('')
        compliance_status('INFO', check_1_6_8)
        compliance_status('INFO', '1.6.8  - Below is the list of Network Policies created in the cluster:')

        networkPolicyList = searchReturn.split('\n')
        for ntwPolicy in networkPolicyList:
            compliance_status('INFO', '  *      ' + ntwPolicy)

    except:
        compliance_status('WARN', check_1_6_9)


def compensating_controls():
    try:
        pspSearch = "kubectl get psp"
        searchReturn = mySearchReturn(pspSearch)

        print('')
        compliance_status('INFO', check_1_6_9)
        compliance_status("INFO", '1.6.9. - Review the list (below) of Pod Security Policies enforced on the cluster:')

        pspList = searchReturn.split('\n')
        for Policy in pspList:
            compliance_status('INFO', '  *      ' + Policy)


        print(' ')
        compliance_status("INFO", '1.6.9. - Review the RBAC authorization (rolebinding):')
        compliance_status("INFO", '1.6.9. - Ensure that these policies are configured as per your security requirements')
        roleSearch = "kubectl get rolebinding"
        searchReturn = mySearchReturn(roleSearch)
        roleList = searchReturn.split('\n')

        for role in roleList:
            compliance_status('INFO', '  *      ' + role)

        
        print(' ')
        compliance_status("INFO", '1.6.9. - Review the RBAC authorization (clusterrolebinding):')
        compliance_status("INFO", '1.6.9. - Ensure that these policies are configured as per your security requirements')

        roleSearch2 = "kubectl get clusterrolebinding"
        searchReturn2 = mySearchReturn(roleSearch2)
        roleBindingList = searchReturn2.split('\n')        

        for role in roleBindingList:
            compliance_status('INFO', '  *      ' + role)

    except:
        compliance_status('WARN', check_1_6_9)

def main():
    print('')
    compliance_status('INFO', '1.6 - Checking General Security Primitives')
    compliance_status('INFO', 'LEVEL 2')
    cluster_admin(), pod_Security_Policies()
    administrative_boundaries(), network_segmentation()
    seccomp_profile(), pod_security_context()
    config_image_provenance(), config_network_policies()
    compensating_controls()

main()


