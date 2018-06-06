#!/usr/bin/python
import commands

check_3_2_1="Ensure that the --profiling argument is set to false"

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


def mySearchReturn(mySearch):
    return commands.getoutput(mySearch)

print('')

def profiling():
	try:
		textSearch = 'ps -ef | grep federation-controller-manager | grep "profiling"'
		searchReturn = mySearchReturn(textSearch)

		if('--profiling=false' in searchReturn):
			compliance_status('PASS', check_3_2_1)
		else:
			compliance_status('FAIL', check_3_2_1)
	except:
		compliance_status('WARN', check_3_2_1)

def main():
	compliance_status('INFO', '3.2 - Checking Federation Controller Manager')
	compliance_status('INFO', 'LEVEL 1')
	profiling()

main()