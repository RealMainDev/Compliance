#!/bin/sh

bldylw='\033[1;33m' 
txtrst='\033[0m'

CIS_Timestamp() {
  Start_Time=`date`
  Yell_1="------------- COMPLIANCE TIMESTAMP IS: "
  Yell_2=" -------------"
  
  printf "%b\n" "${bldylw}$Yell_1$Start_Time$Yell_2${txtrst}\n"
}

myEcho () {
  printf "%b\n" "${bldylw}$1${txtrst}\n"
}

myEcho "# ------------------------------------------------------------------------------        
#   TESTING K8s testBranch 2a
#   
#
#   
# ------------------------------------------------------------------------------"

CIS_Timestamp

# Program requirement check
requirements='grep pgrep python'
for req in $requirements; do
  command -v "$req" >/dev/null 2>&1 || { printf "%s command not found\n" "$req"; exit 1; }
done

main () {
  for script in master_pythonScripts/master_*.py
  do
     ./"$script"
  done
}

# main "$@"

echo 'DONE' > testFile
