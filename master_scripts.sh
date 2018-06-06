#!/bin/sh

bldylw='\033[1;33m' 
txtrst='\033[0m'

myEcho () {
  printf "%b\n" "${bldylw}$1${txtrst}\n"
}

myEcho "# ------------------------------------------------------------------------------        
#   Kubernetes CIS Benchmark
#   Version 1.2.0 
#
#   Optum Technology. (c) 2018
# ------------------------------------------------------------------------------"

# Program requirement check
requirements='grep pgrep kubectl python'
for req in $requirements; do
  command -v "$req" >/dev/null 2>&1 || { printf "%s command not found\n" "$req"; exit 1; }
done

main () {
  for script in master_pythonScripts/master_*.py
  do
     ./"$script"
  done
}

main "$@"