#!/bin/sh

bldylw='\033[1;33m' 
txtrst='\033[0m'

myEcho () {
  printf "%b\n" "${bldylw}$1${txtrst}\n"
}
TEST='TEST4'
myEcho "# ------------------------------------------------------------------------------        
#   TESTING K8s testBranch 2
#   
#
#   
# ------------------------------------------------------------------------------"

# Program requirement check
requirements='grep pgrep python'
for req in $requirements; do
  command -v "$req" >/dev/null 2>&1 || { printf "%s command not found\n" "$req"; exit 1; }
done

echo 'DONE' > testFile

