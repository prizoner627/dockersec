# Load output formating
. ./functions/output_lib.sh

DANGEROUS_CAPABILITIES="cap_sys_admin\|cap_sys_ptrace\|cap_sys_module\|dac_read_search\|dac_override"
DANGEROUS_GROUPS="docker\|lxd\|root\|sudo\|wheel"
TIP_PRIVILEGED_MODE="The container appears to be running in privilege mode, we should be able to access the raw disks and mount the hosts root partition in order to gain code execution."
GREP_SECRETS="pass\|secret\|key"
GREP_SOCK_INFOS="Architecture\|OSType\|Name\|DockerRootDir\|NCPU\|OperatingSystem\|KernelVersion\|ServerVersion"
GREP_SOCK_INFOS_IGNORE="IndexConfig"
GREP_IGNORE_MOUNTS="/ /\|/cgroup\|/var/lib/docker/\|/null \| proc proc \|/dev/console\|docker.sock"
CONTAINER_CMDS="docker lxc rkt kubectl podman"

C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
Y="${C}[1;33m"
B="${C}[1;34m"
LG="${C}[1;37m" #LightGray
DG="${C}[1;90m" #DarkGray
NC="${C}[0m"
UNDERLINED="${C}[4m"
EX="${C}[48;5;1m"

# helpers
###########################################
#--------------) Printing (---------------#
###########################################

printer() {
  # Only print if not empty
  if [ "$2" ]; then
    # Temporarily replace the IFS with null to preserve newline chars
    OLDIFS=$IFS
    IFS=
    printf "%s%s%s\n" "$1" "$2" "$NC"
    # Restore it so we don't break anything else
    IFS=$OLDIFS
  fi
}

printSection() {
  # Print a section like:
  # ========================================( Title here )========================================
  l=94
  if [ "$1" ]; then
    s="( $1 )"
  else
    s="$1"
  fi
  size=${#s}
  no=$((l-size))
  start=$((no/2))
  end=$((no-start))
  printf "%s%${start}s" "$B" | tr " " "="
  printf "%s%s%s" "$GREEN" "$s" "$B"
  printf "%${end}s" | tr " " "="
  printf "%s\n" "$NC"
}

printEx() { printer "$EX" "$1"; }
printFail() { printer "$DG" "$1"; }
printInfo() { printer "$LG" "$1"; }
printError() { printer "$RED" "$1"; }
printSuccess() { printer "$Y" "$1"; }
printQuestion() { printf "%s[+]%s %s %s" "$Y" "$GREEN" "$1" "$NC"; }
printStatus() { printer "$DG" "$1"; }
printYesEx() { printEx Yes; }
printYes() { printSuccess Yes; }
printNo() { printFail No; }
TODO() { printError "${NC}TODO $1"; }
nl() { echo ""; }

printTip() {
  if [ "$quiet" ]; then
    return
  fi
  printer "$DG" "$1" | fold -s -w 95
  nl
}

printResult() {
  printQuestion "$1"
  if [ "$2" ]; then
    printSuccess "$2"
  else
    if [ "$3" ]; then
      printError "$3"
    else
      printNo
    fi
  fi
}

printResultLong() {
  printQuestion "$1"
  if [ "$2" ]; then
    printYes
    printStatus "$2"
  else
    if [ "$3" ]; then
      printError "$3"
    else
      printNo
    fi
  fi
}

printMsg() {
  printQuestion "$1"
  printFail "$2"
}


unsetColors(){
  RED=""
  GREEN=""
  Y=""
  B=""
  LG=""
  DG=""
  NC=""
  UNDERLINED=""
  EX=""
}

# checks

userCheck() {
  scjson
  startsectionjson "Docker Container" "Description"
  printQuestion "User ...................."
  if [ "$(id -u)" = 0 ]; then
    isUserRoot="1"
    printSuccess "root"
    starttestjson "User" "root"
    logcheckresult "INFO"    
  else
    printSuccess "$(whoami)"
    starttestjson "User" "$(whoami)"
    logcheckresult "INFO"  
  fi

  printQuestion "Groups .................."
  groups=$(groups| sed "s/\($DANGEROUS_GROUPS\)/${LG}${EX}&${NC}${DG}/g")
  starttestjson "Groups" "$(groups)"
  logcheckresult "INFO"  
  printStatus "$groups" "None"
}

containerID() {
    # Get container ID
    containerID="$(cat /etc/hostname)"
    #containerID="$(hostname)"
    #containerID="$(uname -n)"
    # Get container full ID
    printResult "Container ID ............" "$containerID" "Unknown"
    starttestjson "Container ID" "$containerID"
    logcheckresult "INFO"  

    containerFullID=$(basename "$(cat /proc/1/cpuset)")
    printResult "Container Full ID ......." "$containerFullID" "Unknown"
    starttestjson "Container Full ID" "$containerFullID"
    logcheckresult "INFO" 
}

containerCapabilities() {
  printQuestion "Dangerous Capabilities .."
  if [ -x "$(command -v capsh)" ]; then
    if capsh --print| grep -q "$DANGEROUS_CAPABILITIES"; then
        caps=$(capsh --print |grep 'Current' | cut -d'=' -f 2 | cut -d' ' -f 2 | tr ',' '\n' | grep "$DANGEROUS_CAPABILITIES")
        printYes
        starttestjson "Dangerous Capabilities" "$caps"
        logcheckresult "FAIL"
        printStatus "$caps"
    else
        starttestjson "Dangerous Capabilities" "No Dangerous Capabilities Found"
        logcheckresult "PASS"
        printNo
    fi
  else
    printError "Unknown (capsh not installed)"
  fi
}

containerServices() {
  # SSHD

  printQuestion "SSHD Service ............"

  if ! [ -x "$(command -v ps)" ]; then
    printError "Unknown (ps not installed)"
    return
  fi

  (ps -aux 2>/dev/null || ps -a) | grep -v "grep" | grep -q "sshd"

  # shellcheck disable=SC2181
  if [ $? -eq 0 ]; then
    if [ -f "/etc/ssh/sshd_config" ]; then
      sshPort=$(grep "^Port" /etc/ssh/sshd_config || echo "Port 22" | cut -d' ' -f2)
      starttestjson "SSHD Service" "sshd_config File Found"
      logcheckresult "FAIL"

      printSuccess "Yes (port $sshPort)"
    else
      printSuccess "Yes"
      starttestjson "SSHD Service" "SSHD Service is Enabled"
      logcheckresult "FAIL"

    fi
  else
    printNo
    starttestjson "SSHD Service" "SSHD Service is Dissabled"
    logcheckresult "PASS"

  fi
}

containerPrivileges() {
  printQuestion "Privileged Mode ........."
  if [ -x "$(command -v fdisk)" ]; then
    if [ "$(fdisk -l 2>/dev/null | wc -l)" -gt 0 ]; then
      printYesEx
      printTip "$TIP_PRIVILEGED_MODE"
      starttestjson "Privileged Mode" "Enabled"
      logcheckresult "FAIL"
    else
      printNo
      starttestjson "Privileged Mode" "Dissabled"
      logcheckresult "PASS"      
    fi
  else
    printError "Unknown"
  fi
}

containerTools(){
  for CMD in ${CONTAINER_CMDS}; do
    tools="$tools $(command -v "${CMD}")"   
  done
  starttestjson "Container tools" "$tools"
  logcheckresult "INFO" 
  printResultLong "Container tools ........." "$(echo "$tools" | tr ' ' '\n'| grep -v '^$')" "None"
  endsectionjson
  ejson
}

userCheck
containerID
containerCapabilities
containerServices
containerPrivileges
containerTools

