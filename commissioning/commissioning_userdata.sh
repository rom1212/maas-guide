#!/bin/bash
#
# This script carries inside it multiple files.  When executed, it creates
# the files into a temporary directory and uses them to execute commands
# which gather data about the running machine or perform actions.
#

#### script setup ######
export TEMP_D=$(mktemp -d "${TMPDIR:-/tmp}/${0##*/}.XXXXXX")
export BIN_D="${TEMP_D}/bin"
export PATH="$BIN_D:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

mkdir -p "$BIN_D"

# Ensure that invocations of apt-get are not interactive by default,
# here and in all subprocesses.
export DEBIAN_FRONTEND=noninteractive

### some utility functions ####
aptget() {
    apt-get --assume-yes -q "$@" </dev/null
}

add_bin() {
    cat > "${BIN_D}/$1"
    chmod "${2:-755}" "${BIN_D}/$1"
}

fail() {
    [ -z "$CRED_CFG" ] || signal FAILED "$1"
    echo "FAILED: $1" 1>&2;
    exit 1
}

find_creds_cfg() {
    local config="" file="" found=""

    # If the config location is set in environment variable, trust it.
    [ -n "${COMMISSIONING_CREDENTIALS_URL}" ] &&
      _RET="${COMMISSIONING_CREDENTIALS_URL}" && return

    # Go looking for local files written by cloud-init.
    for file in /etc/cloud/cloud.cfg.d/*cmdline*.cfg; do
        [ -f "$file" ] && _RET="$file" && return
    done

    local opt="" cmdline=""
    if [ -f /proc/cmdline ] && read cmdline < /proc/cmdline; then
        # Search through /proc/cmdline arguments:
        # cloud-config-url trumps url=
        for opt in $cmdline; do
            case "$opt" in
                url=*)
                    found=${opt#url=};;
                cloud-config-url=*)
                    _RET="${opt#*=}"
                    return 0;;
            esac
        done
        [ -n "$found" ] && _RET="$found" && return 0
    fi
    return 1
}

# Do everything needed to be able to use maas_api_helper or any script which
# imports it.
prep_maas_api_helper() {
    local creds=""

    # Update apt cache and install libraries required by maas_api_helper.py
    aptget update
    aptget install python3-yaml python3-oauthlib

    find_creds_cfg || fail "Failed to find credential config"
    creds="$_RET"

    # Get remote credentials into a local file.
    case "$creds" in
        http://*|https://*)
            wget "$creds" -O "${TEMP_D}/my.creds" ||
              fail "failed to get credentials from $cred_cfg"
            creds="${TEMP_D}/my.creds"
            ;;
    esac

    # Use global name read by signal().
    export CRED_CFG="$creds"
}

# Invoke the "signal()" API call to report progress.
# Usage: signal <status> <message>
signal() {
    maas-signal "--config=${CRED_CFG}" "$@"
}


# This script is passed to cloud-init from MAAS during commissioning. This
# script contains multiple files inside it. When executed these files are
# extracted and run. This script detects power settings, runs commissioning
# scripts to gather data about the system, and runs testing scripts to validate
# the hardware is in a functioning state.

####  IPMI setup  ######
IPMI_CONFIG_D="${TEMP_D}/ipmi.d"
mkdir -p "$IPMI_CONFIG_D"
# If IPMI network settings have been configured statically, you can
# make them DHCP. If \'true\', the IPMI network source will be changed
# to DHCP.
IPMI_CHANGE_STATIC_TO_DHCP="false"

# In certain hardware, the parameters for the ipmi_si kernel module
# might need to be specified. If you wish to send parameters, uncomment
# the following line.
#IPMI_SI_PARAMS="type=kcs ports=0xca2"

add_ipmi_config() {
   cat > "${IPMI_CONFIG_D}/$1"
   chmod "${2:-644}" "${IPMI_CONFIG_D}/$1"
}

main() {
    prep_maas_api_helper

    # Install IPMI deps
    aptget install freeipmi-tools openipmi ipmitool sshpass

    # Load IPMI kernel modules
    modprobe ipmi_msghandler
    modprobe ipmi_devintf
    modprobe ipmi_si ${IPMI_SI_PARAMS}
    modprobe ipmi_ssif
    udevadm settle

    # Power settings.
    local pargs=""
    if $IPMI_CHANGE_STATIC_TO_DHCP; then
        pargs="--dhcp-if-static"
    fi
    power_type=$(maas-ipmi-autodetect-tool)
    if [ -z $power_type ]; then
        power_type=$(maas-wedge-autodetect --check) || power_type=""
    fi
    case "$power_type" in
        ipmi)
            power_settings=$(maas-ipmi-autodetect \\
              --configdir "$IPMI_CONFIG_D" ${pargs})
            ;;
        moonshot)
            power_settings=$(maas-moonshot-autodetect)
            ;;
        wedge)
            power_settings=$(maas-wedge-autodetect --get-credentials) || power_settings=""
            ;;
    esac
    if [ ! -z "$power_settings" ]; then
        signal \\
          "--power-type=${power_type}" "--power-parameters=${power_settings}" \\
          WORKING "Finished [maas-ipmi-autodetect]"
    fi

    maas-run-remote-scripts "--config=${CRED_CFG}" "${TEMP_D}"
}

### begin writing files ###

# Example config: enable BMC remote access (on some systems.)
#add_ipmi_config "02-global-config.ipmi" <<"END_IPMI_CONFIG"
#Section Lan_Channel
#\tVolatile_Access_Mode\t\t\tAlways_Available
#\tVolatile_Enable_User_Level_Auth\t\tYes
#\tVolatile_Channel_Privilege_Limit\tAdministrator
#\tNon_Volatile_Access_Mode\t\tAlways_Available
#\tNon_Volatile_Enable_User_Level_Auth\tYes
#\tNon_Volatile_Channel_Privilege_Limit\tAdministrator
#EndSection
#END_IPMI_CONFIG

add_bin "maas-ipmi-autodetect-tool" <<"END_MAAS_IPMI_AUTODETECT_TOOL"
#!/usr/bin/python3

import glob
import re
import subprocess


def detect_ipmi():
    # XXX: andreserl 2013-04-09 bug=1064527: Try to detect if node
    # is a Virtual Machine. If it is, do not try to detect IPMI.
    with open(\'/proc/cpuinfo\', \'r\') as cpuinfo:
        for line in cpuinfo:
            if line.startswith(\'model name\') and \'QEMU\' in line:
                return (False, None)

    (status, output) = subprocess.getstatusoutput(\'ipmi-locate\')
    show_re = re.compile(\'(IPMI\\ Version:) (\\d\\.\\d)\')
    res = show_re.search(output)
    if res is None:
        found = glob.glob("/dev/ipmi[0-9]")
        if len(found):
            return (True, "UNKNOWN: %s" % " ".join(found))
        return (False, "")

    # We\'ve detected IPMI, but it doesn\'t necessarily mean we can access
    # the BMC. Let\'s test if we can.
    cmd = \'bmc-config --checkout --key-pair=Lan_Conf:IP_Address_Source\'
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        return (False, "")

    return (True, res.group(2))


def is_host_moonshot():
    output = subprocess.check_output([\'ipmitool\', \'raw\', \'06\', \'01\'])
    # 14 is the code that identifies a machine as a moonshot
    if output.split()[0] == "14":
        return True
    return False


def main():
    # Check whether IPMI exists or not.
    (status, ipmi_version) = detect_ipmi()
    if not status:
        # if False, then failed to detect ipmi
        exit(1)

    if is_host_moonshot():
        print("moonshot")
    else:
        print("ipmi")


if __name__ == \'__main__\':
    main()

END_MAAS_IPMI_AUTODETECT_TOOL

add_bin "maas-ipmi-autodetect" <<"END_MAAS_IPMI_AUTODETECT"
#!/usr/bin/python3
#
# maas-ipmi-autodetect - autodetect and autoconfigure IPMI.
#
# Copyright (C) 2013-2016 Canonical
#
# Authors:
#    Andres Rodriguez <andres.rodriguez@canonical.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from collections import OrderedDict
import json
import os
import platform
import random
import re
import string
import subprocess
import time


class IPMIError(Exception):
    """An error related to IPMI."""


def run_command(command_args):
    """Run a command. Return output if successful or raise exception if not."""
    output = subprocess.check_output(command_args, stderr=subprocess.STDOUT)
    return output.decode(\'utf-8\')


def bmc_get(key):
    """Fetch the output of a key via bmc-config checkout."""
    command = (\'bmc-config\', \'--checkout\', \'--key-pair=%s\' % key)
    output = run_command(command)
    return output


def bmc_set(key, value):
    """Set the value of a key via bmc-config commit."""
    command = (\'bmc-config\', \'--commit\', \'--key-pair=%s=%s\' % (key, value))
    run_command(command)


def format_user_key(user_number, parameter):
    """Format a user key string."""
    return \'%s:%s\' % (user_number, parameter)


def bmc_user_get(user_number, parameter):
    """Get a user parameter via bmc-config commit."""
    key = format_user_key(user_number, parameter)
    raw = bmc_get(key)
    pattern = r\'^\\s*%s(?:[ \\t])+([^#\\s]+[^\
]*)$\' % (re.escape(parameter))
    match = re.search(pattern, raw, re.MULTILINE)
    if match is None:
        return None
    return match.group(1)


def bmc_user_set(user_number, parameter, value):
    """Set a user parameter via bmc-config commit."""
    key = format_user_key(user_number, parameter)
    bmc_set(key, value)


def bmc_list_sections():
    """Retrieve the names of config sections from the BMC."""
    command = (\'bmc-config\', \'-L\')
    output = run_command(command)
    return output


def list_user_numbers():
    """List the user numbers on the BMC."""
    output = bmc_list_sections()
    pattern = r\'^(User\\d+)$\'
    users = re.findall(pattern, output, re.MULTILINE)

    return users


def pick_user_number_from_list(search_username, user_numbers):
    """Pick the best user number for a user from a list of user numbers.

    If any any existing user\'s username matches the search username, pick
    that user.

    Otherwise, pick the first user that has no username set.

    If no users match those criteria, raise an IPMIError.
    """
    first_unused = None

    for user_number in user_numbers:
        # The IPMI spec reserves User1 as anonymous.
        if user_number == \'User1\':
            continue

        username = bmc_user_get(user_number, \'Username\')

        if username == search_username:
            return user_number

        # Usually a BMC won\'t include a Username value if the user is unused.
        # Some HP BMCs use "(Empty User)" to indicate a user in unused.
        if username in [None, \'(Empty User)\'] and first_unused is None:
            first_unused = user_number

    return first_unused


def pick_user_number(search_username):
    """Pick the best user number for a username."""
    user_numbers = list_user_numbers()
    user_number = pick_user_number_from_list(search_username, user_numbers)

    if not user_number:
        raise IPMIError(\'No IPMI user slots available.\')

    return user_number


def is_ipmi_dhcp():
    output = bmc_get(\'Lan_Conf:IP_Address_Source\')
    show_re = re.compile(\'IP_Address_Source\\s+Use_DHCP\')
    return show_re.search(output) is not None


def set_ipmi_network_source(source):
    bmc_set(\'Lan_Conf:IP_Address_Source\', source)


def _bmc_get_ipmi_addresses(address_type):
    try:
        return bmc_get(address_type)
    except subprocess.CalledProcessError:
        return ""


def get_ipmi_ip_address():
    show_re = re.compile(
        \'((?:[0-9]{1,3}\\.){3}[0-9]{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+)\')
    for address_type in [
            \'Lan_Conf:IP_Address\',
            \'Lan6_Conf:IPv6_Static_Addresses\',
            \'Lan6_Conf:IPv6_Dynamic_Addresses\']:
        output = _bmc_get_ipmi_addresses(address_type)
        # Loop through the addreses by preference: IPv4, static IPv6, dynamic
        # IPv6.  Return the first valid, non-link-local address we find.
        # While we could conceivably allow link-local addresses, we would need
        # to devine which of our interfaces is the correct link, and then we
        # would need support for link-local addresses in freeipmi-tools.
        res = show_re.findall(output)
        for ip in res:
            if ip.lower().startswith(\'fe80::\') or ip == \'0.0.0.0\':
                time.sleep(2)
                continue
            if address_type.startswith(\'Lan6_\'):
                return \'[%s]\' % ip
            return ip
    # No valid IP address was found.
    return None


def verify_ipmi_user_settings(user_number, user_settings):
    """Verify user settings were applied correctly."""

    bad_values = {}

    for key, expected_value in user_settings.items():
        # Password isn\'t included in checkout. Plus,
        # some older BMCs may not support Enable_User.
        if key not in [\'Enable_User\', \'Password\']:
            value = bmc_user_get(user_number, key)
            if value != expected_value:
                bad_values[key] = value

    if len(bad_values) == 0:
        return

    errors_string = \' \'.join([
        "for \'%s\', expected \'%s\', actual \'%s\';" % (
            key, user_settings[key], actual_value)
        for key, actual_value in bad_values.items()
        ]).rstrip(\';\')
    message = "IPMI user setting verification failures: %s." % (errors_string)
    raise IPMIError(message)


def apply_ipmi_user_settings(user_settings):
    """Commit and verify IPMI user settings."""
    username = user_settings[\'Username\']
    ipmi_user_number = pick_user_number(username)

    for key, value in user_settings.items():
        bmc_user_set(ipmi_user_number, key, value)

    verify_ipmi_user_settings(ipmi_user_number, user_settings)


def make_ipmi_user_settings(username, password):
    """Factory for IPMI user settings."""
    # Some BMCs care about the order these settings are applied in.
    #
    # - Dell Poweredge R420 Systems require the username and password to
    # be set prior to the user being enabled.
    #
    # - Supermicro systems require the LAN Privilege Limit to be set
    # prior to enabling LAN IPMI msgs for the user.
    user_settings = OrderedDict((
        (\'Username\', username),
        (\'Password\', password),
        (\'Enable_User\', \'Yes\'),
        (\'Lan_Privilege_Limit\', \'Administrator\'),
        (\'Lan_Enable_IPMI_Msgs\', \'Yes\'),
    ))
    return user_settings


def configure_ipmi_user(username, password):
    """Create or configure an IPMI user for remote use."""
    user_settings = make_ipmi_user_settings(username, password)
    apply_ipmi_user_settings(user_settings)


def commit_ipmi_settings(config):
    run_command((\'bmc-config\', \'--commit\', \'--filename\', config))


def get_maas_power_settings(user, password, ipaddress, version):
    return "%s,%s,%s,%s" % (user, password, ipaddress, version)


def get_maas_power_settings_json(user, password, ipaddress, version):
    power_params = {
        "power_address": ipaddress,
        "power_pass": password,
        "power_user": user,
        "power_driver": version,
    }
    return json.dumps(power_params)


def generate_random_password(min_length=8, max_length=15):
    length = random.randint(min_length, max_length)
    letters = string.ascii_letters + string.digits
    return \'\'.join([random.choice(letters) for _ in range(length)])


def bmc_supports_lan2_0():
    """Detect if BMC supports LAN 2.0."""
    output = run_command((\'ipmi-locate\'))
    if \'IPMI Version: 2.0\' in output or platform.machine() == \'ppc64le\':
        return True
    return False


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=\'send config file to modify IPMI settings with\')
    parser.add_argument(
        "--configdir", metavar="folder", help="specify config file directory",
        default=None)
    parser.add_argument(
        "--dhcp-if-static", action="store_true", dest="dhcp",
        help="set network source to DHCP if Static", default=False)
    parser.add_argument(
        "--commission-creds", action="store_true", dest="commission_creds",
        help="Create IPMI temporary credentials", default=False)

    args = parser.parse_args()

    # Check whether IPMI is being set to DHCP. If it is not, and
    # \'--dhcp-if-static\' has been passed,  Set it to IPMI to DHCP.
    if not is_ipmi_dhcp() and args.dhcp:
        set_ipmi_network_source("Use_DHCP")
        # allow IPMI 120 seconds to obtain an IP address
        time.sleep(120)
    # create user/pass
    IPMI_MAAS_USER = "maas"
    IPMI_MAAS_PASSWORD = generate_random_password()

    configure_ipmi_user(IPMI_MAAS_USER, IPMI_MAAS_PASSWORD)

    # Commit other IPMI settings
    if args.configdir:
        for file in os.listdir(args.configdir):
            commit_ipmi_settings(os.path.join(args.configdir, file))

    # get the IP address
    IPMI_IP_ADDRESS = get_ipmi_ip_address()
    if IPMI_IP_ADDRESS is None:
        # if IPMI_IP_ADDRESS not set (or reserved), wait 60 seconds and retry.
        set_ipmi_network_source("Static")
        time.sleep(2)
        set_ipmi_network_source("Use_DHCP")
        time.sleep(60)
        IPMI_IP_ADDRESS = get_ipmi_ip_address()

    if IPMI_IP_ADDRESS is None:
        # Exit (to not set power params in MAAS) if no IPMI_IP_ADDRESS
        # has been detected
        exit(1)

    if bmc_supports_lan2_0():
        IPMI_VERSION = "LAN_2_0"
    else:
        IPMI_VERSION = "LAN"
    if args.commission_creds:
        print(get_maas_power_settings_json(
            IPMI_MAAS_USER, IPMI_MAAS_PASSWORD, IPMI_IP_ADDRESS, IPMI_VERSION))
    else:
        print(get_maas_power_settings(
            IPMI_MAAS_USER, IPMI_MAAS_PASSWORD, IPMI_IP_ADDRESS, IPMI_VERSION))

if __name__ == \'__main__\':
    main()

END_MAAS_IPMI_AUTODETECT

add_bin "maas-moonshot-autodetect" <<"END_MAAS_MOONSHOT_AUTODETECT"
#!/usr/bin/python3

import argparse
import json
import re
import subprocess


IPMI_MAAS_USER = \'Administrator\'
IPMI_MAAS_PASSWORD = \'password\'


def get_local_address():
    output = subprocess.getoutput(\'ipmitool raw 0x2c 1 0\')
    return "0x%s" % output.split()[2]


def get_cartridge_address(local_address):
    # obtain address of Cartridge Controller (parent of the system node):
    output = subprocess.getoutput(
        \'ipmitool -t 0x20 -b 0 -m %s raw 0x2c 1 0\' % local_address)
    return "0x%s" % output.split()[2]


def get_channel_number(address, output):
    # channel number (routing to this system node)
    show = re.compile(
        r\'Device Slave Address\\s+:\\s+%sh(.*?)Channel Number\\s+:\\s+\\d+\'
        % address.replace(\'0x\', \'\').upper(),
        re.DOTALL)
    res = show.search(output)
    return res.group(0).split()[-1]


def get_ipmi_ip_address(local_address):
    output = subprocess.getoutput(
        \'ipmitool -B 0 -T 0x20 -b 0 -t 0x20 -m %s lan print 2\' % local_address)
    show_re = re.compile(
        \'IP Address\\s+:\\s+\'
        \'(?P<addr>(?:[0-9]{1,3}\\.){3}[0-9]{1,3}|[0-9a-fA-F]*:[0-9a-fA-F:.]+)\')
    res = show_re.search(output)
    if res is None:
        return None
    return res.groupdict().get(\'addr\', None)


def get_maas_power_settings(user, password, ipaddress, hwaddress):
    return "%s,%s,%s,%s" % (user, password, ipaddress, hwaddress)


def get_maas_power_settings_json(user, password, ipaddress, hwaddress):
    power_params = {
        "power_address": ipaddress,
        "power_pass": password,
        "power_user": user,
        "power_hwaddress": hwaddress,
    }
    return json.dumps(power_params)


def main():
    parser = argparse.ArgumentParser(
        description=\'send config file to modify IPMI settings with\')
    parser.add_argument(
        "--commission-creds", action="store_true", dest="commission_creds",
        help="Create IPMI temporary credentials", default=False)

    args = parser.parse_args()

    local_address = get_local_address()
    node_address = get_cartridge_address(local_address)

    # Obtaining channel numbers:
    output = subprocess.getoutput(
        \'ipmitool -b 0 -t 0x20 -m %s sdr list mcloc -v\' % local_address)

    local_chan = get_channel_number(local_address, output)
    cartridge_chan = get_channel_number(node_address, output)

    # ipmitool -I lanplus -H 10.16.1.11 -U Administrator -P password -B 0
    #     -T 0x88 -b 7 -t 0x72 -m 0x20 power status
    IPMI_HW_ADDRESS = "-B %s -T %s -b %s -t %s -m 0x20" % (
        cartridge_chan,
        node_address,
        local_chan,
        local_address,
        )

    IPMI_IP_ADDRESS = get_ipmi_ip_address(local_address)

    if args.commission_creds:
        print(get_maas_power_settings_json(
            IPMI_MAAS_USER, IPMI_MAAS_PASSWORD, IPMI_IP_ADDRESS,
            IPMI_HW_ADDRESS))
    else:
        print(get_maas_power_settings(
            IPMI_MAAS_USER, IPMI_MAAS_PASSWORD, IPMI_IP_ADDRESS,
            IPMI_HW_ADDRESS))


if __name__ == \'__main__\':
    main()

END_MAAS_MOONSHOT_AUTODETECT

add_bin "maas-wedge-autodetect" <<"END_MAAS_WEDGE_AUTODETECT"
#!/bin/bash

# This script will detect if there is a Wedge power driver
# and tell you the ip address of the Wedge BMC

# The LLA of OpenBMC and default username password
SWLLA="fe80::ff:fe00:2" # needed to find the DEV for internal BMC network
BMCLLA="fe80::1" # The BMC\'s LLA
SSHUSER="root" # Default username
SSHPASS="0penBmc" # Default password

Error(){
        echo "ERROR: $1"
        exit 1
}

Usage(){
        cat <<EOF
Usage: ${0##*/} [ options ]

   node enlistment into the MAAS server

   options:
      -c | --check            check if this is a wedge
      -g | --get-credentials  obtain the credentials for the wedge
      -e | --get-enlist-creds obtain the credentials for the wedge for enlistment
      -h | --help             display usage

   Example:
    - ${0##*/} --check

EOF
}

bad_Usage() { Usage 1>&2; [ $# -eq 0 ] || Error "$@"; }

short_opts="hcge"
long_opts="help,check,get-credentials,get-enlist-creds"
getopt_out=$(getopt --name "${0##*/}" \\
        --options "${short_opts}" --long "${long_opts}" -- "$@") &&
        eval set -- "${getopt_out}" ||
        bad_Usage

if [ -z "$(which sshpass)" ]
then
        Error "please apt-get install sshpass"
fi

# Obtain the \'net\' device connected to the BMC.
DEV="$(ip -o a show to "${SWLLA}" | awk \'// { print $2 }\')" || Error "Unable to detect the \'wedge\' net device connected to the BMC."

# Get dmidecode information to find out if this is a switch
SM="$(dmidecode -s system-manufacturer)"
SPN="$(dmidecode -s system-product-name)"
BPN="$(dmidecode -s baseboard-product-name)"

detect_known_switch(){
    # This is based of https://github.com/lool/sonic-snap/blob/master/common/id-switch
    # try System Information > Manufacturer first
    case "$SM" in
        "Intel")
            case "$SPN" in
                "EPGSVR")
                    manufacturer=accton
                    ;;
                *)
                    Error "Unable to detect switch"
                    ;;
            esac
            ;;
        "Joytech")
            case "$SPN" in
                "Wedge-AC-F 20-001329")
                    manufacturer=accton
                    ;;
                *)
                    Error "Unable to detect switch"
                    ;;
            esac
            ;;
        "To be filled by O.E.M.")
            case "$BPN" in
                "PCOM-B632VG-ECC-FB-ACCTON-D")
                    manufacturer=accton
                    ;;
                *)
                    Error "Unable to detect switch"
                    ;;
            esac
            ;;
        *)
            Error "Unable to detect switch"
            ;;
    esac
    # next look at System Information > Product Name
    case "$manufacturer-$SPN" in
        "accton-EPGSVR")
            model=wedge40
            ;;
        "accton-Wedge-AC-F 20-001329")
            model=wedge40
            ;;
        "accton-To be filled by O.E.M.")
            case "$BPN" in
                "PCOM-B632VG-ECC-FB-ACCTON-D")
                    model=wedge100
                    ;;
                *)
                    Error "Unable to detect switch model"
                    ;;
            esac
            ;;
        *)
            Error "Unable to detect switch model"
            ;;
    esac
    echo "$model"
}

wedge_autodetect(){
    # First detect this is a known switch
    model=$(detect_known_switch) || Error "Unable to detect switch model"
    # Second, lets verify if this is a known endpoint
    # First try to hit the API. This would work on Wedge 100.
    if curl -s \'http://[\'"${BMCLLA}"%"${DEV}"\']:8080/api\' | grep -qs \'Wedge RESTful API Entry\'; then
        echo "wedge"
    # If the above failed, try to hit the SSH. This would work on Wedge 40
    elif [ ! -z "$(sshpass -p "${SSHPASS}" ssh -o StrictHostKeyChecking=no "${SSHUSER}"@"${BMCLLA}"%"${DEV}" \'ip -o -4 addr show | awk "{ if(NR>1)print \\$4 "} | cut -d/ -f1\')" ]; then
        echo "wedge"
    else
        Error "Unable to detect the BMC for a "$model" switch"
    fi
}

wedge_discover(){
    # Obtain the IP address of the BMC by logging into it using the default values (we cannot auto-discover
    # non-default values).
    IP="$(sshpass -p "${SSHPASS}" ssh -o StrictHostKeyChecking=no "${SSHUSER}"@"${BMCLLA}"%"${DEV}" \\
        \'ip -o -4 addr show | awk "{ if(NR>1)print \\$4 "} | cut -d/ -f1\')" || Error "Unable to obtain the \'wedge\' BMC IP address."
    # If we were able to optain the IP address, then we can simply return the credentials.
    echo "$SSHUSER,$SSHPASS,$IP,"
}


wedge_discover_json(){
    # Obtain the IP address of the BMC by logging into it using the default values (we cannot auto-discover
    # non-default values).
    IP="$(sshpass -p "${SSHPASS}" ssh -o StrictHostKeyChecking=no "${SSHUSER}"@"${BMCLLA}"%"${DEV}" \\
        \'ip -o -4 addr show | awk "{ if(NR>1)print \\$4 "} | cut -d/ -f1\')" || Error "Unable to obtain the \'wedge\' BMC IP address."
    # If we were able to optain the IP address, then we can simply return the credentials.
    echo "{\\"power_user\\":\\""$SSHUSER"\\", \\"power_pass\\":\\""$SSHPASS"\\",\\"power_address\\":\\""$IP"\\"}"
}

while [ $# -ne 0 ]; do
        cur="${1}"; next="${2}";
        case "$cur" in
                -h|--help) Usage; exit 0;;
                -c|--check) wedge_autodetect; exit 0;;
                -g|--get-credentials) wedge_discover; exit 0;;
                -e|--get-enlist-creds) wedge_discover_json; exit 0;;
                --) shift; break;;
        esac
        shift;
done
Usage


END_MAAS_WEDGE_AUTODETECT

add_bin "maas_api_helper.py" <<"END_MAAS_API_HELPER"
# Copyright 2016-2017 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

"""Help functioners to send commissioning data to MAAS region."""

__all__ = [
    \'geturl\',
    \'read_config\',
    \'signal\',
    ]

from collections import OrderedDict
from datetime import (
    datetime,
    timedelta,
)
from email.utils import parsedate
import json
import mimetypes
import os
import random
import selectors
import socket
import string
from subprocess import TimeoutExpired
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import oauthlib.oauth1 as oauth
import yaml

# Current MAAS metadata API version.
MD_VERSION = \'2012-03-01\'


# See fcntl(2), re. F_SETPIPE_SZ. By requesting this many bytes from a pipe on
# each read we can be sure that we are always draining its buffer completely.
with open("/proc/sys/fs/pipe-max-size") as _pms:
    PIPE_MAX_SIZE = int(_pms.read())


def oauth_headers(url, consumer_key, token_key, token_secret, consumer_secret,
                  clockskew=0):
    """Build OAuth headers using given credentials."""
    timestamp = int(time.time()) + clockskew
    client = oauth.Client(
        consumer_key,
        client_secret=consumer_secret,
        resource_owner_key=token_key,
        resource_owner_secret=token_secret,
        signature_method=oauth.SIGNATURE_PLAINTEXT,
        timestamp=str(timestamp))
    uri, signed_headers, body = client.sign(url)
    return signed_headers


def authenticate_headers(url, headers, creds, clockskew=0):
    """Update and sign a dict of request headers."""
    if creds.get(\'consumer_key\', None) is not None:
        headers.update(oauth_headers(
            url,
            consumer_key=creds[\'consumer_key\'],
            token_key=creds[\'token_key\'],
            token_secret=creds[\'token_secret\'],
            consumer_secret=creds[\'consumer_secret\'],
            clockskew=clockskew))


def warn(msg):
    sys.stderr.write(msg + "\
")


def geturl(url, creds, headers=None, data=None):
    # Takes a dict of creds to be passed through to oauth_headers,
    #   so it should have consumer_key, token_key, ...
    if headers is None:
        headers = {}
    else:
        headers = dict(headers)

    clockskew = 0

    error = Exception("Unexpected Error")
    for naptime in (1, 1, 2, 4, 8, 16, 32):
        authenticate_headers(url, headers, creds, clockskew)
        try:
            req = urllib.request.Request(url=url, data=data, headers=headers)
            return urllib.request.urlopen(req).read()
        except urllib.error.HTTPError as exc:
            error = exc
            if \'date\' not in exc.headers:
                warn("date field not in %d headers" % exc.code)
                pass
            elif exc.code in (401, 403):
                date = exc.headers[\'date\']
                try:
                    ret_time = time.mktime(parsedate(date))
                    clockskew = int(ret_time - time.time())
                    warn("updated clock skew to %d" % clockskew)
                except:
                    warn("failed to convert date \'%s\'" % date)
        except Exception as exc:
            error = exc

        warn("request to %s failed. sleeping %d.: %s" % (url, naptime, error))
        time.sleep(naptime)

    raise error


def _encode_field(field_name, data, boundary):
    assert isinstance(field_name, bytes)
    assert isinstance(data, bytes)
    assert isinstance(boundary, bytes)
    return (
        b\'--\' + boundary,
        b\'Content-Disposition: form-data; name=\\"\' + field_name + b\'\\"\',
        b\'\', data,
        )


def _encode_file(name, file, boundary):
    assert isinstance(name, str)
    assert isinstance(boundary, bytes)
    byte_name = name.encode("utf-8")
    return (
        b\'--\' + boundary,
        (
            b\'Content-Disposition: form-data; name=\\"\' + byte_name + b\'\\"; \' +
            b\'filename=\\"\' + byte_name + b\'\\"\'
        ),
        b\'Content-Type: \' + _get_content_type(name).encode("utf-8"),
        b\'\',
        file if isinstance(file, bytes) else file.read(),
        )


def _random_string(length):
    return b\'\'.join(
        random.choice(string.ascii_letters).encode("ascii")
        for ii in range(length + 1)
    )


def _get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or \'application/octet-stream\'


def encode_multipart_data(data, files):
    """Create a MIME multipart payload from L{data} and L{files}.

    @param data: A mapping of names (ASCII strings) to data (byte string).
    @param files: A mapping of names (ASCII strings) to file objects ready to
        be read.
    @return: A 2-tuple of C{(body, headers)}, where C{body} is a a byte string
        and C{headers} is a dict of headers to add to the enclosing request in
        which this payload will travel.
    """
    boundary = _random_string(30)

    lines = []
    for name in data:
        lines.extend(_encode_field(name, data[name], boundary))
    for name in files:
        lines.extend(_encode_file(name, files[name], boundary))
    lines.extend((b\'--\' + boundary + b\'--\', b\'\'))
    body = b\'\\r\
\'.join(lines)

    headers = {
        \'Content-Type\': (
            \'multipart/form-data; boundary=\' + boundary.decode("ascii")),
        \'Content-Length\': str(len(body)),
    }

    return body, headers


def read_config(url, creds):
    """Read cloud-init config from given `url` into `creds` dict.

    Updates any keys in `creds` that are None with their corresponding
    values in the config.

    Important keys include `metadata_url`, and the actual OAuth
    credentials.
    """
    if url.startswith("http://") or url.startswith("https://"):
        cfg_str = urllib.request.urlopen(urllib.request.Request(url=url))
    else:
        if url.startswith("file://"):
            url = url[7:]
        cfg_str = open(url, "r").read()

    cfg = yaml.safe_load(cfg_str)

    # Support reading cloud-init config for MAAS datasource.
    if \'datasource\' in cfg:
        cfg = cfg[\'datasource\'][\'MAAS\']

    for key in creds.keys():
        if key in cfg and creds[key] is None:
            creds[key] = cfg[key]


class SignalException(Exception):

    def __init__(self, error):
        self.error = error

    def __str__(self):
        return self.error


def signal(
        url, creds, status, error=None, script_result_id=None,
        files: dict=None, exit_status=None, script_version_id=None,
        power_type=None, power_params=None):
    """Send a node signal to a given maas_url."""
    params = {
        b\'op\': b\'signal\',
        b\'status\': status.encode(\'utf-8\'),
    }

    if error is not None:
        params[b\'error\'] = error.encode(\'utf-8\')

    if script_result_id is not None:
        params[b\'script_result_id\'] = str(script_result_id).encode(\'utf-8\')

    if exit_status is not None:
        params[b\'exit_status\'] = str(exit_status).encode(\'utf-8\')

    if script_version_id is not None:
        params[b\'script_version_id\'] = str(script_version_id).encode(\'utf-8\')

    if None not in (power_type, power_params):
        params[b\'power_type\'] = power_type.encode(\'utf-8\')
        user, power_pass, power_address, driver = power_params.split(",")
        # OrderedDict is used to make testing easier.
        power_params = OrderedDict([
            (\'power_user\', user),
            (\'power_pass\', power_pass),
            (\'power_address\', power_address),
        ])
        if power_type == \'moonshot\':
            power_params[\'power_hwaddress\'] = driver
        else:
            power_params[\'power_driver\'] = driver
        params[b\'power_parameters\'] = json.dumps(power_params).encode()

    data, headers = encode_multipart_data(
        params, ({} if files is None else files))

    try:
        payload = geturl(url, creds=creds, headers=headers, data=data)
        if payload != b\'OK\':
            raise SignalException(
                "Unexpected result sending region commissioning data: %s" % (
                    payload))
    except urllib.error.HTTPError as exc:
        raise SignalException("HTTP error [%s]" % exc.code)
    except urllib.error.URLError as exc:
        raise SignalException("URL error [%s]" % exc.reason)
    except socket.timeout as exc:
        raise SignalException("Socket timeout [%s]" % exc)
    except TypeError as exc:
        raise SignalException(str(exc))
    except Exception as exc:
        raise SignalException("Unexpected error [%s]" % exc)


def capture_script_output(
        proc, combined_path, stdout_path, stderr_path, timeout_seconds=None):
    """Capture stdout and stderr from `proc`.

    Standard output is written to a file named by `stdout_path`, and standard
    error is written to a file named by `stderr_path`. Both are also written
    to a file named by `combined_path`.

    If the given subprocess forks additional processes, and these write to the
    same stdout and stderr, their output will be captured only as long as
    `proc` is running.

    Optionally a timeout can be given in seconds. This time is padded by 60
    seconds to allow for script cleanup. If the script runs past the timeout
    the process is killed and an exception is raised. Forked processes are not
    subject to the timeout.

    :return: The exit code of `proc`.
    """
    if timeout_seconds in (None, 0):
        timeout = None
    else:
        # Pad the timeout by 60 seconds to allow for cleanup.
        timeout = datetime.now() + timedelta(seconds=(timeout_seconds + 60))

    # Create the file and then open it in read write mode for terminal
    # emulation.
    for path in (stdout_path, stderr_path, combined_path):
        open(path, \'w\').close()
    with open(stdout_path, \'r+b\') as out, open(stderr_path, \'r+b\') as err:
        with open(combined_path, \'r+b\') as combined:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, out)
                selector.register(proc.stderr, selectors.EVENT_READ, err)
                while selector.get_map() and proc.poll() is None:
                    # Select with a short timeout so that we don\'t tight loop.
                    _select_script_output(selector, combined, 0.1)
                    if timeout is not None and datetime.now() > timeout:
                        break
                else:
                    # Process has finished or has closed stdout and stderr.
                    # Process anything still sitting in the latter\'s buffers.
                    _select_script_output(selector, combined, 0.0)

    now = datetime.now()
    # Wait for the process to finish.
    if timeout is None:
        # No timeout just wait until the process finishes.
        return proc.wait()
    elif now >= timeout:
        # Loop above detected time out execeed, kill the process.
        proc.kill()
        raise TimeoutExpired(proc.args, timeout_seconds)
    else:
        # stdout and stderr have been closed but the timeout has not been
        # exceeded. Run with the remaining amount of time.
        try:
            return proc.wait(timeout=(timeout - now).seconds)
        except TimeoutExpired:
            # Make sure the process was killed
            proc.kill()
            raise


def _select_script_output(selector, combined, timeout):
    """Helper for `capture_script_output`."""
    for key, event in selector.select(timeout):
        if event & selectors.EVENT_READ:
            # Read from the _raw_ file. Ordinarily Python blocks until a
            # read(n) returns n bytes or the stream reaches end-of-file,
            # but here we only want to get what\'s there without blocking.
            chunk = key.fileobj.raw.read(PIPE_MAX_SIZE)
            if len(chunk) == 0:  # EOF
                selector.unregister(key.fileobj)
            else:
                # The list comprehension is needed to get byte objects instead
                # of their numeric value.
                for i in [chunk[i:i + 1] for i in range(len(chunk))]:
                    for f in [key.data, combined]:
                        # Some applications don\'t properly detect that they are
                        # not being run in a terminal and refresh output for
                        # progress bars, counters, and spinners. These
                        # characters quickly add up making the log difficult to
                        # read. When writing output from an application emulate
                        # a terminal so readable data is captured.
                        if i == b\'\\b\':
                            # Backspace - Go back one space, if we can.
                            if f.tell() != 0:
                                f.seek(-1, os.SEEK_CUR)
                        elif i == b\'\\r\':
                            # Carriage return - Seek to the beginning of the
                            # line, as indicated by a line feed, or file.
                            while f.tell() != 0:
                                f.seek(-1, os.SEEK_CUR)
                                if f.read(1) == b\'\
\':
                                    # Check if line feed was found.
                                    break
                                else:
                                    # The read advances the file position by
                                    # one so seek back again.
                                    f.seek(-1, os.SEEK_CUR)
                        elif i == b\'\
\':
                            # Line feed - Some applications do a carriage
                            # return and then a line feed. The data on the line
                            # should be saved, not overwritten.
                            f.seek(0, os.SEEK_END)
                            f.write(i)
                        else:
                            f.write(i)

END_MAAS_API_HELPER

add_bin "maas-signal" <<"END_MAAS_SIGNAL"
#!/usr/bin/env python3

import os
import sys

from maas_api_helper import (
    MD_VERSION,
    read_config,
    signal,
    SignalException,
)


VALID_STATUS = ("OK", "FAILED", "WORKING", "TESTING")
POWER_TYPES = ("ipmi", "virsh", "manual", "moonshot", "wedge")


def fail(msg):
    sys.stderr.write("FAIL: %s" % msg)
    sys.exit(1)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=\'Send signal operation and optionally post files to MAAS\')
    parser.add_argument(
        "--config", metavar="file", help="Specify config file", default=None)
    parser.add_argument(
        "--ckey", metavar="key", help="The consumer key to auth with",
        default=None)
    parser.add_argument(
        "--tkey", metavar="key", help="The token key to auth with",
        default=None)
    parser.add_argument(
        "--csec", metavar="secret", help="The consumer secret (likely \'\')",
        default="")
    parser.add_argument(
        "--tsec", metavar="secret", help="The token secret to auth with",
        default=None)
    parser.add_argument(
        "--apiver", metavar="version",
        help="The apiver to use (\\"\\" can be used)", default=MD_VERSION)
    parser.add_argument(
        "--url", metavar="url", help="The data source to query", default=None)
    parser.add_argument(
        "--script-result-id", metavar="script_result_id", type=int,
        dest=\'script_result_id\',
        help="The ScriptResult database id this signal is about.")
    parser.add_argument(
        "--file", dest=\'files\', help="File to post", action=\'append\',
        default=[])
    parser.add_argument(
        "--exit-status", metavar="exit_status", type=int, dest=\'exit_status\',
        help="The exit return code of the script this signal is about.")
    parser.add_argument(
        "--script-version-id", metavar="script_version_id", type=int,
        dest=\'script_version_id\',
        help="The Script VersionTextFile database id this signal is about.")
    parser.add_argument(
        "--power-type", dest=\'power_type\', help="Power type.",
        choices=POWER_TYPES, default=None)
    parser.add_argument(
        "--power-parameters", dest=\'power_params\', help="Power parameters.",
        default=None)

    parser.add_argument(
        "status", help="Status", choices=VALID_STATUS)
    parser.add_argument(
        "error", help="Optional error message", nargs=\'?\', default=None)

    args = parser.parse_args()

    creds = {
        \'consumer_key\': args.ckey,
        \'token_key\': args.tkey,
        \'token_secret\': args.tsec,
        \'consumer_secret\': args.csec,
        \'metadata_url\': args.url,
        }

    if args.config:
        read_config(args.config, creds)

    url = creds.get(\'metadata_url\')
    if url is None:
        fail("URL must be provided either in --url or in config\
")
    url = "%s/%s/" % (url, args.apiver)

    files = {}
    for fpath in args.files:
        files[os.path.basename(fpath)] = open(fpath, \'rb\')

    try:
        signal(
            url, creds, args.status, args.error, args.script_result_id,
            files, args.exit_status, args.script_version_id, args.power_type,
            args.power_params)
    except SignalException as e:
        fail(e.error)


if __name__ == \'__main__\':
    main()

END_MAAS_SIGNAL

add_bin "maas-run-remote-scripts" <<"END_MAAS_RUN_REMOTE_SCRIPTS"
#!/usr/bin/env python3
#
# maas-run-remote-scripts - Download a set of scripts from the MAAS region,
#                           execute them, and send the results back.
#
# Author: Lee Trager <lee.trager@canonical.com>
#
# Copyright (C) 2017 Canonical
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import copy
from datetime import timedelta
from io import BytesIO
import json
import os
from subprocess import (
    PIPE,
    Popen,
    TimeoutExpired,
)
import sys
import tarfile
from threading import (
    Event,
    Thread,
)
import time


try:
    from maas_api_helper import (
        geturl,
        MD_VERSION,
        read_config,
        signal,
        SignalException,
        capture_script_output,
    )
except ImportError:
    # For running unit tests.
    from snippets.maas_api_helper import (
        geturl,
        MD_VERSION,
        read_config,
        signal,
        SignalException,
        capture_script_output,
    )


def fail(msg):
    sys.stderr.write("FAIL: %s" % msg)
    sys.exit(1)


def signal_wrapper(*args, **kwargs):
    """Wrapper to output any SignalExceptions to STDERR."""
    try:
        signal(*args, **kwargs)
    except SignalException as e:
        fail(e.error)


def download_and_extract_tar(url, creds, scripts_dir):
    """Download and extract a tar from the given URL.

    The URL may contain a compressed or uncompressed tar.
    """
    binary = BytesIO(geturl(url, creds))

    with tarfile.open(mode=\'r|*\', fileobj=binary) as tar:
        tar.extractall(scripts_dir)


def run_scripts(url, creds, scripts_dir, out_dir, scripts):
    """Run and report results for the given scripts."""
    total_scripts = len(scripts)
    fail_count = 0
    base_args = {
        \'url\': url,
        \'creds\': creds,
        \'status\': \'WORKING\',
    }
    for i, script in enumerate(scripts):
        i += 1
        args = copy.deepcopy(base_args)
        args[\'script_result_id\'] = script[\'script_result_id\']
        script_version_id = script.get(\'script_version_id\')
        if script_version_id is not None:
            args[\'script_version_id\'] = script_version_id
        timeout_seconds = script.get(\'timeout_seconds\')

        signal_wrapper(
            error=\'Starting %s [%d/%d]\' % (
                script[\'name\'], i, len(scripts)),
            **args)

        script_path = os.path.join(scripts_dir, script[\'path\'])
        combined_path = os.path.join(out_dir, script[\'name\'])
        stdout_name = \'%s.out\' % script[\'name\']
        stdout_path = os.path.join(out_dir, stdout_name)
        stderr_name = \'%s.err\' % script[\'name\']
        stderr_path = os.path.join(out_dir, stderr_name)

        try:
            # This script sets its own niceness value to the highest(-20) below
            # to help ensure the heartbeat keeps running. When launching the
            # script we need to lower the nice value as a child process
            # inherits the parent processes niceness value. preexec_fn is
            # executed in the child process before the command is run. When
            # setting the nice value the kernel adds the current nice value
            # to the provided value. Since the runner uses a nice value of -20
            # setting it to 40 gives the actual nice value of 20.
            proc = Popen(
                script_path, stdout=PIPE, stderr=PIPE,
                preexec_fn=lambda: os.nice(40))
            capture_script_output(
                proc, combined_path, stdout_path, stderr_path, timeout_seconds)
        except OSError as e:
            fail_count += 1
            if isinstance(e.errno, int) and e.errno != 0:
                args[\'exit_status\'] = e.errno
            else:
                # 2 is the return code bash gives when it can\'t execute.
                args[\'exit_status\'] = 2
            result = str(e).encode()
            if result == b\'\':
                result = b\'Unable to execute script\'
            args[\'files\'] = {
                script[\'name\']: result,
                stderr_name: result,
            }
            signal_wrapper(
                error=\'Failed to execute %s [%d/%d]: %d\' % (
                    script[\'name\'], i, total_scripts, args[\'exit_status\']),
                **args)
        except TimeoutExpired:
            fail_count += 1
            args[\'status\'] = \'TIMEDOUT\'
            args[\'files\'] = {
                script[\'name\']: open(combined_path, \'rb\').read(),
                stdout_name: open(stdout_path, \'rb\').read(),
                stderr_name: open(stderr_path, \'rb\').read(),
            }
            signal_wrapper(
                error=\'Timeout(%s) expired on %s [%d/%d]\' % (
                    str(timedelta(seconds=timeout_seconds)), script[\'name\'], i,
                    total_scripts),
                **args)
        else:
            if proc.returncode != 0:
                fail_count += 1
            args[\'exit_status\'] = proc.returncode
            args[\'files\'] = {
                script[\'name\']: open(combined_path, \'rb\').read(),
                stdout_name: open(stdout_path, \'rb\').read(),
                stderr_name: open(stderr_path, \'rb\').read(),
            }
            signal_wrapper(
                error=\'Finished %s [%d/%d]: %d\' % (
                    script[\'name\'], i, len(scripts), args[\'exit_status\']),
                **args)

    # Signal failure after running commissioning or testing scripts so MAAS
    # transisitions the node into FAILED_COMMISSIONING or FAILED_TESTING.
    if fail_count != 0:
        signal_wrapper(
            url, creds, \'FAILED\', \'%d scripts failed to run\' % fail_count)

    return fail_count


def run_scripts_from_metadata(url, creds, scripts_dir, out_dir):
    """Run all scripts from a tar given by MAAS."""
    with open(os.path.join(scripts_dir, \'index.json\')) as f:
        scripts = json.load(f)[\'1.0\']

    fail_count = 0
    commissioning_scripts = scripts.get(\'commissioning_scripts\')
    if commissioning_scripts is not None:
        fail_count += run_scripts(
            url, creds, scripts_dir, out_dir, commissioning_scripts)
        if fail_count != 0:
            return

    testing_scripts = scripts.get(\'testing_scripts\')
    if testing_scripts is not None:
        # If the node status was COMMISSIONING transition the node into TESTING
        # status. If the node is already in TESTING status this is ignored.
        signal_wrapper(url, creds, \'TESTING\')
        fail_count += run_scripts(
            url, creds, scripts_dir, out_dir, testing_scripts)

    # Only signal OK when we\'re done with everything and nothing has failed.
    if fail_count == 0:
        signal_wrapper(url, creds, \'OK\', \'All scripts successfully ran\')


class HeartBeat(Thread):
    """Creates a background thread which pings the MAAS metadata service every
    two minutes to let it know we\'re still up and running scripts. If MAAS
    doesn\'t hear from us it will assume something has gone wrong and power off
    the node.
    """

    def __init__(self, url, creds):
        super().__init__(name=\'HeartBeat\')
        self._url = url
        self._creds = creds
        self._run = Event()
        self._run.set()

    def stop(self):
        self._run.clear()

    def run(self):
        # Record the relative start time of the entire run.
        start = time.monotonic()
        tenths = 0
        while self._run.is_set():
            # Record the start of this heartbeat interval.
            heartbeat_start = time.monotonic()
            heartbeat_elapsed = 0
            total_elapsed = heartbeat_start - start
            args = [self._url, self._creds, \'WORKING\']
            # Log the elapsed time plus the measured clock skew, if this
            # is the second run through the loop.
            if tenths > 0:
                args.append(
                    \'Elapsed time (real): %d.%ds; Python: %d.%ds\' % (
                        total_elapsed, total_elapsed % 1 * 10,
                        tenths // 10, tenths % 10))
            signal_wrapper(*args)
            # Spin for 2 minutes before sending another heartbeat.
            while heartbeat_elapsed < 120 and self._run.is_set():
                heartbeat_end = time.monotonic()
                heartbeat_elapsed = heartbeat_end - heartbeat_start
                # Wake up every tenth of a second to record clock skew and
                # ensure delayed scheduling doesn\'t impact the heartbeat.
                time.sleep(0.1)
                tenths += 1


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description=\'Download and run scripts from the MAAS metadata service.\')
    parser.add_argument(
        "--config", metavar="file", help="Specify config file", default=None)
    parser.add_argument(
        "--ckey", metavar="key", help="The consumer key to auth with",
        default=None)
    parser.add_argument(
        "--tkey", metavar="key", help="The token key to auth with",
        default=None)
    parser.add_argument(
        "--csec", metavar="secret", help="The consumer secret (likely \'\')",
        default="")
    parser.add_argument(
        "--tsec", metavar="secret", help="The token secret to auth with",
        default=None)
    parser.add_argument(
        "--apiver", metavar="version",
        help="The apiver to use (\\"\\" can be used)", default=MD_VERSION)
    parser.add_argument(
        "--url", metavar="url", help="The data source to query", default=None)

    parser.add_argument(
        "storage_directory",
        help="Directory to store the extracted data from the metadata service."
    )

    args = parser.parse_args()

    creds = {
        \'consumer_key\': args.ckey,
        \'token_key\': args.tkey,
        \'token_secret\': args.tsec,
        \'consumer_secret\': args.csec,
        \'metadata_url\': args.url,
        }

    if args.config:
        read_config(args.config, creds)

    url = creds.get(\'metadata_url\')
    if url is None:
        fail("URL must be provided either in --url or in config\
")
    url = "%s/%s/" % (url, args.apiver)

    # Disable the OOM killer on the runner process, the OOM killer will still
    # go after any tests spawned.
    oom_score_adj_path = os.path.join(
        \'/proc\', str(os.getpid()), \'oom_score_adj\')
    open(oom_score_adj_path, \'w\').write(\'-1000\')
    # Give the runner the highest nice value to ensure the heartbeat keeps
    # running.
    os.nice(-20)

    heart_beat = HeartBeat(url, creds)
    heart_beat.start()

    scripts_dir = os.path.join(args.storage_directory, \'scripts\')
    os.makedirs(scripts_dir)
    out_dir = os.path.join(args.storage_directory, \'out\')
    os.makedirs(out_dir)

    download_and_extract_tar("%s/maas-scripts/" % url, creds, scripts_dir)
    run_scripts_from_metadata(url, creds, scripts_dir, out_dir)

    heart_beat.stop()


if __name__ == \'__main__\':
    main()

END_MAAS_RUN_REMOTE_SCRIPTS


main
exit
