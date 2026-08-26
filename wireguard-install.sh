#!/usr/bin/env bash

# Secure WireGuard server installer
# https://github.com/angristan/wireguard-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Default values
CONFIG_FILE="./setup.conf"
LOG_DIR="."
LOG_FILENAME="wireguard-install-$(date +%Y%m%d%H%M%S).log"
CLI_LOG_DIR=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
	case $1 in
	-c | --config)
		CONFIG_FILE="$2"
		shift
		shift
		;;
	-f | --force)
		FORCE_REINSTALL="1"
		shift
		;;
	-u | --update)
		UPDATE_CONFIG="1"
		shift
		;;
	-l | --log)
		LOG_DIR="$2"
		CLI_LOG_DIR="$2"
		shift
		shift
		;;
	-h | --help)
		echo "Usage: $0 [options]"
		echo "Options:"
		echo "  -c, --config <path>  Path to the configuration file (default: ./setup.conf)"
		echo "  -f, --force          Force reinstall if already installed"
		echo "  -u, --update         Update configuration if already installed"
		echo "  -l, --log <path>     Path to the log directory (default: .)"
		echo "  -h, --help           Show this help message"
		exit 0
		;;
	*)
		echo "Unknown option: $1"
		exit 1
		;;
	esac
done

function installPackages() {
	"$@" 2>&1 | tee -a "${LOG_FILE}"
	if [ "${PIPESTATUS[0]}" -ne 0 ]; then
		echo -e "${RED}Failed to install packages.${NC}"
		echo "Please check your internet connection and package sources."
		echo "Installation failed (package installation) at $(date)" >>"${LOG_FILE}"
		exit 1
	fi
}

function isValidIPv4() {
	local ADDRESS=$1
	local OCTETS
	local OCTET

	IFS='.' read -r -a OCTETS <<<"${ADDRESS}"
	[[ ${#OCTETS[@]} -eq 4 ]] || return 1

	for OCTET in "${OCTETS[@]}"; do
		[[ ${OCTET} =~ ^[0-9]{1,3}$ ]] || return 1
		((10#${OCTET} <= 255)) || return 1
	done
}

function isValidPort() {
	local PORT=$1

	[[ ${PORT} =~ ^[0-9]+$ ]] || return 1
	((10#${PORT} >= 1 && 10#${PORT} <= 65535))
}

function isValidIPv4Cidr() {
	local CIDR=$1
	local ADDRESS
	local PREFIX
	local EXTRA_FIELD

	IFS='/' read -r ADDRESS PREFIX EXTRA_FIELD <<<"${CIDR}"
	[[ -z ${EXTRA_FIELD} ]] || return 1
	isValidIPv4 "${ADDRESS}" || return 1
	[[ ${PREFIX} =~ ^[0-9]+$ ]] || return 1
	((10#${PREFIX} >= 0 && 10#${PREFIX} <= 32))
}

function ipv4ToInteger() {
	local ADDRESS=$1
	local A
	local B
	local C
	local D

	IFS='.' read -r A B C D <<<"${ADDRESS}"
	echo "$(((10#${A} << 24) | (10#${B} << 16) | (10#${C} << 8) | 10#${D}))"
}

function ipv4BelongsToCidr() {
	local ADDRESS=$1
	local CIDR=$2
	local NETWORK_ADDRESS=${CIDR%/*}
	local PREFIX=${CIDR#*/}
	local ADDRESS_INTEGER
	local NETWORK_INTEGER
	local MASK

	ADDRESS_INTEGER=$(ipv4ToInteger "${ADDRESS}")
	NETWORK_INTEGER=$(ipv4ToInteger "${NETWORK_ADDRESS}")

	if ((10#${PREFIX} == 0)); then
		MASK=0
	else
		MASK=$(((0xFFFFFFFF << (32 - 10#${PREFIX})) & 0xFFFFFFFF))
	fi

	(((ADDRESS_INTEGER & MASK) == (NETWORK_INTEGER & MASK)))
}

function validatePrivateForwardRules() {
	local RULE
	local PROTOCOL
	local LISTEN_IP
	local LISTEN_PORT
	local TARGET_IP
	local TARGET_PORT
	local SNAT_IP
	local EXTRA_FIELD
	local RULE_KEY
	local SEEN_RULE_KEYS=" "

	for RULE in ${PRIVATE_FORWARD_RULES:-}; do
		IFS='|' read -r PROTOCOL LISTEN_IP LISTEN_PORT TARGET_IP TARGET_PORT SNAT_IP EXTRA_FIELD <<<"${RULE}"

		if [[ -z ${PROTOCOL} || -z ${LISTEN_IP} || -z ${LISTEN_PORT} || -z ${TARGET_IP} || -z ${TARGET_PORT} || -z ${SNAT_IP} || -n ${EXTRA_FIELD} ]]; then
			echo "Invalid private forward '${RULE}'. Expected protocol|listen_ip|listen_port|target_ip|target_port|snat_ip."
			exit 1
		fi

		if [[ ${PROTOCOL} != "tcp" && ${PROTOCOL} != "udp" ]]; then
			echo "Invalid protocol '${PROTOCOL}' in private forward '${RULE}'. Only tcp and udp are supported."
			exit 1
		fi

		if ! isValidIPv4 "${LISTEN_IP}" || ! isValidIPv4 "${TARGET_IP}" || ! isValidIPv4 "${SNAT_IP}"; then
			echo "Invalid IPv4 address in private forward '${RULE}'."
			exit 1
		fi

		if ! isValidPort "${LISTEN_PORT}" || ! isValidPort "${TARGET_PORT}"; then
			echo "Invalid port in private forward '${RULE}'."
			exit 1
		fi

		if [[ ${LISTEN_IP} != "${SERVER_WG_IPV4}" ]]; then
			echo "Private forward '${RULE}' must listen on SERVER_WG_IPV4 (${SERVER_WG_IPV4})."
			exit 1
		fi

		RULE_KEY="${PROTOCOL}|${LISTEN_IP}|${LISTEN_PORT}"
		if [[ ${SEEN_RULE_KEYS} == *" ${RULE_KEY} "* ]]; then
			echo "Duplicate private forward listener '${RULE_KEY}'."
			exit 1
		fi
		SEEN_RULE_KEYS+="${RULE_KEY} "
	done
}

function validatePrivateRouteRules() {
	local RULE
	local PROTOCOL
	local TARGET_IP
	local TARGET_PORT
	local PROTECTED_SUBNET
	local SNAT_IP
	local EXTRA_FIELD
	local RULE_KEY
	local SEEN_RULE_KEYS=" "

	for RULE in ${PRIVATE_ROUTE_RULES:-}; do
		IFS='|' read -r PROTOCOL TARGET_IP TARGET_PORT PROTECTED_SUBNET SNAT_IP EXTRA_FIELD <<<"${RULE}"

		if [[ -z ${PROTOCOL} || -z ${TARGET_IP} || -z ${TARGET_PORT} || -z ${PROTECTED_SUBNET} || -z ${SNAT_IP} || -n ${EXTRA_FIELD} ]]; then
			echo "Invalid private route '${RULE}'. Expected protocol|target_ip|target_port|protected_subnet|snat_ip."
			exit 1
		fi

		if [[ ${PROTOCOL} != "tcp" && ${PROTOCOL} != "udp" ]]; then
			echo "Invalid protocol '${PROTOCOL}' in private route '${RULE}'. Only tcp and udp are supported."
			exit 1
		fi

		if ! isValidIPv4 "${TARGET_IP}" || ! isValidIPv4 "${SNAT_IP}" || ! isValidIPv4Cidr "${PROTECTED_SUBNET}"; then
			echo "Invalid IPv4 address or CIDR in private route '${RULE}'."
			exit 1
		fi

		if ! isValidPort "${TARGET_PORT}"; then
			echo "Invalid port in private route '${RULE}'."
			exit 1
		fi

		if ! ipv4BelongsToCidr "${TARGET_IP}" "${PROTECTED_SUBNET}"; then
			echo "Private route target '${TARGET_IP}' is outside '${PROTECTED_SUBNET}'."
			exit 1
		fi

		RULE_KEY="${PROTOCOL}|${TARGET_IP}|${TARGET_PORT}"
		if [[ ${SEEN_RULE_KEYS} == *" ${RULE_KEY} "* ]]; then
			echo "Duplicate private route '${RULE_KEY}'."
			exit 1
		fi
		SEEN_RULE_KEYS+="${RULE_KEY} "
	done
}

function appendPrivateRouteRules() {
	local WG_CONFIG=$1
	local WG_SUBNET="${SERVER_WG_IPV4%.*}.0/24"
	local RULE
	local PROTOCOL
	local TARGET_IP
	local TARGET_PORT
	local PROTECTED_SUBNET
	local SNAT_IP
	local SEEN_PROTECTED_SUBNETS=" "

	# Insert subnet rejects first. Target-specific accepts below are inserted
	# above them, while broader WireGuard port accepts remain below them.
	for RULE in ${PRIVATE_ROUTE_RULES:-}; do
		IFS='|' read -r PROTOCOL TARGET_IP TARGET_PORT PROTECTED_SUBNET SNAT_IP <<<"${RULE}"
		if [[ ${SEEN_PROTECTED_SUBNETS} != *" ${PROTECTED_SUBNET} "* ]]; then
			echo "PostUp = iptables -w -I FORWARD 1 -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${PROTECTED_SUBNET} -j REJECT --reject-with icmp-port-unreachable" >>"${WG_CONFIG}"
			SEEN_PROTECTED_SUBNETS+="${PROTECTED_SUBNET} "
		fi
	done

	for RULE in ${PRIVATE_ROUTE_RULES:-}; do
		IFS='|' read -r PROTOCOL TARGET_IP TARGET_PORT PROTECTED_SUBNET SNAT_IP <<<"${RULE}"

		cat >>"${WG_CONFIG}" <<EOF
PostUp = iptables -w -I FORWARD 1 -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
PostUp = iptables -w -I FORWARD 1 -o ${SERVER_WG_NIC} -s ${TARGET_IP} -d ${WG_SUBNET} -p ${PROTOCOL} --sport ${TARGET_PORT} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostUp = iptables -w -t nat -I POSTROUTING 1 -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -j SNAT --to-source ${SNAT_IP}
PostDown = iptables -w -D FORWARD -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
PostDown = iptables -w -D FORWARD -o ${SERVER_WG_NIC} -s ${TARGET_IP} -d ${WG_SUBNET} -p ${PROTOCOL} --sport ${TARGET_PORT} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -w -t nat -D POSTROUTING -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -j SNAT --to-source ${SNAT_IP}
EOF
	done

	SEEN_PROTECTED_SUBNETS=" "
	for RULE in ${PRIVATE_ROUTE_RULES:-}; do
		IFS='|' read -r PROTOCOL TARGET_IP TARGET_PORT PROTECTED_SUBNET SNAT_IP <<<"${RULE}"
		if [[ ${SEEN_PROTECTED_SUBNETS} != *" ${PROTECTED_SUBNET} "* ]]; then
			echo "PostDown = iptables -w -D FORWARD -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${PROTECTED_SUBNET} -j REJECT --reject-with icmp-port-unreachable" >>"${WG_CONFIG}"
			SEEN_PROTECTED_SUBNETS+="${PROTECTED_SUBNET} "
		fi
	done
}

function appendPrivateForwardRules() {
	local WG_CONFIG=$1
	local WG_SUBNET="${SERVER_WG_IPV4%.*}.0/24"
	local RULE
	local PROTOCOL
	local LISTEN_IP
	local LISTEN_PORT
	local TARGET_IP
	local TARGET_PORT
	local SNAT_IP

	for RULE in ${PRIVATE_FORWARD_RULES:-}; do
		IFS='|' read -r PROTOCOL LISTEN_IP LISTEN_PORT TARGET_IP TARGET_PORT SNAT_IP <<<"${RULE}"

		cat >>"${WG_CONFIG}" <<EOF
PostUp = iptables -w -t nat -I PREROUTING 1 -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${LISTEN_IP} -p ${PROTOCOL} --dport ${LISTEN_PORT} -j DNAT --to-destination ${TARGET_IP}:${TARGET_PORT}
PostUp = iptables -w -I FORWARD 1 -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
PostUp = iptables -w -I FORWARD 1 -o ${SERVER_WG_NIC} -s ${TARGET_IP} -d ${WG_SUBNET} -p ${PROTOCOL} --sport ${TARGET_PORT} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostUp = iptables -w -t nat -I POSTROUTING 1 -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -j SNAT --to-source ${SNAT_IP}
PostDown = iptables -w -t nat -D PREROUTING -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${LISTEN_IP} -p ${PROTOCOL} --dport ${LISTEN_PORT} -j DNAT --to-destination ${TARGET_IP}:${TARGET_PORT}
PostDown = iptables -w -D FORWARD -i ${SERVER_WG_NIC} -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
PostDown = iptables -w -D FORWARD -o ${SERVER_WG_NIC} -s ${TARGET_IP} -d ${WG_SUBNET} -p ${PROTOCOL} --sport ${TARGET_PORT} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = iptables -w -t nat -D POSTROUTING -s ${WG_SUBNET} -d ${TARGET_IP} -p ${PROTOCOL} --dport ${TARGET_PORT} -j SNAT --to-source ${SNAT_IP}
EOF
	done
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if command -v virt-what &>/dev/null; then
		VIRT=$(virt-what)
	elif command -v systemd-detect-virt &>/dev/null; then
		VIRT=$(systemd-detect-virt)
	else
		VIRT="none"
	fi

	if [[ ${VIRT} == "openvz" ]]; then
		echo "OpenVZ is not supported"
		exit 1
	fi
	if [[ ${VIRT} == "lxc" ]]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later"
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			if ! (apk update && apk add virt-what); then
				echo -e "${RED}Failed to install virt-what. Continuing without virtualization check.${NC}"
			fi
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	if [[ -n "${CLIENT_CONFIG_DIR}" ]]; then
		echo "${CLIENT_CONFIG_DIR}"
		return
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

function installQuestions() {
	if [[ "${HEADLESS}" != "1" ]]; then
		echo "Welcome to the WireGuard installer!"
		echo "The git repository is available at: https://github.com/angristan/wireguard-install"
		echo ""
		echo "I need to ask you a few questions before starting the setup."
		echo "You can keep the default options and just press enter if you are ok with them."
		echo ""
	fi

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	if [[ -z "${SERVER_PUB_IP}" ]]; then
		SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
		if [[ -z ${SERVER_PUB_IP} ]]; then
			# Detect public IPv6 address
			SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
		fi
	fi

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${SERVER_PUB_IP} ]]; then
			SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
		fi
	else
		read -rp "IPv4 or IPv6 public address: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP
	fi

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${SERVER_PUB_NIC} ]]; then
			SERVER_PUB_NIC="${SERVER_NIC}"
		fi
	else
		until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
			read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
		done
	fi

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${SERVER_WG_NIC} ]]; then
			SERVER_WG_NIC="wg0"
		fi
	else
		until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
			read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
		done
	fi

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${SERVER_WG_IPV4} ]]; then
			SERVER_WG_IPV4="10.66.66.1"
		fi
	else
		until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
			read -rp "Server WireGuard IPv4: " -e -i 10.66.66.1 SERVER_WG_IPV4
		done
	fi

	if [[ "${ENABLE_IPV6}" != "0" ]]; then
		if [[ "${HEADLESS}" == "1" ]]; then
			if [[ -z ${SERVER_WG_IPV6} ]]; then
				SERVER_WG_IPV6="fd42:42:42::1"
			fi
		else
			until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
				read -rp "Server WireGuard IPv6: " -e -i fd42:42:42::1 SERVER_WG_IPV6
			done
		fi
	fi

	# Generate random number within private ports range
	RANDOM_PORT=$(shuf -i49152-65535 -n1)
	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${SERVER_PORT} ]]; then
			SERVER_PORT="${RANDOM_PORT}"
		fi
	else
		until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
			read -rp "Server WireGuard port [1-65535]: " -e -i "${RANDOM_PORT}" SERVER_PORT
		done
	fi

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -n "${RESTRICT_PORT}" ]] || [[ -n "${RESTRICT_PORT_CONNTRACK}" ]]; then
			RESTRICT_TRAFFIC="y"
		else
			RESTRICT_TRAFFIC="n"
		fi
	else
		echo -e "
Do you want to restrict VPN traffic to a specific port?"
		read -rp "Restrict traffic [y/n]: " -e -i n RESTRICT_TRAFFIC
		if [[ "${RESTRICT_TRAFFIC}" == "y" ]]; then
			while true; do
				read -rp "Ports to restrict traffic to (space or comma separated): " -e -i 8042 RESTRICT_PORT_INPUT
				RESTRICT_PORT_NORMALIZED=${RESTRICT_PORT_INPUT//,/ }
				VALID_PORTS=true
				for PORT in ${RESTRICT_PORT_NORMALIZED}; do
					if ! [[ ${PORT} =~ ^[0-9]+$ ]] || [ "${PORT}" -lt 1 ] || [ "${PORT}" -gt 65535 ]; then
						VALID_PORTS=false
						echo "Invalid port: ${PORT}"
						break
					fi
				done
				if [[ "${VALID_PORTS}" == "true" ]]; then
					RESTRICT_PORT="${RESTRICT_PORT_NORMALIZED}"
					break
				fi
			done
		fi
	fi

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${CLIENT_DNS_1} ]]; then
			CLIENT_DNS_1="1.1.1.1"
		fi
		if [[ -z ${CLIENT_DNS_2} ]]; then
			CLIENT_DNS_2="1.0.0.1"
		fi
	else
		echo -e "
What DNS resolvers do you want to use for the clients?"
		echo "   1) Current system resolvers"
		echo "   2) Google"
		echo "   3) 1.1.1.1"
		echo "   4) OpenDNS"
		echo "   5) Quad9"
		echo "   6) AdGuard"
		read -rp "DNS [1-6]: " -e -i 1 DNS
		until [[ ${DNS} =~ ^[1-6]$ ]]; do
			read -rp "DNS [1-6]: " -e -i 1 DNS
		done
		case ${DNS} in
		1)
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
				RESOLV_CONF="/run/systemd/resolve/resolv.conf"
			else
				RESOLV_CONF="/etc/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			DNS_SERVERS=$(grep -v '^#\|^;' "${RESOLV_CONF}" | grep '^nameserver' | awk '{print $2}')
			CLIENT_DNS_1=$(echo "${DNS_SERVERS}" | head -n 1)
			CLIENT_DNS_2=$(echo "${DNS_SERVERS}" | sed -n '2p')
			;;
		2)
			CLIENT_DNS_1="8.8.8.8"
			CLIENT_DNS_2="8.8.4.4"
			;;
		3)
			CLIENT_DNS_1="1.1.1.1"
			CLIENT_DNS_2="1.0.0.1"
			;;
		4)
			CLIENT_DNS_1="208.67.222.222"
			CLIENT_DNS_2="208.67.220.220"
			;;
		5)
			CLIENT_DNS_1="9.9.9.9"
			CLIENT_DNS_2="149.112.112.112"
			;;
		6)
			CLIENT_DNS_1="94.140.14.14"
			CLIENT_DNS_2="94.140.15.15"
			;;
		esac
	fi

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${ALLOWED_IPS} ]]; then
			if [[ "${RESTRICT_TRAFFIC}" == "y" ]]; then
				if [[ "${ENABLE_IPV6}" == "0" ]]; then
					ALLOWED_IPS="${SERVER_WG_IPV4}/24"
				else
					ALLOWED_IPS="${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64"
				fi
			else
				if [[ "${ENABLE_IPV6}" == "0" ]]; then
					ALLOWED_IPS="0.0.0.0/0"
				else
					ALLOWED_IPS="0.0.0.0/0,::/0"
				fi
			fi
		elif [[ "${RESTRICT_TRAFFIC}" == "y" ]]; then
			if [[ "${ALLOWED_IPS}" == "0.0.0.0/0" || "${ALLOWED_IPS}" == "0.0.0.0/0,::/0" ]]; then
				if [[ "${ENABLE_IPV6}" == "0" ]]; then
					ALLOWED_IPS="${SERVER_WG_IPV4}/24"
				else
					ALLOWED_IPS="${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64"
				fi
			fi
		fi
	else
		until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
			echo -e "\nWireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN."
			if [[ "${RESTRICT_TRAFFIC}" == "y" ]]; then
				if [[ "${ENABLE_IPV6}" == "0" ]]; then
					DEFAULT_ALLOWED_IPS="${SERVER_WG_IPV4}/24"
				else
					DEFAULT_ALLOWED_IPS="${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64"
				fi
			else
				if [[ "${ENABLE_IPV6}" == "0" ]]; then
					DEFAULT_ALLOWED_IPS="0.0.0.0/0"
				else
					DEFAULT_ALLOWED_IPS="0.0.0.0/0,::/0"
				fi
			fi
			read -rp "Allowed IPs list for generated clients (leave default to route everything): " -e -i "${DEFAULT_ALLOWED_IPS}" ALLOWED_IPS
			if [[ ${ALLOWED_IPS} == "" ]]; then
				ALLOWED_IPS="${DEFAULT_ALLOWED_IPS}"
			fi
		done
	fi

	validatePrivateForwardRules
	validatePrivateRouteRules

	if [[ "${HEADLESS}" != "1" ]]; then
		echo ""
		echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
		echo "You will be able to generate a client at the end of the installation."
		read -n1 -r -p "Press any key to continue..."
	fi
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	echo "Installation started at $(date)" >>"${LOG_FILE}"

	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update >>"${LOG_FILE}" 2>&1
		installPackages apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update >>"${LOG_FILE}" 2>&1
		fi
		apt-get update >>"${LOG_FILE}" 2>&1
		installPackages apt-get install -y iptables resolvconf qrencode
		installPackages apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			installPackages dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard >>"${LOG_FILE}" 2>&1
			installPackages dnf install -y wireguard-dkms
		fi
		installPackages dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			installPackages yum install -y epel-release elrepo-release
			installPackages yum install -y kmod-wireguard
			yum install -y qrencode || true # not available on release 9
		fi
		installPackages yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		installPackages dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer >>"${LOG_FILE}" 2>&1
		dnf config-manager --enable -y ol8_developer_UEKR6 >>"${LOG_FILE}" 2>&1
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*' >>"${LOG_FILE}" 2>&1
		installPackages dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		installPackages pacman -S --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update >>"${LOG_FILE}" 2>&1
		installPackages apk add wireguard-tools iptables libqrencode-tools
	fi

	# Verify WireGuard installation
	if ! command -v wg &>/dev/null; then
		echo -e "${RED}WireGuard installation failed. The 'wg' command was not found.${NC}"
		echo "Please check the installation output above for errors."
		exit 1
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
ENABLE_IPV6=${ENABLE_IPV6}
HEADLESS=${HEADLESS}
INSTALL_CLIENT=${INSTALL_CLIENT}
ENABLE_NAT=${ENABLE_NAT}
RESTRICT_TRAFFIC=${RESTRICT_TRAFFIC}
RESTRICT_PORT=\"${RESTRICT_PORT[*]}\"
RESTRICT_PORT_CONNTRACK=\"${RESTRICT_PORT_CONNTRACK[*]}\"
PRIVATE_FORWARD_RULES=\"${PRIVATE_FORWARD_RULES[*]}\"
PRIVATE_ROUTE_RULES=\"${PRIVATE_ROUTE_RULES[*]}\"
CLIENT_CONFIG_DIR=${CLIENT_CONFIG_DIR}
INSTALL_TIMESTAMP=$(date +%Y%m%d%H%M%S)" >/etc/wireguard/params

	# Add server interface
	if [[ "${ENABLE_IPV6}" == "0" ]]; then
		echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		if [[ "${ENABLE_IPV6}" == "0" ]]; then
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		else
			FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		fi
	else
		if [[ "${ENABLE_IPV6}" == "0" ]]; then
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		else
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		fi
	fi

	if [[ "${RESTRICT_TRAFFIC}" == "y" ]]; then
		# Handle if RESTRICT_PORT is an array or string, and normalize separators
		ALL_PORTS="${RESTRICT_PORT[*]}"
		ALL_PORTS=${ALL_PORTS//,/ }

		# Handle if RESTRICT_PORT_CONNTRACK is provided
		ALL_PORTS_CONNTRACK="${RESTRICT_PORT_CONNTRACK[*]}"
		ALL_PORTS_CONNTRACK=${ALL_PORTS_CONNTRACK//,/ }

		echo "PostUp = iptables -I INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		for PORT in ${ALL_PORTS}; do
			echo "PostUp = iptables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done
		for PORT in ${ALL_PORTS_CONNTRACK}; do
			echo "PostUp = iptables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done
		echo "PostDown = iptables -D INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		for PORT in ${ALL_PORTS}; do
			echo "PostDown = iptables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done
		for PORT in ${ALL_PORTS_CONNTRACK}; do
			echo "PostDown = iptables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done

		if [[ "${ENABLE_IPV6}" != "0" ]]; then
			echo "PostUp = ip6tables -I INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			for PORT in ${ALL_PORTS}; do
				echo "PostUp = ip6tables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
			for PORT in ${ALL_PORTS_CONNTRACK}; do
				echo "PostUp = ip6tables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
			echo "PostDown = ip6tables -D INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			for PORT in ${ALL_PORTS}; do
				echo "PostDown = ip6tables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
			for PORT in ${ALL_PORTS_CONNTRACK}; do
				echo "PostDown = ip6tables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
		fi
	fi

	appendPrivateRouteRules "/etc/wireguard/${SERVER_WG_NIC}.conf"
	appendPrivateForwardRules "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Enable routing on the server
	if [[ "${ENABLE_IPV6}" == "0" ]]; then
		echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/wg.conf
	else
		echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'fedora' ]]; then
		chmod -v 700 /etc/wireguard
		chmod -v 600 /etc/wireguard/*
	fi

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf >>"${LOG_FILE}" 2>&1
		rc-update add sysctl >>"${LOG_FILE}" 2>&1
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}" >>"${LOG_FILE}" 2>&1
		rc-service "wg-quick.${SERVER_WG_NIC}" start >>"${LOG_FILE}" 2>&1
		rc-update add "wg-quick.${SERVER_WG_NIC}" >>"${LOG_FILE}" 2>&1
	else
		sysctl --system >>"${LOG_FILE}" 2>&1

		systemctl start "wg-quick@${SERVER_WG_NIC}" >>"${LOG_FILE}" 2>&1
		systemctl enable "wg-quick@${SERVER_WG_NIC}" >>"${LOG_FILE}" 2>&1
	fi

	if [[ "${INSTALL_CLIENT}" != "0" ]]; then
		newClient
		echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"
	fi

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: WireGuard does not seem to be running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${ORANGE}You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status${NC}"
		else
			echo -e "${ORANGE}You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}${NC}"
		fi
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!${NC}"
	else # WireGuard is running
		echo -e "\n${GREEN}WireGuard is running.${NC}"
		if [[ ${OS} == 'alpine' ]]; then
			echo -e "${GREEN}You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status\n\n${NC}"
		else
			echo -e "${GREEN}You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}\n\n${NC}"
		fi
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
		echo "Installation finished successfully at $(date)" >>"${LOG_FILE}"
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	if [[ "${HEADLESS}" == "1" ]]; then
		if [[ -z ${CLIENT_NAME} ]]; then
			echo "Error: CLIENT_NAME is required in headless mode"
			exit 1
		fi
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo "Error: Client ${CLIENT_NAME} already exists"
			exit 1
		fi
	else
		until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
			read -rp "Client name: " -e CLIENT_NAME
			CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

			if [[ ${CLIENT_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
				echo ""
			fi
		done
	fi

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		read -rp "Client WireGuard IPv4: ${BASE_IP}." -e -i "${DOT_IP}" DOT_IP
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.${NC}"
			echo ""
		fi
	done

	if [[ "${ENABLE_IPV6}" == "0" ]]; then
		:
	else
		BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
		until [[ ${IPV6_EXISTS} == '0' ]]; do
			read -rp "Client WireGuard IPv6: ${BASE_IP}::" -e -i "${DOT_IP}" DOT_IP
			CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
			IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

			if [[ ${IPV6_EXISTS} != 0 ]]; then
				echo ""
				echo -e "${ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.${NC}"
				echo ""
			fi
		done
	fi

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	mkdir -p "$HOME_DIR"

	if [[ -n "${CLIENT_DNS_2}" ]]; then
		DNS_LINE="DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}"
	else
		DNS_LINE="DNS = ${CLIENT_DNS_1}"
	fi

	if [[ "${ENABLE_IPV6}" == "0" ]]; then
		# Create client file and add the server as a peer
		echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32
${DNS_LINE}

# Uncomment the next line to set a custom MTU
# This might impact performance, so use it only if you know what you are doing
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

		# Add the client as a peer to the server
		echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		# Create client file and add the server as a peer
		echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
${DNS_LINE}

# Uncomment the next line to set a custom MTU
# This might impact performance, so use it only if you know what you are doing
# See https://github.com/nitred/nr-wg-mtu-finder to find your optimal MTU
# MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

		# Add the client as a peer to the server
		echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo -e "${GREEN}\nHere is your client config file as a QR Code:\n${NC}"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"
		echo ""
	fi

	echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf${NC}"
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall WireGuard and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/wireguard directory if you want to keep your configuration files.\n${NC}"
	if [[ "${FORCE_REINSTALL}" == "1" ]]; then
		REMOVE="y"
	else
		read -rp "Do you really want to remove WireGuard? [y/n]: " -e REMOVE
		REMOVE=${REMOVE:-n}
	fi
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ -n "${CLIENT_CONFIG_DIR}" ]]; then
			rm -rf "${CLIENT_CONFIG_DIR}"
		fi

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			echo "WireGuard failed to uninstall properly."
			return 1
		else
			echo "WireGuard uninstalled successfully."
			return 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function updateWireGuard() {
	echo "Updating WireGuard configuration..."

	# Source config file to get new values
	if [[ -e "${CONFIG_FILE}" ]]; then
		# shellcheck disable=SC1091
		source "${CONFIG_FILE}"
	fi

	validatePrivateForwardRules
	validatePrivateRouteRules

	# Save existing clients
	CLIENTS_BLOCK=$(sed -n '/^### Client/,$p' "/etc/wireguard/${SERVER_WG_NIC}.conf")

	# Update params file
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
ENABLE_IPV6=${ENABLE_IPV6}
HEADLESS=${HEADLESS}
INSTALL_CLIENT=${INSTALL_CLIENT}
ENABLE_NAT=${ENABLE_NAT}
RESTRICT_TRAFFIC=${RESTRICT_TRAFFIC}
RESTRICT_PORT=\"${RESTRICT_PORT[*]}\"
RESTRICT_PORT_CONNTRACK=\"${RESTRICT_PORT_CONNTRACK[*]}\"
PRIVATE_FORWARD_RULES=\"${PRIVATE_FORWARD_RULES[*]}\"
PRIVATE_ROUTE_RULES=\"${PRIVATE_ROUTE_RULES[*]}\"
CLIENT_CONFIG_DIR=${CLIENT_CONFIG_DIR}
INSTALL_TIMESTAMP=${INSTALL_TIMESTAMP}" >/etc/wireguard/params

	# Stop WireGuard to clean up old firewall rules
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" stop
	else
		systemctl stop "wg-quick@${SERVER_WG_NIC}"
	fi

	# Regenerate Interface config
	# Add server interface
	if [[ "${ENABLE_IPV6}" == "0" ]]; then
		echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		if [[ "${ENABLE_IPV6}" == "0" ]]; then
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		else
			FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		fi
	else
		if [[ "${ENABLE_IPV6}" == "0" ]]; then
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		else
			if [[ "${ENABLE_NAT}" != "0" ]]; then
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			else
				echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			fi
		fi
	fi

	if [[ "${RESTRICT_TRAFFIC}" == "y" ]]; then
		# Handle if RESTRICT_PORT is an array or string, and normalize separators
		ALL_PORTS="${RESTRICT_PORT[*]}"
		ALL_PORTS=${ALL_PORTS//,/ }

		# Handle if RESTRICT_PORT_CONNTRACK is provided
		ALL_PORTS_CONNTRACK="${RESTRICT_PORT_CONNTRACK[*]}"
		ALL_PORTS_CONNTRACK=${ALL_PORTS_CONNTRACK//,/ }

		echo "PostUp = iptables -I INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		for PORT in ${ALL_PORTS}; do
			echo "PostUp = iptables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done
		for PORT in ${ALL_PORTS_CONNTRACK}; do
			echo "PostUp = iptables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done
		echo "PostDown = iptables -D INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		for PORT in ${ALL_PORTS}; do
			echo "PostDown = iptables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done
		for PORT in ${ALL_PORTS_CONNTRACK}; do
			echo "PostDown = iptables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		done

		if [[ "${ENABLE_IPV6}" != "0" ]]; then
			echo "PostUp = ip6tables -I INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			for PORT in ${ALL_PORTS}; do
				echo "PostUp = ip6tables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
			for PORT in ${ALL_PORTS_CONNTRACK}; do
				echo "PostUp = ip6tables -I INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
			echo "PostDown = ip6tables -D INPUT -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j DROP" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			for PORT in ${ALL_PORTS}; do
				echo "PostDown = ip6tables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
			for PORT in ${ALL_PORTS_CONNTRACK}; do
				echo "PostDown = ip6tables -D INPUT -i ${SERVER_WG_NIC} -p tcp --dport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
				echo "PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -p tcp -m conntrack --ctorigdstport ${PORT} -j ACCEPT" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
			done
		fi
	fi

	appendPrivateRouteRules "/etc/wireguard/${SERVER_WG_NIC}.conf"
	appendPrivateForwardRules "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# Restore clients
	if [[ -n "${CLIENTS_BLOCK}" ]]; then
		echo "" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
		echo "${CLIENTS_BLOCK}" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Restart WireGuard
	if [[ ${OS} == 'alpine' ]]; then
		rc-service "wg-quick.${SERVER_WG_NIC}" start
	else
		systemctl start "wg-quick@${SERVER_WG_NIC}"
	fi

	echo "Update finished successfully at $(date)" >>"${LOG_FILE}"
}

function manageMenu() {
	while true; do
		echo "Welcome to WireGuard-install!"
		echo "The git repository is available at: https://github.com/angristan/wireguard-install"
		echo ""
		echo "It looks like WireGuard is already installed."
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) List all users"
		echo "   3) Revoke existing user"
		echo "   4) Uninstall WireGuard"
		echo "   5) Exit"

		# Reset menu option variable to force prompt
		MENU_OPTION=""

		until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
			HEADLESS="0"
			read -rp "Select an option [1-5]: " MENU_OPTION
		done
		case "${MENU_OPTION}" in
		1)
			newClient
			;;
		2)
			listClients
			;;
		3)
			revokeClient
			;;
		4)
			uninstallWg
			exit 0
			;;
		5)
			exit 0
			;;
		esac
		echo ""
		read -n1 -r -p "Press any key to continue..."
		echo ""
	done
}

# Check for root, virt, OS...
initialCheck

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	# shellcheck disable=SC1091
	source /etc/wireguard/params
fi

# Define logging globally so it is available even when just adding a user or updating
if [[ -n "${CLI_LOG_DIR}" ]]; then
	LOG_DIR="${CLI_LOG_DIR}"
fi
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/${LOG_FILENAME}"

if [[ -n "${SERVER_PUB_KEY}" ]]; then
	if [[ "${FORCE_REINSTALL}" == "1" ]]; then
		uninstallWg
		if [[ $? -ne 0 ]]; then
			exit 1
		fi
		SERVER_PUB_KEY=""
	elif [[ "${UPDATE_CONFIG}" == "1" ]]; then
		updateWireGuard
		exit 0
	else
		manageMenu
	fi
fi

if [[ -z "${SERVER_PUB_KEY}" ]]; then
	if [[ -e "${CONFIG_FILE}" ]]; then
		# shellcheck disable=SC1091
		source "${CONFIG_FILE}"
	fi
	# No need to redefine LOG_FILE here, it's done above.
	installWireGuard
fi
