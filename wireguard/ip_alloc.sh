#!/bin/bash
#
#  VPN IP allocation for WG clients
#
source ./env

WG_CLIENT_CIDR="${SERVER_NETWORK}"
WG_CLIENT_IP_ADDR_LIST="$(cidrl ${SERVER_NETWORK} | head -n-1 | tail -n+2)"	# all allocatable host IPs in network
WG_CLIENT_IP_ADDR_LIST_ARRAY=(${WG_CLIENT_IP_ADDR_LIST})			# convert to array ...


# Initialise free and taken array
WG_CLIENT_IP_ADDR_FREE_ARRAY=(${WG_CLIENT_IP_ADDR_LIST})			# all unallocated host IPs in network
WG_CLIENT_IP_ADDR_TAKEN_ARRAY=()						# all allocated host IPs in network

TEST_VIS_CHECK="NO"

function alloc_IP() {

	# Skip each IP address addr 
	# for each WGCFG if none, break 
	echo ${1} | head -1

}

function test_visibility() {
	echo "in test_visibility: WG_CLIENT_IP_ADDR_LIST_ARRAY=${WG_CLIENT_IP_ADDR_LIST_ARRAY[@]}"
	echo "in test_visibility: after set in main: TEST_VIS_CHECK=${TEST_VIS_CHECK}"
	declare -g TEST_VIS_CHECK="YES"
	echo "in test visibility after: declare -g TEST_VIS_CHECK=${TEST_VIS_CHECK}"
}
# 
# echo "WG VPN CIDR: ${WG_CLIENT_CIDR}"
# echo
# 
# echo "Complete IP Address Pool Array: ${WG_CLIENT_IP_ADDR_LIST_ARRAY[@]}"
# echo "Complete IP Address Pool Array Size: ${#WG_CLIENT_IP_ADDR_LIST_ARRAY[@]}"
# echo
# 
# # echo "**** DEBUG visibility scope of var in function"

# # echo "in main before calling test_visibility() TEST_VIS_CHECK=${TEST_VIS_CHECK}"
# # # 
# # test_visibility
# # # 
# # echo "in main after calling test_visibility() TEST_VIS_CHECK=${TEST_VIS_CHECK}"
# # 
# exit

# 
echo "###### First allocation"

echo "Pre-allocation taken IP Address pool array: ${WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} elements)"
echo "Pre-allocation free IP Address pool array: ${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} elements)"
echo



NEXT_IP="$( alloc_IP ${WG_CLIENT_IP_ADDR_FREE_ARRAY} )"
echo "** Allocate next available (free) IP Address: ${NEXT_IP} "
echo

# echo "Add Next Available IP Address to TAKEN list"
WG_CLIENT_IP_ADDR_TAKEN_ARRAY+=("${NEXT_IP}")

echo "Post allocation taken IP address pool array: ${WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} elements)"

# echo "Remove allocated IP address from FREE list"
# WG_CLIENT_IP_ADDR_FREE_ARRAY=("${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]/$NEXT_IP}")
# rebuild array to remove indice gap
unset 'WG_CLIENT_IP_ADDR_FREE_ARRAY[0]'
for i in "${!WG_CLIENT_IP_ADDR_FREE_ARRAY[@]}"; do
	NEW_FREE_ARRAY+=( "${WG_CLIENT_IP_ADDR_FREE_ARRAY[i]}" )
done
WG_CLIENT_IP_ADDR_FREE_ARRAY=("${NEW_FREE_ARRAY[@]}")
unset NEW_FREE_ARRAY


echo "Post allocation free IP address pool array: ${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} elements)"
echo



echo "###### Second allocation"

echo "Pre-allocation taken IP Address pool array: ${WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} elements)"
echo "Pre-allocation free IP Address pool array: ${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} elements)"
echo



NEXT_IP="$( alloc_IP ${WG_CLIENT_IP_ADDR_FREE_ARRAY} )"
echo "** Allocate next available (free) IP Address: ${NEXT_IP} "
echo

# echo "Add Next Available IP Address to TAKEN list"
WG_CLIENT_IP_ADDR_TAKEN_ARRAY+=("${NEXT_IP}")

echo "Post allocation taken IP address pool array: ${WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} elements)"

# echo "Remove allocated IP address from FREE list"
# WG_CLIENT_IP_ADDR_FREE_ARRAY=("${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]/$NEXT_IP}")

unset 'WG_CLIENT_IP_ADDR_FREE_ARRAY[0]'

for i in "${!WG_CLIENT_IP_ADDR_FREE_ARRAY[@]}"; do
        NEW_FREE_ARRAY+=( "${WG_CLIENT_IP_ADDR_FREE_ARRAY[i]}" )
done
WG_CLIENT_IP_ADDR_FREE_ARRAY=("${NEW_FREE_ARRAY[@]}")
unset NEW_FREE_ARRAY


echo "Post allocation free IP address pool array: ${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} elements)"
echo


echo "###### Third allocation"

echo "Pre-allocation taken IP Address pool array: ${WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} elements)"
echo "Pre-allocation free IP Address pool array: ${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} elements)"
echo



NEXT_IP="$( alloc_IP ${WG_CLIENT_IP_ADDR_FREE_ARRAY} )"
echo "** Allocate next available (free) IP Address: ${NEXT_IP} "
echo

# echo "Add Next Available IP Address to TAKEN list"
WG_CLIENT_IP_ADDR_TAKEN_ARRAY+=("${NEXT_IP}")

echo "Post allocation taken IP address pool array: ${WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_TAKEN_ARRAY[@]} elements)"

# echo "Remove allocated IP address from FREE list"
# WG_CLIENT_IP_ADDR_FREE_ARRAY=("${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]/$NEXT_IP}")
# rebuild array to remove indice gap
unset 'WG_CLIENT_IP_ADDR_FREE_ARRAY[0]'
for i in "${!WG_CLIENT_IP_ADDR_FREE_ARRAY[@]}"; do
        NEW_FREE_ARRAY+=( "${WG_CLIENT_IP_ADDR_FREE_ARRAY[i]}" )
done
WG_CLIENT_IP_ADDR_FREE_ARRAY=("${NEW_FREE_ARRAY[@]}")
unset NEW_FREE_ARRAY


echo "Post allocation free IP address pool array: ${WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} (${#WG_CLIENT_IP_ADDR_FREE_ARRAY[@]} elements)"
echo


