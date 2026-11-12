#!/bin/bash
#
# get_mname()
#
function get_mname() {
    #
    # get_mname <domain>
    # 
    # Returns MNAME field of DNS SOA record of <domain> parameter which is read as an arbitrary FQDN
    #   <domain> - any arbitrary Fully Qualified Domain Name
    #
    MNAME="`dig +nostats +noquestion +noanswer +nocmd +noadditional +nocomments +answer ${1} SOA | cut -f6 | cut -f1 -d' '`"
    echo ${MNAME}
}

if [[ -n ${TEST_GET_MNAME} ]]; then
	get_mname $1
fi
