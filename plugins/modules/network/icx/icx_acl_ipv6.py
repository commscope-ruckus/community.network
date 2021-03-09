#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: icx_acl
author: "Ruckus Wireless (@Commscope)"
short_description: Configures ACL in Ruckus ICX 7000 series switches.
description:
  - Configures ACL in Ruckus ICX 7000 series switches.
notes:
  - Tested against ICX 10.1
options:
  acl_name:
    description: Specifies a unique ACL name.
    type: str
  rule:
    description: Inserts filtering rules in IPv6 access control lists
    type: list
    element: dict
    suboptions: 
      seq_num:
        description: Enables you to assign a sequence number to the rule. Valid values range from 1 through 65000.
        type: int
      rule_type:
        description: Inserts filtering rules in IPv4 standard named or numbered ACLs that will deny/permit packets.
        type: string
        choices: ['deny', 'permit']
      ip_protocol_name:
        description: Specifies the type of IPv6 packet to filter.
        type: str
        choices: ['ahp', 'esp', 'icmp', 'ipv6', 'sctp', 'tcp', 'udp']
      ip_protocol_num:
        description: Protocol number (from 0 to 255).
        type: int            
      source:
        description: (ipv6-source-prefix/prefix-length | host source-ipv6_address | any)
        type: dict
        required: true
        suboptions:
          host_ipv6_address:
            description: Specifies a host source IPv6 address. A prefix length of 128 is implied.
            type: str
            default: no            
          ipv6_prefix_prefix_length:
            description: Specifies a source prefix and prefix length that a packet must match for the specified action (deny or permit) to occur. 
            type: str
          any:
            description: Specifies all source addresses.
            type: bool
            default: no            
      destination:
        description: ipv6-source-prefix/prefix-length | host source-ipv6_address | any. 
        type: dict
        required: true
        suboptions:
          host_ipv6_address:
            description: Specifies a host destination IPv6 address. A prefix length of 128 is implied.
            type: str
            default: no            
          ipv6_prefix_prefix_length:
            description: Specifies a destination prefix and prefix length that a packet must match for the specified action (deny or permit) to occur. 
            type: str
          any:
            description: Specifies all destination addresses.
            type: bool
            default: no 
      source_comparison_operators:
        description: If you specified tcp or udp, the following optional operators are available. Specify either port number or name for the operation. 
        type: dict
        suboptions:
          operator:
            description: Specifies comparison operator.
            type: str  
            choices: ['eq','gt','lt','neq','range']    
          port_num:
            description: Specifies port numbers that satisfy the operation with the port number you enter.
            type: int
          port_name:
            description: Specifies port numbers that satisfy the operation with the numeric equivalent of the port name.
            type: str
            choices: ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']
          high_port_num:
            description: For range operator, specifies high port number.
            type: int
          high_port_name:
            description: For range operator, specifies higher port name.
            type: str
            choices: ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']  
      destination_comparison_operators:
        description: If you specified tcp or udp, the following optional operators are available. Specify either port number or name for the operation. 
        type: dict
        suboptions:
          operator:
            description: Specifies comparison operator.
            type: str  
            choices: ['eq','gt','lt','neq','range']    
          port_num:
            description: Specifies port numbers that satisfy the operation with the port number you enter.
            type: int
          port_name:
            description: Specifies port numbers that satisfy the operation with the numeric equivalent of the port name.
            type: str
            choices: ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']
          high_port_num:
            description: For range operator, specifies high port number.
            type: int
          high_port_name:
            description: For range operator, specifies higher port name.
            type: str
            choices: ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']          
      established:
        description: (For TCP rules only) Filter packets that have the Acknowledgment (ACK) or Reset (RST) flag set.
        type: bool
        default: no
      icmp_num:
        description: Specifies a numbered message type. Use either icmp_num or icmp_type.
        type: int
      icmp_type:
        description: Specifies icmp type.
        type: str  
        choices: ['beyond-scope','destination-unreachable','echo-reply','echo-request','header','hop-limit','mld-query','mld-reduction','mld-report','nd-na','nd-ns','next-header','no-admin','no-route','packet-too-big','parameter-option','parameter-problem','port-unreachable','reassembly-timeout','renum-command','renum-result','renum-seq-number','router-advertisement','router-renumbering','router-solicitation','time-exceeded','unreachable']   
      fragments:
        description: Filters on IPv6 fragments with a non-zero fragment offset. Available only in IPv6 ACLs.
        type: bool
        default: no                            
      routing:
        description: Filters on IPv6 packets routed from the source. Available only in IPv6 ACLs.
        type: bool
        default: no   
      dscp_matching_dscp_value:
        description: Filters by DSCP value. Values range from 0 through 63.
        type: int
      dscp_marking_dscp_value:
        description: Assigns the DSCP value that you specify to the packet. Values range from 0 through 63.
        type: int
      802.1p_priority_matching_value:
        description: Filters by 802.1p priority, for rate limiting. Values range from 0 through 7.
        type: int
      802.1p_priority_marking_value:
        description: Assigns the 802.1p value that you specify to the packet. Values range from 0 through 7.
        type: int
      internal_priority_marking_queuing_priority:
        description: Assigns the identical 802.1p value and internal queuing priority (traffic class) that you specify to the packet [0-7]
        type: int
      802.1p_and_internal_marking_priority_value:
        description: Assigns the identical 802.1p value and internal queuing priority (traffic class) that you specify to the packet [0-7]
        type: int
      traffic_policy_name:
        description: Enables the device to limit rate of inbound traffic and to count packets and bytes per packet to which ACL deny clauses are applied.
        type: str
      log:
        type: bool
        default: no
      mirror:
        type: bool
        default: no
      state:
        description: Specifies whether to configure or remove rule.
        type: str
        default: present
        choices: ['present', 'absent']
  state:
    description: Create/Remove an IPv6 access control list (ACL).
    type: str
    default: present
    choices: ['present', 'absent']
"""

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import ConnectionError,exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, acl_name= None, rule = None, state= None):

    acl_cmds = []
    rules_acl_cmds = [] 
    if state == 'absent':
        cmd = "no ipv6 access-list {}".format(acl_name)
    else:
        cmd = "ipv6 access-list {}".format(acl_name)
    acl_cmds.append(cmd)

    if rule is not None:
        for elements in rule:              
            if elements['ip_protocol_name'] == "icmp":
                if elements['seq_num'] is not None:
                    if elements['state'] == 'absent':
                        cmd = "no sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                    else:
                        cmd = "sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                else:
                    if elements['state'] == 'absent':
                        cmd = "no {}".format(elements['rule_type'])
                    else:
                        cmd = " {}".format(elements['rule_type'])

                if elements['ip_protocol_name'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_name'])
                elif elements['ip_protocol_num'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_num'])
                if elements['source']['host_ipv6_address'] is not None:
                    cmd+=" host {}".format(elements['source']['host_ipv6_address'])
                elif elements['source']['ipv6_prefix_prefix_length'] is not None:
                    cmd+=" {}".format(elements['source']['ipv6_prefix_prefix_length'])
                elif elements['source']['any'] is not None:
                    cmd+= " any"
                if elements['destination']['host_ipv6_address'] is not None:
                    cmd+= " host {}".format(elements['destination']['host_ipv6_address'])
                elif elements['destination']['ipv6_prefix_prefix_length'] is not None:
                    cmd+= " {}".format(elements['destination']['ipv6_prefix_prefix_length'])
                elif elements['destination']['any'] is not None:
                    cmd+= " any"              
                if elements['icmp_num'] is not None:
                    cmd+= " {}".format(elements['icmp_num'])
                elif elements['icmp_type'] is not None:
                    cmd+= " {}".format(elements['icmp_type'])
                if elements['dscp_matching_dscp_value'] is not None:
                    cmd+= " dscp-matching {}".format(elements['dscp_matching_dscp_value'])
                if elements['dscp_marking_dscp_value'] is not None:
                    cmd+= " dscp-marking {}".format(elements['dscp_marking_dscp_value'])
                if elements['traffic_policy_name'] is not None:
                    cmd+=" traffic-policy {}".format(elements['traffic_policy_name'])
                if elements['log']:
                    cmd+= " log"
                if elements['mirror']:
                    cmd+= " mirror"
                rules_acl_cmds.append(cmd)

            elif elements['ip_protocol_name'] == "ipv6":
                if elements['seq_num'] is not None:
                    if elements['state'] == 'absent':
                        cmd = "no sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                    else:
                        cmd = "sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                else:
                    if elements['state'] == 'absent':
                        cmd = "no {}".format(elements['rule_type'])
                    else:
                        cmd = " {}".format(elements['rule_type'])

                if elements['ip_protocol_name'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_name'])
                elif elements['ip_protocol_num'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_num'])
                if elements['source']['host_ipv6_address'] is not None:
                    cmd+=" host {}".format(elements['source']['host_ipv6_address'])
                elif elements['source']['ipv6_prefix_prefix_length'] is not None:
                    cmd+=" {}".format(elements['source']['ipv6_prefix_prefix_length'])
                elif elements['source']['any'] is not None:
                    cmd+= " any"
                if elements['destination']['host_ipv6_address'] is not None:
                    cmd+= " host {}".format(elements['destination']['host_ipv6_address'])
                elif elements['destination']['ipv6_prefix_prefix_length'] is not None:
                    cmd+= " {}".format(elements['destination']['ipv6_prefix_prefix_length'])
                elif elements['destination']['any'] is not None:
                    cmd+= " any" 
                if elements['fragments']:
                    cmd+=" fragments"
                elif elements['routing']:
                    cmd+=" routing"
                if elements['dscp_matching_dscp_value'] is not None:
                    cmd+=" dscp-matching {}".format(elements['dscp_matching_dscp_value'])
                if elements['priority_matching_value'] is not None:
                    cmd+=" 802.1p-priority-matching {}".format(elements['priority_matching_value'])                  
                if elements['dscp_marking_dscp_value'] is not None:
                    cmd+=" dscp-marking {}".format(elements['dscp_marking_dscp_value'])
                if elements['priority_marking_value'] is not None:
                    cmd+= " 802.1p-priority-marking {}".format(elements['priority_marking_value'])
                    if elements['internal_priority_marking_queuing_priority'] is not None:
                        cmd+= " internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])
                elif elements['internal_priority_marking_queuing_priority'] is not None:
                    cmd+= " internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])
                elif elements['traffic_policy_name'] is not None:
                    cmd+= " traffic-policy {}".format(elements['traffic_policy_name'])
                if elements['log']:
                    cmd+= " log"
                if elements['mirror']:
                    cmd+= " mirror"
                
                rules_acl_cmds.append(cmd)

            elif (elements['ip_protocol_name'] == "tcp") or (elements['ip_protocol_name'] == "udp") :
                if elements['seq_num'] is not None:
                    if elements['state'] == 'absent':
                        cmd = "no sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                    else:
                        cmd = "sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                else:
                    if elements['state'] == 'absent':
                        cmd = "no {}".format(elements['rule_type'])
                    else:
                        cmd = " {}".format(elements['rule_type'])
                if elements['ip_protocol_name'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_name'])
                elif elements['ip_protocol_num'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_num'])
                if elements['source']['host_ipv6_address'] is not None:
                    cmd+=" host {}".format(elements['source']['host_ipv6_address'])
                elif elements['source']['ipv6_prefix_prefix_length'] is not None:
                    cmd+=" {}".format(elements['source']['ipv6_prefix_prefix_length'])
                elif elements['source']['any'] is not None:
                    cmd+= " any"           
                if elements['source_comparison_operators'] is not None:         
                    if elements['source_comparison_operators']['operator'] is not None:
                        cmd+=" {}".format(elements['source_comparison_operators']['operator'])
                        if elements['source_comparison_operators']['port_num'] is not None:
                            cmd+=" {}".format(elements['source_comparison_operators']['port_num'])
                        elif elements['source_comparison_operators']['port_name'] is not None :
                            cmd+=" {}".format(elements['source_comparison_operators']['port_name'])
                        if elements['source_comparison_operators']['high_port_num'] is not None:
                            cmd+=" {}".format(elements['source_comparison_operators']['high_port_num'])
                        elif elements['source_comparison_operators']['high_port_name'] is not None:
                            cmd+=" {}".format(elements['destination_comparison_operators']['high_port_name'])
                if elements['destination']['host_ipv6_address'] is not None:
                    cmd+=" host {}".format(elements['destination']['host_ipv6_address'])
                elif elements['destination']['ipv6_prefix_prefix_length'] is not None:
                    cmd+=" {}".format(elements['destination']['ipv6_prefix_prefix_length'])
                elif elements['destination']['any'] is not None:
                    cmd+= " any"  
                if elements['destination_comparison_operators'] is not None: 
                    if elements['destination_comparison_operators']['operator'] is not None:
                        cmd+= " {}".format(elements['destination_comparison_operators']['operator'])
                        if elements['destination_comparison_operators']['port_num'] is not None:
                            cmd+= " {}".format(elements['destination_comparison_operators']['port_num'])
                        elif elements['destination_comparison_operators']['port_name'] is not None:
                            cmd+= " {}".format(elements['destination_comparison_operators']['port_name'])
                        if elements['destination_comparison_operators']['high_port_num'] is not None:
                            cmd+= " {}".format(elements['destination_comparison_operators']['high_port_num'])
                        elif elements['destination_comparison_operators']['high_port_name'] is not None:
                            cmd+=" {}".format(elements['destination_comparison_operators']['high_port_name'])
                if elements['established']:
                    cmd+= " established"
                if elements['dscp_matching_dscp_value'] is not None:
                    cmd+= " dscp-matching {}".format(elements['dscp_matching_dscp_value'])
                if elements['priority_matching_value'] is not None:
                    cmd+= " 802.1p-priority-matching {}".format(elements['priority_matching_value'])
                if elements['dscp_marking_dscp_value'] is not None:
                    cmd+= " dscp-marking {}".format(elements['dscp_marking_dscp_value'])
                if elements['priority_marking_value'] is not None:
                    cmd+= " 802.1p-priority-marking {}".format(elements['priority_marking_value'])
                    if elements['internal_priority_marking_queuing_priority'] is not None:
                        cmd+= " internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority']) 
                elif elements['internal_priority_marking_queuing_priority'] is not None:
                    cmd+= " internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])                
                elif elements['traffic_policy_name'] is not None:
                    cmd+= " traffic-policy {}".format(elements['traffic_policy_name'])
                if elements['log']:
                    cmd+= " log"
                if elements['mirror']:
                    cmd+= " mirror"  
                rules_acl_cmds.append(cmd) 

            else: 
                if elements['seq_num'] is not None:
                    if elements['state'] == 'absent':
                        cmd = "no sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                    else:
                        cmd = "sequence {}".format(elements['seq_num'])
                        if elements['rule_type'] is not None:
                            cmd+= " {}".format(elements['rule_type'])
                else:
                    if elements['state'] == 'absent':
                        cmd = " no {}".format(elements['rule_type'])
                    else:
                        cmd = " {}".format(elements['rule_type'])

                if elements['ip_protocol_name'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_name'])
                elif elements['ip_protocol_num'] is not None:
                    cmd+= " {}".format(elements['ip_protocol_num'])
                if elements['source']['host_ipv6_address'] is not None:
                    cmd+=" host {}".format(elements['source']['host_ipv6_address'])
                elif elements['source']['ipv6_prefix_prefix_length'] is not None:
                    cmd+=" {}".format(elements['source']['ipv6_prefix_prefix_length'])
                elif elements['source']['any'] is not None:
                    cmd+= " any"       
                if elements['destination']['host_ipv6_address'] is not None:
                    cmd+=" host {}".format(elements['destination']['host_ipv6_address'])
                elif elements['destination']['ipv6_prefix_prefix_length'] is not None:
                    cmd+=" {}".format(elements['destination']['ipv6_prefix_prefix_length'])
                elif elements['destination']['any'] is not None:
                    cmd+= " any"
                if elements['dscp_matching_dscp_value'] is not None:
                    cmd+= " dscp-matching {}".format(elements['dscp_matching_dscp_value'])
                if elements['priority_matching_value'] is not None:
                    cmd+= " 802.1p-priority-matching {}".format(elements['priority_matching_value'])
                if elements['dscp_marking_dscp_value'] is not None:
                    cmd+= " dscp-marking {}".format(elements['dscp_marking_dscp_value'])
                if elements['priority_marking_value'] is not None:
                    cmd+= " 802.1p-priority-marking {}".format(elements['priority_marking_value'])
                    if elements['internal_priority_marking_queuing_priority'] is not None:
                        cmd+= " internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])
                elif elements['internal_priority_marking_queuing_priority'] is not None:
                    cmd+= " internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])  
                elif elements['traffic_policy_name'] is not None:
                    cmd+= " traffic-policy {}".format(elements['traffic_policy_name'])
                if elements['log']:
                    cmd+= " log"
                if elements['mirror']:
                    cmd+= " mirror"
                rules_acl_cmds.append(cmd)

    cmds = acl_cmds + rules_acl_cmds

    return cmds          
            


def main():
    """entry point for module execution
    """ 
    source_spec = dict(
        host_ipv6_address=dict(type='str'),
        ipv6_prefix_prefix_length=dict(type='str'),
        any=dict(type='bool', default='no')
    )
    source_comparison_operators_spec = dict(
        operator=dict(type='str',  choices = ['eq','gt','lt','neq','range']),
        port_num=dict(type='int'),
        port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']),
        high_port_num=dict(type='int'),
        high_port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl'])
    )
    destination_spec = dict(
        host_ipv6_address=dict(type='str'),
        ipv6_prefix_prefix_length=dict(type='str'),
        any=dict(type='bool', default='no')
    )
    destination_comparison_operators_spec = dict(
        operator=dict(type='str', choices = ['eq','gt','lt','neq','range']),
        port_num=dict(type='int'),
        port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']),
        high_port_num=dict(type='int'),
        high_port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl'])
    )  
    rule_spec = dict(
        seq_num = dict(type='int'),
        rule_type = dict(type='str', choices=['deny', 'permit']),
        ip_protocol_name = dict(type='str', choices=['ahp', 'esp', 'icmp', 'ipv6', 'sctp', 'tcp', 'udp']),
        ip_protocol_num = dict(type='int'),
        source = dict(type='dict',required = True, options=source_spec),
        source_comparison_operators = dict(type='dict', options=source_comparison_operators_spec),
        destination = dict(type='dict', required = True, options=destination_spec),
        established = dict(type='bool', default='no'),
        destination_comparison_operators = dict(type='dict', options=destination_comparison_operators_spec),
        icmp_num = dict(type='int'),
        icmp_type = dict(type='str',choices = ['beyond-scope','destination-unreachable','echo-reply','echo-request','header','hop-limit','mld-query','mld-reduction','mld-report','nd-na','nd-ns','next-header','no-admin','no-route','packet-too-big','parameter-option','parameter-problem','port-unreachable','reassembly-timeout','renum-command','renum-result','renum-seq-number','router-advertisement','router-renumbering','router-solicitation','time-exceeded','unreachable']),
        fragments = dict(type='bool', default='no'),
        routing = dict(type='bool', default='no'),
        dscp_matching_dscp_value = dict(type='int'),
        dscp_marking_dscp_value = dict(type='int'),
        priority_matching_value = dict(type='int'),
        priority_marking_value = dict(type='int'),
        internal_priority_marking_queuing_priority = dict(type='int'),
        traffic_policy_name = dict(type='str'),
        log = dict(type='bool', default= 'no'),
        mirror = dict(type='bool', default= 'no'),
        state= dict(type='str', default='present', choices=['present', 'absent'])      
    )

    argument_spec = dict(
        acl_name= dict(type='str'),
        rule= dict(type='list', elements='dict', options=rule_spec),
        state= dict(type='str', default='present', choices=['present', 'absent'])
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    
    warnings = list()
    results = {'changed': False}
    acl_name = module.params["acl_name"]
    rule = module.params.get('rule')
    state = module.params["state"]

    if warnings:
        result['warnings'] = warnings 
    commands = build_command(module, acl_name, rule, state)
    results['commands'] = commands

    if commands:
        if not module.check_mode:
            response = load_config(module, commands)


        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()

