#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: icx_acl_ip
author: "Ruckus Wireless (@Commscope)"
short_description: Configures ACL in Ruckus ICX 7000 series switches.
description:
  - Configures ACL in Ruckus ICX 7000 series switches.
notes:
  - Tested against ICX 10.1
options:
  acl_type:
    description: Specifies standard/extended access control list. 
      Standard - Contains rules that permit or deny traffic based on source addresses that you specify. The rules are applicable to all ports of the specified address. 
      Extended - Contains rules that permit or deny traffic according to source and destination addresses, as well as other parameters. For example, you can also filter by port, protocol (TCP or UDP), and TCP flags.
    type: str
    required: true
    choices: ['standard','extended']         
  acl_name:
    description: Specifies a unique ACL name.
    type: str
  acl_id:
    description: Specifies a unique ACL number.
    type: int
  standard_rule:
    description: Inserts filtering rules in standard named or numbered ACLs that will deny or permit packets.
    type: list
    elements: dict
    suboptions:
      seq_num:
        description: Enables you to assign a sequence number to the rule. Valid values range from 1 through 65000.
        type: int
      rule_type:
        description: Inserts filtering rules in IPv4 standard named or numbered ACLs that will deny/permit packets.
        type: string
        required: true
        choices: ['deny', 'permit']
      host:
        description: Specifies the source as host.
        type: bool
        default: no            
      source_ip:
        description: Specifies a source address for which you want to filter the subnet. 
          Format - IPv4address/mask | IPv4 address | IPv6 address | ipv6-source-prefix/prefix-length
        type: str
      mask:
        description: Defines a mask, whose effect is to specify a subnet that includes the source address that you specified.
        type: str
      hostname:
        description: Specifies the known hostname of the source host
        type: str
      any:
        description: Specifies all source addresses.
        type: bool
        default: no   
      log:
        description: Enables logging for the rule. Used in conjunction with the logging enable command at the ip access-list command configuration level.
        type: bool
        default: no
      mirror:
        description: Mirrors packets matching the rule.
        type: bool
        default: no
      state:
        description: Specifies whether to configure or remove rule.
        type: str
        default: present
        choices: ['present', 'absent']        
  extended_rule: 
    description: Inserts filtering rules in extended named or numbered ACLs. Specify either protocol name or number.
    type: list
    element: dict
    suboptions:
      seq_num:
        description: Enables you to assign a sequence number to the rule. Valid values range from 1 through 65000.
        type: int
      rule_type:
        description: Inserts filtering rules in IPv4 standard named or numbered ACLs that will deny/permit packets.
        type: string
        required: true
        choices: ['deny', 'permit']
      ip_protocol_name:
        description: Specifies the type of IPv4 packet to filter.
        type: str
        choices: ['icmp','igmp','igrp','ip','ospf','tcp','udp']
      ip_protocol_num:
        description: Protocol number (from 0 to 255).
        type: int            
      source:
        description: {host hostname or A.B.C.D | A.B.C.D or A.B.C.D/L | any} 
        type: dict
        required: true
        suboptions:
          host:
            description: Specifies the source as host.
            type: bool
            default: no            
          ip_address:
            description: Specifies a source IPv4 address for which you want to filter the subnet. 
            type: str
          mask:
            description: Defines a mask, whose effect is to specify a subnet that includes the source address that you specified.
            type: str
          hostname:
            description: Specifies the known hostname of the source host
            type: str
          any:
            description: Specifies all source addresses.
            type: bool
            default: no            
      destination:
        description: {host hostname or A.B.C.D | A.B.C.D or A.B.C.D/L | any}
        type: dict
        required: true
        suboptions:
          host:
            description: Specifies the destination as host.
            type: bool
            default: no            
          ip_address:
            description: Specifies a destination address for which you want to filter the subnet.
              Format - IPv4address/mask | IPv4 address | IPv6 address | ipv6-source-prefix/prefix-length
            type: str
          mask:
            description: Defines a subnet mask that includes the destination address that you specified.
            type: str
          hostname:
            description: Specifies the known hostname of the destination host.
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
            description: Specifies comparison operator
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
        description: Specifies a numbered message type. Use this format if the rule also needs to include precedence, tos , one of the
            DSCP options, one of the 802.1p options, internal-priority-marking , or traffic-policy.
        type: int
      icmp_type:
        description: Specifies icmp type.
        type: str  
        choices: ['any-icmp-type','echo','echo-reply','information-request','mask-reply','mask-request','parameter-problem','redirect','source-quench','time-exceeded'',''timestamp-reply'',''timestamp-request'',''unreachable']   
      precedence:
        description: Specifies a precedence-name. 
          0 or routine - Specifies routine precedence.
          1 or priority - Specifies priority precedence.
          2 or immediate - Specifies immediate precedence.
          3 or flash - Specifies flash precedence.
          4 or flash-override - Specifies flash-override precedence.
          5 or critical - Specifies critical precedence.
          6 or internet - Specifies internetwork control precedence.
          7 or network - Specifies network control precedence.
        type: str  
        choices: ['routine','priority','immediate','flash','flash-override','critical','internet','network']  
      tos:
        description: Specifies a type of service (ToS). Enter either a supported tos-name or the equivalent tos-value.
          0 or normal - Specifies normal ToS.
          1 or min-monetary-cost - Specifies min monetary cost ToS.
          2 or max-reliability - Specifies max reliability ToS.
          4 or max-throughput - Specifies max throughput ToS.
          8 or min-delay - Specifies min-delay ToS.
        type: str  
        choices: ['normal','min-monetary-cost','max-reliability','max-throughput','min-delay']   
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
    description: Specifies whether to create or delete ACL.
    type: str
    default: present
    choices: ['present', 'absent']      
"""

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import ConnectionError,exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, acl_type= None, acl_name= None, acl_id= None, standard_rule = None, extended_rule= None, state= None):

    acl_cmds = []
    if state == 'absent':
        cmd = "no ip access-list {}".format(acl_type)
    else:
        cmd = "ip access-list {}".format(acl_type)
    if acl_name is not None:
        cmd+= " {}".format(acl_name)
    else:
        cmd+=" {}".format(acl_id)
    acl_cmds.append(cmd)

    extended_rule_cmds = []
    standard_rule_cmds = []
    if standard_rule is not None:
        for elements in standard_rule:
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
                    cmd = "{}".format(elements['rule_type'])

            if elements['host']:
                if elements['hostname'] is not None:
                    cmd+= " host {}".format(elements['hostname'])
                else:
                    cmd+=" host {}".format(elements['source_ip'])
            elif elements['any']:
                cmd+= " any"
            elif elements['hostname'] is not None:
                cmd+= " host {}".format(elements['hostname'])
                if elements['mask'] is not None:
                    cmd+= " {}".format(elements['mask'])
            else:
                cmd+=" {}".format(elements['source_ip'])
                if elements['mask'] is not None:
                    cmd+= " {}".format(elements['mask'])

            if elements['log']:
                cmd+= " log"      
            if elements['mirror']:
                cmd+= " mirror"
            standard_rule_cmds.append(cmd)


    if extended_rule is not None:
        for elements in extended_rule:              
            if elements['seq_num'] is not None:
                if elements['state'] == 'absent':
                    cmd = "no sequence {}".format(elements['seq_num'])
                    if elements['rule_type'] is not None:
                        cmd+=" {}".format(elements['rule_type'])
                else:
                    cmd = "sequence {}".format(elements['seq_num'])
                    if elements['rule_type'] is not None:
                        cmd+=" {}".format(elements['rule_type'])
            else:
                if elements['state'] == 'absent':
                    cmd = "no {}".format(elements['rule_type'])
                else:
                    cmd = "{}".format(elements['rule_type'])

            if elements['ip_protocol_name'] is not None:
                cmd+=" {}".format(elements['ip_protocol_name'])
            elif elements['ip_protocol_num'] is not None:
                cmd+=" {}".format(elements['ip_protocol_num'])
            if elements['source']['host']:
                if elements['source']['hostname'] is not None:
                    cmd+=" host {}".format(elements['source']['hostname'])
                elif elements['source']['ip_address'] is not None:
                    cmd+=" host {}".format(elements['source']['ip_address'])
            elif elements['source']['any']:
                cmd+=" any"
            else:
                if elements['source']['ip_address'] is not None:
                    cmd+=" {}".format(elements['source']['ip_address'])
                    if elements['source']['mask'] is not None:
                        cmd+=" {}".format(elements['source']['mask'])
            if (elements['ip_protocol_name'] == "tcp") or (elements['ip_protocol_name'] == "udp"):
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
            if elements['destination']['host']:
                if elements['destination']['hostname'] is not None:
                    cmd+=" host {}".format(elements['destination']['hostname'])
                elif elements['destination']['ip_address'] is not None:
                    cmd+=" host {}".format(elements['destination']['ip_address'])
            elif elements['destination']['any']:
                cmd+=" any"
            else:
                if elements['destination']['ip_address'] is not None:
                    cmd+=" {}".format(elements['destination']['ip_address'])
                    if elements['destination']['mask'] is not None:
                        cmd+=" {}".format(elements['destination']['mask'])    
            if elements['ip_protocol_name'] == "icmp":                       
                if elements['icmp_num'] is not None:
                    cmd+=" {}".format(elements['icmp_num'])
                elif elements['icmp_type'] is not None:
                    cmd+=" {}".format(elements['icmp_type'])
            if (elements['ip_protocol_name'] == "tcp") or (elements['ip_protocol_name'] == "udp"):
                if elements['destination_comparison_operators'] is not None: 
                    if elements['destination_comparison_operators']['operator'] is not None:
                        cmd+=" {}".format(elements['destination_comparison_operators']['operator'])
                        if elements['destination_comparison_operators']['port_num'] is not None:
                            cmd+=" {}".format(elements['destination_comparison_operators']['port_num'])
                        elif elements['destination_comparison_operators']['port_name'] is not None:
                            cmd+=" {}".format(elements['destination_comparison_operators']['port_name'])
                        if elements['destination_comparison_operators']['high_port_num'] is not None:
                            cmd+=" {}".format(elements['destination_comparison_operators']['high_port_num'])
                        elif elements['destination_comparison_operators']['high_port_name'] is not None:
                            cmd+=" {}".format(elements['destination_comparison_operators']['high_port_name'])
                if elements['established']:
                    cmd+=" established"
            if elements['precedence'] is not None:
                cmd+=" precedence {}".format(elements['precedence'])
            if elements['tos'] is not None:
                cmd+=" tos {}".format(elements['tos'])             
            if elements['dscp_matching_dscp_value'] is not None:
                cmd+=" dscp-matching {}".format(elements['dscp_matching_dscp_value'])
            if elements['priority_matching_value'] is not None:
                cmd+=" 802.1p-priority-matching {}".format(elements['priority_matching_value'])
            if elements['dscp_marking_dscp_value'] is not None:
                cmd+=" dscp-marking {}".format(elements['dscp_marking_dscp_value'])
            if elements['internal_marking_priority_value'] is not None:
                cmd+=" 802.1p-and-internal-marking {}".format(elements['internal_marking_priority_value'])
            elif elements['priority_marking_value'] is not None:
                cmd+=" 802.1p-priority-marking {}".format(elements['priority_marking_value'])
                if elements['internal_priority_marking_queuing_priority'] is not None:
                    cmd+=" internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])
                    if elements['log']:
                        cmd+=" log"
                        if elements['mirror']:
                            cmd+=" mirror"   
            elif elements['internal_priority_marking_queuing_priority'] is not None:
                cmd+=" internal-priority-marking {}".format(elements['internal_priority_marking_queuing_priority'])
                if elements['log']:
                    cmd+=" log"
                    if elements['mirror']:
                        cmd+=" mirror"               
            elif elements['traffic_policy_name'] is not None:
                cmd+=" traffic-policy {}".format(elements['traffic_policy_name'])
                if elements['log']:
                    cmd+=" log"
                    if elements['mirror']:
                        cmd+=" mirror"
            else:
                if elements['log']:
                    cmd+=" log"
                if elements['mirror']:
                    cmd+=" mirror"
                
            extended_rule_cmds.append(cmd)
    
    cmds = acl_cmds + standard_rule_cmds + extended_rule_cmds

    return cmds          
            


def main():
    """entry point for module execution
    """ 
    source_spec = dict(
        host = dict(type='bool', default='no'),
        ip_address = dict(type='str'),
        mask = dict(type='str'),
        hostname = dict(type='str'),
        any=dict(type='bool', default='no')
    )
    destination_spec = dict(
        host = dict(type='bool', default='no'),
        ip_address = dict(type='str'),
        mask = dict(type='str'),
        hostname = dict(type='str'),
        any=dict(type='bool', default='no')
    )
    source_comparison_operators_spec = dict(
        operator=dict(type='str',  choices = ['eq','gt','lt','neq','range']),
        port_num=dict(type='int'),
        port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']),
        high_port_num=dict(type='int'),
        high_port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl'])
    )
    destination_comparison_operators_spec = dict(
        operator=dict(type='str', choices = ['eq','gt','lt','neq','range']),
        port_num=dict(type='int'),
        port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl']),
        high_port_num=dict(type='int'),
        high_port_name=dict(type='str', choices = ['ftp-data','ftp','ssh','telnet','smtp','dns','http','gppitnp','pop2','pop3','sftp','sqlserv','bgp','ldap','ssl'])
    )  
    standard_rule_spec = dict(
        seq_num = dict(type='int'),
        rule_type = dict(type='str', choices=['deny', 'permit']),
        host = dict(type='bool', default='no'),
        source_ip = dict(type='str'),
        mask = dict(type='str'),
        hostname = dict(type='str'),
        any=dict(type='bool', default='no'),
        log = dict(type='bool', default= 'no'),
        mirror = dict(type='bool', default= 'no'),
        state= dict(type='str', default='present', choices=['present', 'absent'])      
    )
    extended_rule_spec = dict(
        seq_num = dict(type='int'),
        rule_type = dict(type='str', required= True, choices=['deny', 'permit']),
        ip_protocol_name = dict(type='str', choices=['icmp','igmp','igrp','ip','ospf','tcp','udp']),
        ip_protocol_num = dict(type='int'),
        source = dict(type='dict',required = True, options=source_spec),
        destination = dict(type='dict', required = True, options=destination_spec),
        source_comparison_operators = dict(type='dict', options=source_comparison_operators_spec),
        destination_comparison_operators = dict(type='dict', options=destination_comparison_operators_spec),
        established = dict(type='bool', default='no'),
        icmp_num = dict(type='int'),
        icmp_type = dict(type='str',choices = ['beyond-scope','destination-unreachable','echo-reply','echo-request','header','hop-limit','mld-query','mld-reduction','mld-report','nd-na','nd-ns','next-header','no-admin','no-route','packet-too-big','parameter-option','parameter-problem','port-unreachable','reassembly-timeout','renum-command','renum-result','renum-seq-number','router-advertisement','router-renumbering','router-solicitation','time-exceeded','unreachable']),
        precedence = dict(type='str',choices= ['routine','priority','immediate','flash','flash-override','critical','internet','network']),
        tos  = dict(type='str',choices= ['normal','min-monetary-cost','max-reliability','max-throughput','min-delay']),
        dscp_matching_dscp_value = dict(type='int'),
        dscp_marking_dscp_value = dict(type='int'),
        priority_matching_value = dict(type='int'),
        priority_marking_value = dict(type='int'),
        internal_priority_marking_queuing_priority = dict(type='int'),
        internal_marking_priority_value = dict(type='int'),
        traffic_policy_name = dict(type='str'),
        log = dict(type='bool', default= 'no'),
        mirror = dict(type='bool', default= 'no'),
        state= dict(type='str', default='present', choices=['present', 'absent'])      
    )
    argument_spec = dict(
        acl_type= dict(type='str', required = True, choices=['standard','extended']),
        acl_name= dict(type='str'),
        acl_id= dict(type='int'),
        standard_rule= dict(type='list', elements='dict', options=standard_rule_spec),
        extended_rule= dict(type='list', elements='dict', options=extended_rule_spec),
        state= dict(type='str', default='present', choices=['present', 'absent'])
    )
    required_one_of = [['acl_name','acl_id']]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of = required_one_of,
                           supports_check_mode=True)
    
    warnings = list()
    results = {'changed': False}
    acl_type = module.params["acl_type"]
    acl_name = module.params["acl_name"]
    acl_id = module.params["acl_id"]
    standard_rule = module.params.get("standard_rule")
    extended_rule = module.params.get("extended_rule")
    state = module.params["state"]

    if warnings:
        result['warnings'] = warnings 
    commands = build_command(module, acl_type, acl_name, acl_id, standard_rule, extended_rule, state)
    results['commands'] = commands

    if commands:
        if not module.check_mode:
            response = load_config(module, commands)


        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()