#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: icx_acl_assign
author: "Ruckus Wireless (@Commscope)"
short_description: Configures ACL in Ruckus ICX 7000 series switches.
description:
  - Configures ACL Assign in Ruckus ICX 7000 series switches.
notes:
  - Tested against ICX 10.1
options:
  ip_access_group:
    description: Applies IPv4 access control lists (ACLs) to traffic entering or exiting an interface.
    type: dict
    suboptions:
      acl_num:
        description: Specifies an ACL number. You can specify from 1 through 99 for standard ACLs and from 100 through 199 for extended ACLs.
        type: int  
      acl_name:
        description: Specifies a valid ACL name.
        type: str
      acl_type:
        description: Applies the ACL to inbound or outbound traffic on the port.
        type: str
        choices: ['in','out'] 
      ethernet:
        description: Specifies the list of Ethernet interface from which the packets are coming. [unit / slot / port]
        type: list       
      to_ethernet:
        description: Specifies the range of Ethernet interfaces from which the packets are coming. [unit / slot / port]
        type: str     
      frag_deny:
        description: Denies all IP fragments on the port.
        type: bool       
        default: no
      state:
        description: Specifies whether to configure or remove ip access-group.
        type: str
        default: present
        choices: ['present', 'absent']
  mac_access_group:
    description: Binds an access-list filter to an interface.
    type: dict
    suboptions:
      mac_acl_name:
        description: MAC ACL name.
        type: str  
        required: true
      logging_enable:
        description: Allows logging of any matched statement within the applied mac access-list that contains a log action.
        type: bool
        default: no
      state:
        description: Specifies whether to configure or remove MAC access-group.
        type: str
        default: present
        choices: ['present', 'absent']
  ip_sg_access_group:
    description: Binds an ingress IPv4 access control list (ACL) meant for IP Source Guard (IPSG) ports (SG ACL) to a port or VLAN.
    type: dict
    suboptions:
      acl_name:
        description: Specifies the IPSG ACL to be bound to the interface.
        type: str      
      ethernet:
        description: Specifies the Ethernet interface and the interface ID in the unit/slot/port format.  [unit / slot / port]
        type: str       
      to_ethernet:
        description: Specifies a range of Ethernet interfaces. [unit / slot / port]
        type: str
      lag_id:
        description: Specifies the LAG virtual interface.
        type: int
      to_lag_id:
        description: Specifies a range of LAG IDs.
        type: int           
      state:
        description: Specifies whether to configure or remove ip sg-access-group.
        type: str
        default: present
        choices: ['present', 'absent']
  web_access_group:
    description: Configures an ACL that restricts web management access to the device.
    type: dict
    suboptions:
      acl_num:
        description: The standard access list number. The valid values are 1 through 99.
        type: int
      acl_name:
        description: The standard access list name.
        type: str   
      ipv6_acl_name:
        description: The IPv6 access list name.
        type: str   
      state:
        description: Specifies whether to configure or remove web access-group.
        type: str
        default: present
        choices: ['present', 'absent']
  ssh_access_group:
    description: Configures an ACL that restricts SSH access to the device.
    type: dict
    suboptions:
      acl_num:
        description: The standard access list number. The valid values are from 1 through 99.
        type: int
      acl_name:
        description: The standard access list name.
        type: str   
      ipv6_acl_name:
        description: The IPv6 access list name.
        type: str   
      state:
        description: Specifies whether to configure or remove ssh access-group.
        type: str
        default: present
        choices: ['present', 'absent']
  telnet_access_group:
    description: Configures an ACL that restricts Telnet access to the device.
    type: dict
    suboptions:
      acl_num:
        description: The standard access list number. The valid values are from 1 through 99.
        type: int
      acl_name:
        description: The standard access list name.
        type: str   
      ipv6_acl_name:
        description: The IPv6 access list name.
        type: str   
      state:
        description: Specifies whether to configure or remove telnet access-group.
        type: str
        default: present
        choices: ['present', 'absent']
"""

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import ConnectionError,exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, ip_access_group=None, mac_access_group=None, ip_sg_access_group=None, web_access_group=None, ssh_access_group=None, telnet_access_group=None):
    """
    Function to build the command to send to the terminal for the switch
    to execute. All args come from the module's unique params.
    """

    cmds= [] 
    
    if ip_access_group is not None:
        if ip_access_group['state'] == 'absent':
            cmd = "no ip access-group"
        else:
            cmd = "ip access-group"
        if ip_access_group['acl_num'] is not None:
            cmd+=" {} {}".format(ip_access_group['acl_num'],ip_access_group['acl_type'])
        else:
             cmd+=" {} {}".format(ip_access_group['acl_name'],ip_access_group['acl_type'])
        if ip_access_group['acl_type'] == 'in':
            if ip_access_group['ethernet'] is not None:
                cmd+= " ethernet "+" ethernet ".join(ip_access_group['ethernet']) 
                if ip_access_group['to_ethernet'] is not None:
                    cmd+=" to {}".format(ip_access_group['to_ethernet'])
            cmds.append(cmd)
    
        if ip_access_group['frag_deny'] is not None:
            if ip_access_group['state'] == 'absent':
                cmd = "no ip access-group frag deny"
            else:
                cmd = "ip access-group frag deny"     
        cmds.append(cmd)

    if mac_access_group is not None:
        if mac_access_group['state'] == 'absent':
            cmd = "no mac access-group {} in".format(mac_access_group['mac_acl_name'])     
        else:
            cmd = "mac access-group {} in".format(mac_access_group['mac_acl_name']) 
        if mac_access_group['logging_enable'] is not None:
            cmd+=" {}".format("logging enable")
        cmds.append(cmd)

    ip_sg_access_group_cmds= []

    if ip_sg_access_group is not None:
        ip_sg_access_group_cmds = ['source-guard enable']
        if ip_sg_access_group['state'] == 'absent':
            cmd = "no ip sg-access-group {} in".format(ip_sg_access_group['acl_name'])   
        else:
            cmd = "ip sg-access-group {} in".format(ip_sg_access_group['acl_name'])
        if ip_sg_access_group['ethernet'] is not None:
            cmd+=" ethernet {}".format(ip_sg_access_group['ethernet'])
            if ip_sg_access_group['to_ethernet'] is not None:
                cmd+=" to {}".format(ip_sg_access_group['to_ethernet'])
                if ip_sg_access_group['lag_id'] is not None:
                    cmd+=" lag {}".format(ip_sg_access_group['lag_id'])
                    if ip_sg_access_group['to_lag_id'] is not None:
                        cmd+=" to {}".format(ip_sg_access_group['to_lag_id'])

        ip_sg_access_group_cmds.append(cmd)
        cmds = cmds + ip_sg_access_group_cmds

    if web_access_group is not None:
        if web_access_group['state'] == 'absent':
            cmd = "no web access-group"    
        else:
             cmd = "web access-group" 
        if web_access_group['acl_num'] is not None:
             cmd+=" {}".format(web_access_group['acl_num'])
        elif web_access_group['acl_name'] is not None:
             cmd+=" {}".format(web_access_group['acl_name']) 
        else:
             cmd+=" ipv6 {}".format(web_access_group['ipv6_acl_name']) 
        cmds.append(cmd)
        
    if ssh_access_group is not None:
        if ssh_access_group['state'] == 'absent':
            cmd = "no ssh access-group"    
        else:
            cmd = "ssh access-group" 
        if ssh_access_group['acl_num'] is not None:
            cmd+=" {}".format(ssh_access_group['acl_num'])
        elif ssh_access_group['acl-name'] is not None:
            cmd+=" {}".format(ssh_access_group['acl_name']) 
        else:
            cmd+=" ipv6 {}".format(ssh_access_group['ipv6_acl_name']) 
        cmds.append(cmd)
    
    if telnet_access_group is not None:
        if telnet_access_group['state'] == 'absent':
            cmd = "no telnet access-group"    
        else:
            cmd = "telnet access-group" 
        if telnet_access_group['acl_num'] is not None:
            cmd+=" {}".format(telnet_access_group['acl_num'])
        elif telnet_access_group['acl_name'] is not None:
            cmd+=" {}".format(telnet_access_group['acl_name']) 
        else:
            cmd+=" ipv6 {}".format(telnet_access_group['ipv6_acl_name']) 
        cmds.append(cmd)

    return cmds

def main():
    """entry point for module execution
    """

    ip_access_group_spec = dict(
        acl_num=dict(type='int'), 
        acl_name=dict(type='str'),
        acl_type=dict(type='str', choices=['in','out']),
        ethernet=dict(type='list'),
        to_ethernet=dict(type='str'),
        frag_deny=dict(type='bool', default='no'),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    mac_access_group_spec = dict(
        mac_acl_name=dict(type='str', required=True),
        logging_enable=dict(type='bool', default='no'),
        state=dict(type='str', default='present', choices=['present', 'absent']),
    )
    ip_sg_access_group_spec = dict(
        acl_name=dict(type='str'),
        ethernet=dict(type='str'),
        to_ethernet=dict(type='str'),
        lag_id=dict(type='int'),
        to_lag_id=dict(type='int'),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    web_access_group_spec = dict(
        acl_num=dict(type='int'), 
        acl_name=dict(type='str'),
        ipv6_acl_name=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    ssh_access_group_spec = dict(
        acl_num=dict(type='int'), 
        acl_name=dict(type='str'),
        ipv6_acl_name=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    telnet_access_group_spec = dict(
        acl_num=dict(type='int'), 
        acl_name=dict(type='str'),
        ipv6_acl_name=dict(type='str'),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    argument_spec = dict(
        ip_access_group = dict(type='dict', options=ip_access_group_spec),
        mac_access_group = dict(type='dict', options=mac_access_group_spec),
        ip_sg_access_group = dict(type='dict', options=ip_sg_access_group_spec),
        web_access_group = dict(type='dict', options=web_access_group_spec),
        ssh_access_group = dict(type='dict', options=ssh_access_group_spec),
        telnet_access_group = dict(type='dict', options=telnet_access_group_spec)
    )

    required_one_of = [['ip_access_group', 'mac_access_group', 'ip_sg_access_group', 'web_access_group', 'ssh_access_group', 'telnet_access_group']]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=required_one_of,
                           supports_check_mode=True)

    warnings = list()
    results = {'changed': False}
    ip_access_group = module.params["ip_access_group"]
    mac_access_group= module.params["mac_access_group"]
    ip_sg_access_group = module.params["ip_sg_access_group"]
    web_access_group = module.params["web_access_group"]
    ssh_access_group = module.params["ssh_access_group"]
    telnet_access_group = module.params["telnet_access_group"]

    if warnings:
        results['warnings'] = warnings

    commands = build_command(module, ip_access_group, mac_access_group, ip_sg_access_group, web_access_group, ssh_access_group, telnet_access_group)
    results['commands'] = commands

    if commands:
        if not module.check_mode:
            response = load_config(module, commands)


        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()