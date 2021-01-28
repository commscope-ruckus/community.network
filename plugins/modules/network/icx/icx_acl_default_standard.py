#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: icx_acl_default_standard
author: "Ruckus Wireless (@Commscope)"
short_description: Configures ACL in Ruckus ICX 7000 series switches.
description:
  - Configures ACL in Ruckus ICX 7000 series switches.
notes:
  - Tested against ICX 10.1
options:
  default_acl:
    description: Configures the default ACL for failed, timed-out, or guest user sessions.
    type: dict
    suboptions:
      ip_type:
        description: Specifies an IPv4 or IPv6 ACL.
        type: str
        required: true
        choices: ['ipv4', 'ipv6'] 
      acl_name_or_id:
        description: acl-id |acl-name (ID of standard or numbered ACL (IPv4 only)|Name or extended name of the ACL).
        type: str
      auth_type:
        description: Specifies incoming or outgoing authentication.
        type: str
        choices: ['in', 'out'] 
      state:
        description: Specifies whether to configure or remove rule.
        type: str
        default: present
        choices: ['present', 'absent']
  standard_acl:
    description: Inserts filtering rules in standard named or numbered ACLs that will deny or permit packets.
    type: dict
    suboptions:
      rule_type:
        description: Inserts filtering rules in IPv4 standard named or numbered ACLs that will deny/permit packets.
        type: str
        choices: ['deny', 'permit']
      source_address_type:
        description: Specifies the type of source address.
        type: str
        choices: ['source', 'host', 'any']
      source_ip_address:
        description: Specifies a source address for which you want to filter the subnet.
        type: str
      mask:
        description: Defines a subnet mask to be applied to the source address you specified.
        type: str
      hostname:
        description: Specifies the known hostname associated with a particular source IP address.
        type: str      
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
 """

EXAMPLES = """
- name: Configure default acl
  community.network.icx_acl_default_standard:
    default_acl:
      ip_type: ipv4
      acl_name_or_id: guest
      auth_type: in
      state: present

- name: Configure standard acl
  community.network.icx_acl_default_standard:
    standard_acl:
      rule_type: deny
      source_address_type: source
      source_ip_address: 10.157.29.12
      log: yes
      state: present

"""

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import ConnectionError,exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, default_acl=None, standard_acl=None):
    """
    Function to build the command to send to the terminal for the switch
    to execute. All args come from the module's unique params.
    """
    default_cmds= [] 
    standard_cmds= []
    if default_acl is not None:
        default_cmds= ['authentication'] 
        if default_acl['state'] == 'absent':
            cmd = "no default-acl {}".format(default_acl['ip_type'])      
        else:
            cmd = "default-acl {}".format(default_acl['ip_type'])      

        if default_acl['acl_name_or_id'] is not None:
            cmd+= " {}".format(default_acl['acl_name_or_id'])
        if default_acl['auth_type'] is not None:
            cmd+= " {}".format(default_acl['auth_type'])
        default_cmds.append(cmd)

    if standard_acl is not None:
        if standard_acl['state'] == 'absent':
            if standard_acl['rule_type'] == 'deny':
                standard_cmds= ['ip access-list standard 4']
                cmd = "no deny"      
            else:
                standard_cmds= ['ip access-list standard 11']
                cmd = "no permit"
        else:
            if standard_acl['rule_type'] == 'deny':
                standard_cmds= ['ip access-list standard 4']
                cmd = "deny"      
            else:
                standard_cmds= ['ip access-list standard 11']
                cmd = "permit" 

        if standard_acl['source_address_type'] == 'source':
            cmd+=" {}".format(standard_acl['source_ip_address'])
            if standard_acl['mask'] is not None:
                cmd+= " {}".format(standard_acl['mask'])
        elif standard_acl['source_address_type'] == 'host':
            if standard_acl['hostname'] is not None:
                cmd+= " host {}".format(standard_acl['hostname'])
            else:
                cmd+=" host {}".format(standard_acl['source_ip_address'])
                if standard_acl['mask'] is not None:
                    cmd+= " {}".format(standard_acl['mask'])
        else:
            cmd+= " any"

        if standard_acl['log']:
            cmd+= " log"
        
        if standard_acl['mirror']:
            cmd+= " mirror"
        standard_cmds.append(cmd)

    cmds = default_cmds + standard_cmds
    return cmds

def main():
    """entry point for module execution
    """
    default_acl_spec = dict(
        ip_type=dict(type='str', required=True, choices=['ipv4', 'ipv6']),
        acl_name_or_id=dict(type='str'),
        auth_type=dict(type='str', choices=['in', 'out']),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    standard_acl_spec = dict(
        rule_type=dict(type='str', choices=['deny', 'permit']),
        source_address_type=dict(type='str', choices=['source', 'host', 'any']),
        source_ip_address=dict(type='str'),
        mask=dict(type='str'),
        hostname=dict(type='str'),
        log=dict(type='bool', default='False'),
        mirror=dict(type='bool', default='False'),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    argument_spec = dict(
        default_acl = dict(type='dict', options=default_acl_spec),
        standard_acl = dict(type='dict', options=standard_acl_spec)
    )

    required_one_of = [['default_acl', 'standard_acl']]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=required_one_of,
                           supports_check_mode=True)

    warnings = list()
    results = {'changed': False}
    default_acl = module.params["default_acl"]
    standard_acl = module.params["standard_acl"]

    if warnings:
        results['warnings'] = warnings

    commands = build_command(module, default_acl, standard_acl)
    results['commands'] = commands

    if commands:
        if not module.check_mode:
            response = load_config(module, commands)

        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()