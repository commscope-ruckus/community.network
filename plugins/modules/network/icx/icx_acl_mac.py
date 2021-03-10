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
  acl_id:
    description: Specifies a unique ACL number.
    type: int
  rule:
    description: Inserts filtering rules in mac access control list
    type: list
    element: dict
    suboptions:     
      rule_type:
        description: Inserts filtering rules in IPv4 standard named or numbered ACLs that will deny/permit packets.
        type: str
        choices: ['deny', 'permit']   
      source:  
        description: {source_mac_address soource_mask | any }
        type: dict
        suboptions:             
          source_mac_address:
            description: HHHH.HHHH.HHHH Source Ethernet MAC address.
            type: str  
          source_mask:
            description: HHHH.HHHH.HHHH Source mask
            type: str           
          any:
            description: Matches any.
            type: bool
            default: no  
      destination:  
        description: {destination_mac_address destination_mask | any }
        type: dict
        suboptions:             
          destination_mac_address:
            description: HHHH.HHHH.HHHH Destination Ethernet MAC address.
            type: str  
          destination_mask:
            description: HHHH.HHHH.HHHH Destination mask
            type: str           
          any:
            description: Matches any.
            type: bool
            default: no     
      log:
        type: bool
        default: no
      mirror:
        type: bool
        default: no
      ether_type:
        description: Specifies whether to configure or remove rule.
        type: str
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

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import ConnectionError, exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, acl_name=None, acl_id=None, rule=None, state=None):
    """
    Function to build the command to send to the terminal for the switch
    to execute. All args come from the module's unique params.
    """

    acl_cmds = []
    if state == 'absent':
        cmd = "no mac access-list {}".format(acl_name)
    else:
        cmd = "mac access-list {}".format(acl_name)

    acl_cmds.append(cmd)

    rule_acl_cmds = []
    if rule is not None:
        for elements in rule:
            if elements['state'] == 'absent':
                if elements['rule_type'] == 'deny':
                    cmd = "no deny"
                else:
                    cmd = "no permit"
            else:
              if elements['rule_type'] == 'deny':
                cmd = "deny"
              else:
                cmd = "permit"

            if elements['source']['source_mac_address'] is not None:
                cmd+= " {}".format(elements['source']['source_mac_address'])
                if elements['source']['source_mask'] is not None:
                    cmd+= " {}".format(elements['source']['source_mask'])
            elif elements['source']['any'] is not None:
                cmd+= " any"
            if elements['destination']['destination_mac_address'] is not None:
                cmd+= " {}".format(elements['destination']['destination_mac_address'])
                if elements['destination']['destination_mask'] is not None:
                    cmd+= " {}".format(elements['destination']['destination_mask'])
            elif elements['destination']['any'] is not None:
                cmd+= " any"
            if elements['ether_type']:
                cmd+= "ether-type {}".format(elements['ether_type'])
            if elements['log']:
                cmd+= " log"
            if elements['mirror']:
                cmd+= " mirror"
            
            rule_acl_cmds.append(cmd)

    cmds = 	acl_cmds + rule_acl_cmds
    return cmds	


def main():
    """ main entry point for module execution
    """
    
    source_spec = dict(
        source_mac_address = dict(type='str'),
        source_mask = dict(type='str'),
        any = dict(type='bool', default='False')
    )

    destination_spec = dict(
        destination_mac_address = dict(type='str'),
        destination_mask = dict(type='str'),
        any = dict(type='bool', default='False')
    )

    rule_spec = dict(
        rule_type = dict(type='str', choices=['deny', 'permit']),
        source = dict(type='dict', options=source_spec),
        destination = dict(type='dict', options=destination_spec),
        log = dict(type='bool', default='False'),
        mirror = dict(type='bool', default='False'),
        ether_type = dict(type='str'),
        state = dict(type='str', default='present', choices=['present', 'absent'])
    )

    argument_spec = dict(
        acl_name = dict(type='str'),
        acl_id = dict(type='int'),
        rule = dict(type='list', elements='dict', options=rule_spec),
        state = dict(type='str', default='present', choices=['present', 'absent'])
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    warnings = list()
    results = {'changed': False}
    acl_name = module.params["acl_name"]
    acl_id = module.params["acl_id"]
    rule = module.params["rule"]
    state = module.params["state"]
    

    if warnings:
        results['warnings'] = warnings

    commands = build_command(module, acl_name, acl_id, rule, state)
    results['commands'] = commands

    if commands:
        if not module.check_mode:
            response = load_config(module, commands)

        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()

    
