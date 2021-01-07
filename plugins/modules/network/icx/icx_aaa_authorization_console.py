#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: icx_aaa_authorization_console
version_added: "2.10"
author: "Ruckus Wireless (@Commscope)"
short_description: Configures AAA authorization in Ruckus ICX 7000 series switches.
description:
	- Configures AAA authorization in Ruckus ICX 7000 series switches.
notes:
	- Tested against ICX 10.1
options:
    enable_console:
        description: Enables RADIUS Change of Authorization (CoA).
        suboptions:
            state:
                description: Specifies whether to configure or remove authorization.
                type: str
                default: present
                choices: ['present', 'absent']
    coa_ignore:
        description: Discards the specified RADIUS Change of Authorization (CoA) messages.
        suboptions:
            request:
                description: Specifies which message request to ignore.
                choices:  ['disable-port ','dm-request', 'flip-port', 'modify-acl', 'reauth-host']
                required: true
                type: string
            state:
                description: Specifies whether to configure or remove authorization.
                type: str
                default: present
                choices: ['present', 'absent']
    commands:
        description: Configures the AAA authorization configuration parameters for EXEC commands.
        suboptions:
            privilege_level:
                description: Configures the device to perform AAA authorization for the commands available at the specified privilege level. Valid values are 0 (Super User level - all commands), 4 (Port Configuration level - port-config and read-only commands), and 5 (Read Only level -read-only commands)
                type: int
                required:true
                choices: [0,4,5]
            primary_method:
                description: primary authorization method.
                type: string
                required: true
                choices: ['radius','tacacs+','none']
            backup_method1:
                description: backup authorization method if primary method fails.
                type: string
                choices: ['radius','tacacs+','none']
            backup_method2:
                description: bacup authorization method if primary and backup1 methods fail.
                type: string
                choices: ['none']
            state:
                description: Specifies whether to configure or remove authorization.
                type: str
                default: present
                choices: ['present', 'absent']
    exec:
        description: Determines the user privilege level when users are authenticated.
        suboptions:
            primary_method:
                description: primary authorization method.
                type: string
                required:true
                choices: ['radius','tacacs+','none']
            backup_method1:
                description: backup authorization method if primary method fails.
                type: string
                choices: ['radius','tacacs+','none']
            backup_method2:
                description: bacup authorization method if primary and backup1 methods fail.
                type: string
                choices: ['none']
            state:
                description: Specifies whether to configure or remove authorization.
                type: str
                default: present
                choices: ['present', 'absent']
"""

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import ConnectionError,exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, coa_ignore=None, enable_console=None, commands=None, exec_=None):
    """
    Function to build the command to send to the terminal for the switch
    to execute. All args come from the module's unique params.
    """
    cmds= [] 
    if coa_ignore is not None:
        if coa_ignore['state'] == 'absent':
            cmd = "no aaa authorization coa ignore {}".format(coa_ignore['request'])      
        else:
            cmd = "aaa authorization coa ignore {}".format(coa_ignore['request'])  
        cmds.append(cmd) 
    
    if enable_console is not None:
        if enable_console['state'] == 'absent':
            cmd = "no aaa authorization coa enable"
        else:
            cmd = "aaa authorization coa enable"
        cmds.append(cmd)


    if commands is not None:
        if commands['state'] == 'absent':
            cmd = "no aaa authorization commands {} default".format(commands['privilege_level'])      
        else:
            cmd = "aaa authorization commands {} default".format(commands['privilege_level'])      

        if commands['primary_method'] is not None:
            cmd+= " {}".format(commands['primary_method'])
            if commands['backup_method1'] is not None:
                cmd+= " {}".format(commands['backup_method1'])
                if commands['backup_method2'] is not None:
                    cmd+= " {}".format(commands['backup_method2'])
        cmds.append(cmd)

    if exec_ is not None:
        if exec_['state'] == 'absent':
            cmd = "no aaa authorization exec default"
        else:
            cmd = "aaa authorization exec default"      

        if exec_['primary_method'] is not None:
            cmd+= " {}".format(exec_['primary_method'])
            if exec_['backup_method1'] is not None:
                cmd+= " {}".format(exec_['backup_method1'])
                if exec_['backup_method2'] is not None:
                    cmd+= " {}".format(exec_['backup_method2'])
        cmds.append(cmd)


    return cmds

def main():
    """entry point for module execution
    """

    coa_ignore_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        request=dict(type='str',required=True, choices=['disable-port', 'dm-request', 'flip-port' ,'modify-acl' , 'reauth-host'])
    )
    enable_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    commands_spec = dict(
        privilege_level=dict(type='int', required=True, choices=[0,4,5]),
        primary_method=dict(type='str', required=True, choices=['radius', 'tacacs+', 'none']),
        backup_method1=dict(type='str', choices=['radius', 'tacacs+', 'none']),
        backup_method2=dict(type='str', choices=['none']),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    exec_spec = dict(
        primary_method=dict(type='str', required=True, choices=['radius', 'tacacs+', 'none']),
        backup_method1=dict(type='str', choices=['radius', 'tacacs+', 'none']),
        backup_method2=dict(type='str', choices=['none']),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    argument_spec = dict(
        coa_ignore = dict(type='dict', options=coa_ignore_spec),
        enable_console = dict(type='dict', options=enable_spec),
        commands = dict(type='dict', options=commands_spec),
        exec_ = dict(type='dict', options=exec_spec)
    )

    required_one_of = [['coa_ignore', 'enable_console', 'commands', 'exec_']]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=required_one_of,
                           supports_check_mode=True)

    warnings = list()
    results = {'changed': False}
    coa_ignore = module.params["coa_ignore"]
    enable_console = module.params["enable_console"]
    commands = module.params["commands"]
    exec_ = module.params["exec_"]

    if warnings:
        results['warnings'] = warnings

    commands = build_command(module, coa_ignore, enable_console, commands, exec_)
    results['commands'] = commands

    if commands:
        if not module.check_mode:
            response = load_config(module, commands)


        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()