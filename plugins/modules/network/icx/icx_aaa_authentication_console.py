#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = """
---
module: icx_aaa_authentication_console
version_added: "2.10"
author: Ruckus Wireless (@Commscope)
short_description: Configures AAA authentication in Ruckus ICX 7000 series switches
description:
  - Configures AAA authentication in Ruckus ICX 7000 series switches.
notes:
  - Tested against ICX 10.1
options:
    dot1x
      description: Enables 802.1X and MAC authentication.
      [Default: (null)]
      suboptions:
        primary_method:
          description: primary authentication method.
          type: string
          required: true
          choices: ['radius','none']
        backup_method1:
          description: backup authentication method if primary method fails.
          type: string
          choices: ['none'] 
        state:
          description: Specifies whether to configure or remove authentication.
          type: str
          default: present
          choices: ['present', 'absent']
    enable
      description: Configures the AAA authentication method for securing access to the Privileged EXEC level and global configuration levels of the CLI. Only one of method-list or implicit-user should be provided. If the configured primary authentication fails due to an error, the device tries the backup authentication methods in the order they appear in the list.
      [Default: (null)]
      suboptions:
        method_list:
          description: Configures following authentication methods. You can configure up to six backup authentication methods.
          type: list 
          required: true     
          choices: ['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']
        implicit_user:
          description: Configures the device to prompt only for a password when a user attempts to gain Super User access to the Privileged EXEC and global configuration levels of the CLI.
          type: bool
          default: true
        state:
          description: Specifies whether to configure or remove the authentication method.
          type: str   
          default: present           
          choices: ['present', 'absent']
    login
      description: Configures the AAA authentication method for securing access to the Privileged EXEC level and global configuration levels of the CLI. Only one of metod-list or implicit-user should be provided.
      [Default: (null)]
      suboptions:
        method_list:
          description: Configures following authentication methods. You can configure up to six backup authentication methods.
          type: list
          required: true
          choices: ['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']
        privilege_mode: 
          description: Configures the device to enter the privileged EXEC mode after a successful login through Telnet or SSH..       
          type: bool
          default: true      
        state:
          description: Specifies whether to configure or remove the authentication method.
          type: str
          default: present
          choices: ['present', 'absent']
    snmp_server
      description: Configures the AAA authentication method for SNMP server access.  
      [Default: (null)] 
      suboptions:
        method_list:
          description: Configures following authentication methods. You can configure up to six backup authentication methods.
          type: list
          required: true
          choices: ['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']
        state:
          description: Specifies whether to configure or remove the authentication method.
          type: str
          default: present
          choices: ['present', 'absent']
    web_server
      description: Configures the AAA authentication method to access the device through the Web Management Interface.
      [Default: (null)]
      suboptions:
        method_list:
          description: Configures following authentication methods. You can configure up to six backup authentication methods.
          type: list
          required: true
          choices: ['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']
        state:
          description: Specifies whether to configure or remove the authentication method.
          type: str
          default: present
          choices: ['present', 'absent']
"""

EXAMPLES = """

- name: aaa authentication commands for dot1x and enable
  community.network.icx_aaa_authentication_console:
    dot1x:
      primary_method: none
      state: present
    enable:
      method_list: local
      method_list1: radius
      state: present
- name: aaa authentication commands for snmp_server
  community.network.icx_aaa_authentication_console:
    system:
      method_list: local
      method_list1: radius
      method_list2: none
      state: absent
"""
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.connection import ConnectionError,exec_command
from ansible_collections.community.network.plugins.module_utils.network.icx.icx import load_config

def build_command(module, dot1x=None, enable=None, login=None, snmp_server=None, web_server=None):
    """
    Function to build the command to send to the terminal for the switch
    to execute. All args come from the module's unique params.
    """
    cmds= [] 
    if dot1x is not None:
        if dot1x['state'] == 'absent':
            cmd = "no aaa authentication dot1x default"   
        else:
            cmd = "aaa authentication dot1x default"   
        if dot1x['primary_method'] is not None:
            cmd+= " {}".format(dot1x['primary_method'])
            if dot1x['backup_method1'] is not None:
                cmd+= " {}".format(dot1x['backup_method1'])
        cmds.append(cmd)

    if enable is not None:
        if enable['method_list'] is not None:
            if enable['state'] == 'absent':
                cmd = "no aaa authentication enable default {}".format(enable['method_list'])
            else:
                cmd = "aaa authentication enable default {}".format(enable['method_list'])
            if enable['method_list1'] is not None:
                cmd+= " {}".format(enable['method_list1'])
                if enable['method_list2'] is not None:
                    cmd+= " {}".format(enable['method_list2'])
                    if enable['method_list3'] is not None:
                        cmd+= " {}".format(enable['method_list3'])
                        if enable['method_list4'] is not None:
                            cmd+= " {}".format(enable['method_list4'])
                            if enable['method_list5'] is not None:
                                cmd+= " {}".format(enable['method_list5'])
                                if enable['method_list6'] is not None:
                                    cmd+= " {}".format(enable['method_list6'])
            cmds.append(cmd)
        if enable['implicit_user'] is not None:
            if enable['state'] == 'absent':
               cmd = "no aaa authentication enable implicit-user"
            else:
               cmd = "aaa authentication enable implicit-user"
            cmds.append(cmd)

    if login is not None:
        if login['method_list'] is not None:
            if login['state'] == 'absent':
                cmd = "no aaa authentication login default {}".format(login['method_list'])
            else:
                cmd = "aaa authentication login default {}".format(login['method_list'])
            if login['method_list1'] is not None:
                cmd+= " {}".format(login['method_list1'])
                if login['method_list2'] is not None:
                    cmd+= " {}".format(login['method_list2'])
                    if login['method_list3'] is not None:
                        cmd+= " {}".format(login['method_list3'])
                        if login['method_list4'] is not None:
                          cmd+= " {}".format(login['method_list4'])
                          if login['method_list5'] is not None:
                                cmd+= " {}".format(login['method_list5'])
                                if login['method_list6'] is not None:
                                  cmd+= " {}".format(login['method_list6'])    
            cmds.append(cmd)
        if login['privilage_mode'] is not None:
            if login['state'] == 'absent':
               cmd = "no aaa authentication login privilage-mode"
            else:
               cmd = "aaa authentication login privilage-mode" 
            cmds.append(cmd)

    if snmp_server is not None:
        if snmp_server['state'] == 'absent':
            cmd = "no aaa authentication snmp-server default {}".format(snmp_server['method_list'])
        else:
            cmd = "aaa authentication snmp-server default {}".format(snmp_server['method_list'])   
        if snmp_server['method_list1'] is not None:
            cmd+= " {}".format(snmp_server['method_list1'])
            if snmp_server['method_list2'] is not None:
                cmd+= " {}".format(snmp_server['method_list2'])
                if snmp_server['method_list3'] is not None:
                    cmd+= " {}".format(snmp_server['method_list3'])
                    if snmp_server['method_list4'] is not None:
                        cmd+= " {}".format(snmp_server['method_list4'])
                        if snmp_server['method_list5'] is not None:
                            cmd+= " {}".format(snmp_server['method_list5'])
                            if snmp_server['method_list6'] is not None:
                                cmd+= " {}".format(snmp_server['method_list6'])
        cmds.append(cmd)

    if web_server is not None:
        if web_server['state'] == 'absent':
            cmd = "no aaa authentication web-server default {}".format(web_server['method_list'])
        else:
            cmd = "aaa authentication web-server default {}".format(web_server['method_list'])      
        if web_server['method_list1'] is not None:
            cmd+= " {}".format(web_server['method_list1'])
            if web_server['method_list2'] is not None:
                cmd+= " {}".format(web_server['method_list2'])
                if web_server['method_list3'] is not None:
                    cmd+= " {}".format(web_server['method_list3'])
                    if web_server['method_list4'] is not None:
                        cmd+= " {}".format(web_server['method_list4'])
                        if web_server['method_list5'] is not None:
                            cmd+= " {}".format(web_server['method_list5'])
                            if web_server['method_list6'] is not None:
                                cmd+= " {}".format(web_server['method_list6'])
        cmds.append(cmd)   

    return cmds

def main():
    """entry point for module execution
    """ 
    dot1x_spec = dict(
        primary_method=dict(type='str', required=True, choices=['radius','none']),
        backup_method1=dict(type='str', choices=['none']),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    enable_spec = dict(
        method_list=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list1=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list2=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list3=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list4=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list5=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list6=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        implicit_user=dict(type='bool', default=True),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    login_spec = dict(
        method_list=dict(type='str', required=True, choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list1=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list2=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list3=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list4=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list5=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list6=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        privilage_mode=dict(type='bool', default=True),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    snmp_server_spec = dict(
        method_list=dict(type='str', required=True, choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list1=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list2=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list3=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list4=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list5=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list6=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    web_server_spec = dict(
        method_list=dict(type='str', required=True, choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list1=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list2=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list3=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list4=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        method_list5=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']), 
        method_list6=dict(type='str', choices=['enable', 'line', 'local', 'none', 'radius', 'tacacs', 'tacacs+']),
        state=dict(type='str', default='present', choices=['present', 'absent'])
    )
    argument_spec = dict(
        dot1x = dict(type='dict', options=dot1x_spec),
        enable = dict(type='dict', options=enable_spec),
        login = dict(type='dict', options=login_spec),
        snmp_server = dict(type='dict', options=snmp_server_spec),
        web_server = dict(type='dict', options=web_server_spec)
    )

    required_one_of = [['dot1x', 'enable', 'login', 'snmp_server','web_server']]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=required_one_of,
                           supports_check_mode=True)

    warnings = list()
    results = {'changed': False}
    dot1x = module.params["dot1x"]
    enable = module.params["enable"]
    login = module.params["login"]
    snmp_server = module.params["snmp_server"]
    web_server = module.params["web_server"]

    if warnings:
        result['warnings'] = warnings 
    commands = build_command(module, dot1x, enable, login, snmp_server, web_server )
    results['commands'] = commands

    if commands:
        if not module.check_mode:
                response = load_config(module, commands)
        results['changed'] = True

    module.exit_json(**results)

if __name__ == '__main__':
    main()