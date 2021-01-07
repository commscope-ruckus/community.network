# Copyright: (c) 2019, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.network.tests.unit.compat.mock import patch
from ansible_collections.community.network.plugins.modules.network.icx import icx_aaa_authentication_console
from ansible_collections.community.network.tests.unit.plugins.modules.utils import set_module_args
from .icx_module import TestICXModule, load_fixture


class TestICXAaaAuthenticationModule(TestICXModule):
    ''' Class used for Unit Tests agains icx_aaa_authentication_console module '''
    module = icx_aaa_authentication_console

    def setUp(self):
        super(TestICXAaaAuthenticationModule, self).setUp()
        self.mock_load_config = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_aaa_authentication_console.load_config')
        self.load_config = self.mock_load_config.start()
        self.mock_exec_command = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_aaa_authentication_console.exec_command')
        self.exec_command = self.mock_exec_command.start()

    def tearDown(self):
        super(TestICXAaaAuthenticationModule, self).tearDown()
        self.mock_load_config.stop()
        self.mock_exec_command.stop()

    def load_fixtures(self, commands=None):
        self.load_config.return_value = None
        

    def test_icx_aaa_authentication_all_options(self):
        ''' Test for successful aaa authentication with all options'''
        set_module_args(dict(dot1x=dict(primary_method='radius',backup_method1='none'),
                             enable=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+'),
                             login=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+'),
                             snmp_server=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+'),
                             web_server=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+')))
        expected_commands = ['aaa authentication dot1x default radius none',
                             'aaa authentication enable default enable line local none radius tacacs tacacs+',
                             'aaa authentication enable implicit-user',
                             'aaa authentication login default enable line local none radius tacacs tacacs+',
                             'aaa authentication login privilage-mode',
                             'aaa authentication snmp-server default enable line local none radius tacacs tacacs+',
                             'aaa authentication web-server default enable line local none radius tacacs tacacs+']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
        
    def test_icx_aaa_authentication_all_option_backup(self):
        ''' Test for successful aaa authentication with backup_method options'''
        set_module_args(dict(dot1x=dict(primary_method='radius',backup_method1='none'),
                             enable=dict(method_list='enable',method_list1='line'),
                             login=dict(method_list='enable',method_list1='line'),
                             snmp_server=dict(method_list='enable',method_list1='line'),
                             web_server=dict(method_list='enable',method_list1='line')))
        expected_commands = ['aaa authentication dot1x default radius none',
                             'aaa authentication enable default enable line',
                             'aaa authentication enable implicit-user',
                             'aaa authentication login default enable line',
                             'aaa authentication login privilage-mode',
                             'aaa authentication snmp-server default enable line',
                             'aaa authentication web-server default enable line']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_aaa_authentication_all_options_remove(self):
        ''' Test for removiong aaa authentication with all options'''
        set_module_args(dict(dot1x=dict(primary_method='radius',backup_method1='none',state='absent'),
                             enable=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+',state='absent'),
                             login=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+',state='absent'),
                             snmp_server=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+',state='absent'),
                             web_server=dict(method_list='enable',method_list1='line',method_list2='local',method_list3='none' ,method_list4='radius',method_list5='tacacs',method_list6='tacacs+',state='absent')))
        expected_commands = ['no aaa authentication dot1x default radius none',
                             'no aaa authentication enable default enable line local none radius tacacs tacacs+',
                             'no aaa authentication enable implicit-user',
                             'no aaa authentication login default enable line local none radius tacacs tacacs+',
                             'no aaa authentication login privilage-mode',
                             'no aaa authentication snmp-server default enable line local none radius tacacs tacacs+',
                             'no aaa authentication web-server default enable line local none radius tacacs tacacs+']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    
    def test_icx_aaa_authentication_all_option_backup_remove(self):
        ''' Test for removing aaa authentication with backup_method options'''
        set_module_args(dict(dot1x=dict(primary_method='radius',backup_method1='none',state='absent'),
                             enable=dict(method_list='enable',method_list1='line',state='absent'),
                             login=dict(method_list='enable',method_list1='line',state='absent'),
                             snmp_server=dict(method_list='enable',method_list1='line',state='absent'),
                             web_server=dict(method_list='enable',method_list1='line',state='absent')))
        expected_commands = ['no aaa authentication dot1x default radius none',
                             'no aaa authentication enable default enable line',
                             'no aaa authentication enable implicit-user',
                             'no aaa authentication login default enable line',
                             'no aaa authentication login privilage-mode',
                             'no aaa authentication snmp-server default enable line',
                             'no aaa authentication web-server default enable line']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_aaa_authentication_dot1x_enable(self):
        ''' Test for successful aaa authentication for dot1x'''
        set_module_args(dict(dot1x=dict(primary_method='radius',state='present'),enable=dict(method_list='enable',state='present')))
        expected_commands = ['aaa authentication dot1x default radius','aaa authentication enable default enable', 'aaa authentication enable implicit-user']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    

    def test_icx_aaa_authentication_login_snmp_server(self):
        ''' Test for successful aaa authentication for login and snmp_server'''
        set_module_args(dict(login=dict(method_list='line',state='present'),snmp_server=dict(method_list='enable',state='present')))
        expected_commands = ['aaa authentication login default line','aaa authentication login privilage-mode','aaa authentication snmp-server default enable']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_aaa_authentication_web_server(self):
        ''' Test for successful aaa authentication for web_server'''
        set_module_args(dict(web_server=dict(method_list='tacacs',state='present')))
        expected_commands = ['aaa authentication web-server default tacacs']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_aaa_authentication_invalid_args_dot1x(self):
        ''' Test for invalid primary_method'''
        set_module_args(dict(dot1x=dict(primary_method='aaa',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_aaa_authentication_invalid_args_enable(self):
        ''' Test for invalid method_list'''
        set_module_args(dict(enable=dict(method_list='aaa',method_list1='line',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_aaa_authentication_invalid_args_login(self):
        ''' Test for invalid method_list1'''
        set_module_args(dict(login=dict(method_list='enable',method_list1='aaa',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_aaa_authentication_invalid_args_snmp_server(self):
        ''' Test for invalid method_list1'''
        set_module_args(dict(snmp_server=dict(method_list='enable',method_list1='aaa',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_aaa_authentication_invalid_args_web_server(self):
        ''' Test for invalid method_list2'''
        set_module_args(dict(web_server=dict(method_list='enable',method_list1='line',method_list2='aaaa',state='present')))
        result = self.execute_module(failed=True)                           



    

