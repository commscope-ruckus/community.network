# Copyright: (c) 2019, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.network.tests.unit.compat.mock import patch
from ansible_collections.community.network.plugins.modules.network.icx import icx_acl_default_standard
from ansible_collections.community.network.tests.unit.plugins.modules.utils import set_module_args
from .icx_module import TestICXModule, load_fixture


class TestICXAclDefaultStandardModule(TestICXModule):
    ''' Class used for Unit Tests agains icx_aaa_accounting_console module '''
    module = icx_acl_default_standard

    def setUp(self):
        super(TestICXAclDefaultStandardModule, self).setUp()
        self.mock_load_config = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_acl_default_standard.load_config')
        self.load_config = self.mock_load_config.start()
        self.mock_exec_command = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_acl_default_standard.exec_command')
        self.exec_command = self.mock_exec_command.start()

    def tearDown(self):
        super(TestICXAclDefaultStandardModule, self).tearDown()
        self.mock_load_config.stop()
        self.mock_exec_command.stop()

    def load_fixtures(self, commands=None): 
	    self.load_config.return_value = None

    def test_icx_acl_default_standard_all_options(self):
        ''' Test for successful acl default standard with all options'''
        set_module_args(dict(default_acl=dict(ip_type='ipv6',acl_name_or_id='guest',auth_type='in'),
                             standard_acl=dict(rule_type='permit',source_address_type='source',source_ip_address='10.157.29.12',log='yes',mirror='yes')))
        expected_commands = ['authentication',
                             'default-acl ipv6 guest in',     
                             'ip access-list standard 11',
                             'permit 10.157.29.12 log mirror'        
                             ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
        
    def test_icx_acl_default_standard_all_options_remove(self):
        ''' Test for removing acl default standard with all options'''
        set_module_args(dict(default_acl=dict(ip_type='ipv6',acl_name_or_id='guest',auth_type='in',state='absent'),
                             standard_acl=dict(rule_type='permit',source_address_type='source',source_ip_address='10.157.29.12',log='yes',mirror='yes',state='absent')))
        expected_commands = [
            'authentication',
            'no default-acl ipv6 guest in',
            'ip access-list standard 11',
            'no permit 10.157.29.12 log mirror'
            ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_default_acl(self):
        ''' Test for successful default acl'''
        set_module_args(dict(default_acl=dict(ip_type='ipv4',acl_name_or_id='guest',auth_type='out',state='present')))
        expected_commands = ['authentication','default-acl ipv4 guest out']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    
    def test_icx_standard_permit_acl(self):
        ''' Test for successful standard permit acl'''
        set_module_args(dict(standard_acl=dict(rule_type='permit',source_address_type='source',source_ip_address='10.157.29.12',mirror='yes',state='present')))
        expected_commands = ['ip access-list standard 11','permit 10.157.29.12 mirror']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_standard_deny_acl(self):
        ''' Test for successful standard deny acl'''
        set_module_args(dict(standard_acl=dict(rule_type='deny',source_address_type='host',source_ip_address='10.157.29.12',log='yes',state='present')))
        expected_commands = ['ip access-list standard 4','deny host 10.157.29.12 log']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_invalid_args_default_acl(self):
        ''' Test for invalid auth_type '''
        set_module_args(dict(default_acl=dict(ip_type='ipv4',acl_name_or_id='guest',auth_type='aa',state='present')))
        result = self.execute_module(failed=True)

    def test_icx__invalid_args_standard_acl(self):
        ''' Test for invalid rule_type'''
        set_module_args(dict(standard_acl=dict(rule_type='aaa',source_address_type='source',source_ip_address='10.157.29.12',log='yes',mirror='yes',state='present')))
        result = self.execute_module(failed=True)