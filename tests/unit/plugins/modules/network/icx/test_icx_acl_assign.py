# Copyright: (c) 2019, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.network.tests.unit.compat.mock import patch
from ansible_collections.community.network.plugins.modules.network.icx import icx_acl_assign
from ansible_collections.community.network.tests.unit.plugins.modules.utils import set_module_args
from .icx_module import TestICXModule, load_fixture


class TestICXAclAssignModule(TestICXModule):
    ''' Class used for Unit Tests agains icx_acl_assign module '''
    module = icx_acl_assign

    def setUp(self):
        super(TestICXAclAssignModule, self).setUp()
        self.mock_load_config = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_acl_assign.load_config')
        self.load_config = self.mock_load_config.start()
        self.mock_exec_command = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_acl_assign.exec_command')
        self.exec_command = self.mock_exec_command.start()

    def tearDown(self):
        super(TestICXAclAssignModule, self).tearDown()
        self.mock_load_config.stop()
        self.mock_exec_command.stop()

    def load_fixtures(self, commands=None):
        self.load_config.return_value = None

    def test_icx_acl_assign_all_options(self):
        ''' Test for successful acl assign with all options'''
        set_module_args(dict(ip_access_group=dict(acl_num=1,acl_type='in',ethernet=['1/2/1','1/2/2'],to_ethernet='1/2/4',frag_deny='yes'),
                             mac_access_group=dict(mac_acl_name='mac',logging_enable='yes'),
                             ip_sg_access_group=dict(acl_name='sg-acl1'),
                             web_access_group=dict(acl_num='12'),
                             ssh_access_group=dict(acl_num='12'),
                             telnet_access_group=dict(acl_name='acl10')))
        expected_commands = [
            'ip access-group 1 in ethernet 1/2/1 ethernet 1/2/2 to 1/2/4',
            'ip access-group frag deny',
            'mac access-group mac in logging enable',
            'source-guard enable',
            'ip sg-access-group sg-acl1 in',
            'web access-group 12',
            'ssh access-group 12',
            'telnet access-group acl10'
            ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
       
    def test_icx_acl_assign_all_options_remove(self):
        ''' Test for removing acl assign with all options'''
        set_module_args(dict(ip_access_group=dict(acl_num=1,acl_type='in',ethernet=['1/2/1','1/2/2'],to_ethernet='1/2/4',frag_deny='yes',state='absent'),
                             mac_access_group=dict(mac_acl_name='mac',logging_enable='yes',state='absent'),
                             ip_sg_access_group=dict(acl_name='sg-acl1',state='absent'),
                             web_access_group=dict(acl_num='12',state='absent'),
                             ssh_access_group=dict(acl_num='12',state='absent'),
                             telnet_access_group=dict(acl_name='acl10',state='absent')))
        expected_commands = [
            'no ip access-group 1 in ethernet 1/2/1 ethernet 1/2/2 to 1/2/4',
            'no ip access-group frag deny',
            'no mac access-group mac in logging enable',
            'source-guard enable',
            'no ip sg-access-group sg-acl1 in',
            'no web access-group 12',
            'no ssh access-group 12',
            'no telnet access-group acl10'
            ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_assign_ip_access_group(self):
        ''' Test for successful ip_access_group'''
        set_module_args(dict(ip_access_group=dict(acl_num=1,acl_type='in',ethernet=['1/2/1','1/2/2'],to_ethernet='1/2/4',frag_deny='yes',state='present')))
        expected_commands = ['ip access-group 1 in ethernet 1/2/1 ethernet 1/2/2 to 1/2/4','ip access-group frag deny']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_assign_mac_access_group_ip_sg_access_group(self):
        ''' Test for successful mac_access_group and ip_sg_access_group'''
        set_module_args(dict(mac_access_group=dict(mac_acl_name='mac',logging_enable='yes',state='present'),ip_sg_access_group=dict(acl_name='sg-acl1',state='present')))
        expected_commands = ['mac access-group mac in logging enable','source-guard enable','ip sg-access-group sg-acl1 in']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_assign_web_access_group_ssh_access_group(self):
        ''' Test for successful web_access_group and ssh_access_group'''
        set_module_args(dict(web_access_group=dict(acl_num='12',state='present'),ssh_access_group=dict(acl_num='12',state='present')))
        expected_commands = ['web access-group 12','ssh access-group 12']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
   
    def test_icx_acl_assign_telnet_access_group(self):
        ''' Test for successful telnet_access_group'''
        set_module_args(dict(telnet_access_group=dict(acl_name='acl10',state='present')))
        expected_commands = ['telnet access-group acl10']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_assign_invalid_arg_ip_access_group(self):
        ''' Test for invalid acl_type'''
        set_module_args(dict(ip_access_group=dict(acl_num=1,acl_type='aa',ethernet=['1/2/1','1/2/2'],to_ethernet='1/2/4',frag_deny='yes',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_acl_assign_invalid_arg_mac_access_group(self):
        ''' Test for invalid logging_enable'''
        set_module_args(dict(mac_access_group=dict(mac_acl_name='mac',logging_enable='a',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_acl_assign_invalid_arg_ip_sg_access_group(self):
        ''' Test for invalid acl_num'''
        set_module_args(dict(ip_sg_access_group=dict(acl_num= 'a',state='present')))
        result = self.execute_module(failed=True)

    def test_icx_acl_assign_invalid_arg_web_access_group(self):
        ''' Test for invalid acl_num'''
        set_module_args(dict(ssh_access_group=dict(acl_num='a',state='present')))
        result = self.execute_module(failed=True) 