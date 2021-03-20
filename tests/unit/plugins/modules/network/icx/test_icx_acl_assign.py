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
        set_module_args(dict(ip_access_group=dict(acl_num='123', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes'),
                             ipv6_access_group=dict(acl_num='1', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes'),
                             mac_access_group=dict(mac_acl_name='mac_acl1', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable'),
                             default_acl=dict(ip_type='ipv4',acl_name='guest', in_out='in')))
        expected_commands = [
            'vlan 555',
            'tagged ethernet 1/1/2',
            'ip access-group 123 in ethernet 1/1/2 lag 25 logging enable',
            'ip access-group frag deny',
            'vlan 555',
            'tagged ethernet 1/1/2',
            'ipv6 access-group 1 in ethernet 1/1/2 lag 25 logging enable',
            'ipv6 access-group frag deny',
            'vlan 555',
            'tagged ethernet 1/1/2',
            'mac access-group mac_acl1 in ethernet 1/1/2 lag 25 logging enable',
            'authentication',
            'default-acl ipv4 guest in'
            ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
       
    def test_icx_acl_assign_all_options_remove(self):
        ''' Test for removing acl assign with all options'''
        set_module_args(dict(ip_access_group=dict(acl_num='123', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes', state='absent'),
                             ipv6_access_group=dict(acl_num='1', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes', state='absent'),
                             mac_access_group=dict(mac_acl_name='mac_acl1', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', state='absent'),
                             default_acl=dict(ip_type='ipv4',acl_name='guest', in_out='in', state='absent')))
        expected_commands = [
            'vlan 555',
            'tagged ethernet 1/1/2',
            'no ip access-group 123 in ethernet 1/1/2 lag 25 logging enable',
            'no ip access-group frag deny',
            'vlan 555',
            'tagged ethernet 1/1/2',
            'no ipv6 access-group 1 in ethernet 1/1/2 lag 25 logging enable',
            'no ipv6 access-group frag deny',
            'vlan 555',
            'tagged ethernet 1/1/2',
            'no mac access-group mac_acl1 in ethernet 1/1/2 lag 25 logging enable',
            'authentication',
            'no default-acl ipv4 guest in'
            ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_assign_ip_access_group(self):
        ''' Test for successful ip_access_group'''
        set_module_args(dict(ip_access_group=dict(acl_name='scale12', acl_num='123', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes')))
        expected_commands = ['vlan 555','tagged ethernet 1/1/2', 'ip access-group 123 in ethernet 1/1/2 lag 25 logging enable','ip access-group frag deny']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_assign_ipv6_access_group(self):
        ''' Test for successful ipv6_access_group'''
        set_module_args(dict(ipv6_access_group=dict(acl_name='scale123', acl_num='123', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes')))
        expected_commands = ['vlan 555','tagged ethernet 1/1/2', 'ipv6 access-group 123 in ethernet 1/1/2 lag 10 logging enable','ipv6 access-group frag deny']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    
    def test_icx_acl_assign_mac_access_group(self):
        ''' Test for successful mac_access_group'''
        set_module_args(dict(mac_access_group=dict(mac_acl_name='mac_acl1', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable')))
        expected_commands = ['vlan 555','tagged ethernet 1/1/2', 'mac access-group mac_acl1 in ethernet 1/1/2 lag 10 logging enable']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    
    def test_icx_default_acl(self):
        ''' Test for successful default acl'''
        set_module_args(dict(default_acl=dict(ip_type='ipv4',acl_name='guest', in_out='out',state='present')))
        expected_commands = ['authentication','default-acl ipv4 guest out']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    
    def test_icx_acl_assign_invalid_arg_ip_access_group(self):
        ''' Test for invalid in_out'''
        set_module_args(dict(ip_access_group=dict(acl_name='scale12', acl_num='123', in_out='aa', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes')))
        result = self.execute_module(failed=True)

    def test_icx_acl_assign_invalid_arg_ipv6_access_group(self):
        ''' Test for invalid acl_num'''
        set_module_args(dict(ipv6_access_group=dict(acl_name='scale12', acl_num='a', in_out='in', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='enable', frag_deny='yes')))
        result = self.execute_module(failed=True)

    def test_icx_acl_assign_invalid_arg_mac_access_group(self):
        ''' Test for invalid logging enable'''
        set_module_args(dict(ip_access_group=dict(mac_acl_name='mac_acl', ethernet='1/1/2', lag='25', vlan=dict(vlan_num='555', interfaces=['ethernet 1/1/2']), logging='aaa', frag_deny='yes')))
        result = self.execute_module(failed=True)


    def test_icx_invalid_args_default_acl(self):
        ''' Test for invalid in_out '''
        set_module_args(dict(default_acl=dict(ip_type='ipv4',acl_name='guest', in_out='aa',state='present')))
        result = self.execute_module(failed=True)