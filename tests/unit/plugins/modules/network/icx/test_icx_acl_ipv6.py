# Copyright: (c) 2019, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible_collections.community.network.tests.unit.compat.mock import patch
from ansible_collections.community.network.plugins.modules.network.icx import icx_acl_ipv6
from ansible_collections.community.network.tests.unit.plugins.modules.utils import set_module_args
from .icx_module import TestICXModule, load_fixture


class TestICXAclIpv6Module(TestICXModule):
    ''' Class used for Unit Tests agains icx_acl_ipv6 module '''
    module = icx_acl_ipv6

    def setUp(self):
        super(TestICXAclIpv6Module, self).setUp()
        self.mock_load_config = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_acl_ipv6.load_config')
        self.load_config = self.mock_load_config.start()
        self.mock_exec_command = patch('ansible_collections.community.network.plugins.modules.network.icx.icx_acl_ipv6.exec_command')
        self.exec_command = self.mock_exec_command.start()

    def tearDown(self):
        super(TestICXAclIpv6Module, self).tearDown()
        self.mock_load_config.stop()
        self.mock_exec_command.stop()

    def load_fixtures(self, commands=None): 
	    self.load_config.return_value = None

    def test_icx_acl_ipv6_all_options(self):
        ''' Test for successful acl ipv6 with all options'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(seq_num='10',rule_type='permit',ip_protocol_name='ipv6',source=dict(any='yes'),destination=dict(any='yes'),fragments='yes',dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',priority_matching_value='6',traffic_policy_name='policy1',log='yes',mirror='yes')),
                                   (dict(seq_num='20',rule_type='deny',ip_protocol_name='icmp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(any='yes'),icmp_num='25',dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',traffic_policy_name='policy1',log='yes',mirror='yes')),
                                   (dict(seq_num='10',rule_type='deny',ip_protocol_name='tcp',source=dict(host_ipv6_address='2001:DB8:e0ac::2'),destination=dict(host_ipv6_address='2001:DB8:e0aa:0::24'),source_comparison_operators=dict(operator='eq',port_num='22'),destination_comparison_operators=dict(operator='range',port_name='ftp',high_port_name='http'),established='yes',dscp_matching_dscp_value='32',dscp_marking_dscp_value='8',priority_matching_value='6',priority_marking_value='5',internal_priority_marking_queuing_priority='4',log='yes',mirror='yes')),
                                   (dict(seq_num='10',rule_type='permit',ip_protocol_name='ahp',source=dict(any='yes'),destination=dict(any='yes'),dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',priority_matching_value='6',traffic_policy_name='policy1',log='yes',mirror='yes'))]))
        expected_commands = ['ipv6 access-list acl1',
                             'sequence 10 permit ipv6 any any fragments dscp-matching 21 802.1p-priority-matching 6 dscp-marking 8 traffic-policy policy1 log mirror',
                             'sequence 20 deny icmp 2001:DB8::/64 any 25 dscp-matching 21 dscp-marking 8 traffic-policy policy1 log mirror',
                             'sequence 10 deny tcp host 2001:DB8:e0ac::2 eq 22 host 2001:DB8:e0aa:0::24 range ftp http established dscp-matching 32 802.1p-priority-matching 6 dscp-marking 8 802.1p-priority-marking 5 internal-priority-marking 4 log mirror',
                             'sequence 10 permit ahp any any dscp-matching 21 802.1p-priority-matching 6 dscp-marking 8 traffic-policy policy1 log mirror'          
                             ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
        
    def test_icx_acl_ipv6_all_options_remove(self):
        ''' Test for removing acl ipv6 with all options'''
        set_module_args(dict(acl_name='acl1',state='absent',
                             rule=[(dict(seq_num='10',rule_type='permit',ip_protocol_name='ipv6',source=dict(any='yes'),destination=dict(any='yes'),fragments='yes',dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',priority_matching_value='6',traffic_policy_name='policy1',log='yes',mirror='yes',state='absent')),
                                   (dict(seq_num='20',rule_type='deny',ip_protocol_name='icmp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(any='yes'),icmp_num='25',dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',traffic_policy_name='policy1',log='yes',mirror='yes',state='absent')),
                                   (dict(seq_num='10',rule_type='deny',ip_protocol_name='tcp',source=dict(host_ipv6_address='2001:DB8:e0ac::2'),destination=dict(host_ipv6_address='2001:DB8:e0aa:0::24'),source_comparison_operators=dict(operator='eq',port_num='22'),destination_comparison_operators=dict(operator='range',port_name='ftp',high_port_name='http'),established='yes',dscp_matching_dscp_value='32',dscp_marking_dscp_value='8',priority_matching_value='6',priority_marking_value='5',internal_priority_marking_queuing_priority='4',log='yes',mirror='yes',state='absent')),
                                   (dict(seq_num='10',rule_type='permit',ip_protocol_name='ahp',source=dict(any='yes'),destination=dict(any='yes'),dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',priority_matching_value='6',traffic_policy_name='policy1',log='yes',mirror='yes',state='absent'))]))
        expected_commands = [
                             'no ipv6 access-list acl1',
                             'no sequence 10 permit ipv6 any any fragments dscp-matching 21 802.1p-priority-matching 6 dscp-marking 8 traffic-policy policy1 log mirror',
                             'no sequence 20 deny icmp 2001:DB8::/64 any 25 dscp-matching 21 dscp-marking 8 traffic-policy policy1 log mirror',
                             'no sequence 10 deny tcp host 2001:DB8:e0ac::2 eq 22 host 2001:DB8:e0aa:0::24 range ftp http established dscp-matching 32 802.1p-priority-matching 6 dscp-marking 8 802.1p-priority-marking 5 internal-priority-marking 4 log mirror',
                             'no sequence 10 permit ahp any any dscp-matching 21 802.1p-priority-matching 6 dscp-marking 8 traffic-policy policy1 log mirror'
            ]
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx__acl_ipv6_deny_ipv6_icmp(self):
        ''' Test for successful ipv6 and icmp deny rule'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(seq_num='10',rule_type='deny',ip_protocol_name='ipv6',source=dict(host_ipv6_address='2001:DB8:e0ac::2'),destination=dict(any='yes'),routing='yes',dscp_matching_dscp_value='21',priority_matching_value='6',priority_marking_value='6',internal_priority_marking_queuing_priority='2',log='yes')),
                                   (dict(rule_type='deny',ip_protocol_name='icmp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(host_ipv6_address='2001:DB8:e0ac::2'),icmp_num='25',traffic_policy_name='policy1',mirror='yes'))]))
        expected_commands = ['ipv6 access-list acl1',
                             'sequence 10 deny ipv6 host 2001:DB8:e0ac::2 any routing dscp-matching 21 802.1p-priority-matching 6 802.1p-priority-marking 6 internal-priority-marking 2 log',
                             'deny icmp 2001:DB8::/64 host 2001:DB8:e0ac::2 25 traffic-policy policy1 mirror']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_ipv6_deny_udp(self):
        ''' Test for successful udp deny rule'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(seq_num='10',rule_type='deny',ip_protocol_name='udp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(any='yes'),source_comparison_operators=dict(operator='eq',port_num='22'),destination_comparison_operators=dict(operator='range',port_name='ftp',high_port_name='http'),established='yes',dscp_matching_dscp_value='32',dscp_marking_dscp_value='8',priority_matching_value='6',log='yes'))]))
        expected_commands = ['ipv6 access-list acl1',
                             'sequence 10 deny udp 2001:DB8::/64 eq 22 any range ftp http established dscp-matching 32 802.1p-priority-matching 6 dscp-marking 8 log']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    
    def test_icx_acl_ipv6_permit_ipv6_icmp(self):
        ''' Test for successful ipv6 and icmp permit rule'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(rule_type='permit',ip_protocol_name='ipv6',source=dict(host_ipv6_address='2001:DB8:e0ac::2'),destination=dict(any='yes'),routing='yes',dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',priority_matching_value='6',priority_marking_value='6',internal_priority_marking_queuing_priority='2',log='yes',mirror='yes')),
                                   (dict(seq_num='20',rule_type='permit',ip_protocol_name='icmp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(host_ipv6_address='2001:DB8:e0ac::2'),icmp_num='25',dscp_matching_dscp_value='21',dscp_marking_dscp_value='8',traffic_policy_name='policy1',log='yes',mirror='yes'))]))
        expected_commands = ['ipv6 access-list acl1',
                             'permit ipv6 host 2001:DB8:e0ac::2 any routing dscp-matching 21 802.1p-priority-matching 6 dscp-marking 8 802.1p-priority-marking 6 internal-priority-marking 2 log mirror',
                             'sequence 20 permit icmp 2001:DB8::/64 host 2001:DB8:e0ac::2 25 dscp-matching 21 dscp-marking 8 traffic-policy policy1 log mirror']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)

    def test_icx_acl_ipv6_permit_tcp(self):
        ''' Test for successful tcp permit rule'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(rule_type='permit',ip_protocol_name='tcp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(any='yes'),source_comparison_operators=dict(operator='eq',port_num='22'),destination_comparison_operators=dict(operator='range',port_name='ftp',high_port_name='http'),established='yes',dscp_matching_dscp_value='32',dscp_marking_dscp_value='8',priority_matching_value='6',priority_marking_value='5',internal_priority_marking_queuing_priority='4',log='yes',mirror='yes'))]))
        expected_commands = ['ipv6 access-list acl1',
                             'permit tcp 2001:DB8::/64 eq 22 any range ftp http established dscp-matching 32 802.1p-priority-matching 6 dscp-marking 8 802.1p-priority-marking 5 internal-priority-marking 4 log mirror']
        result = self.execute_module(changed=True)
        self.assertEqual(result['commands'], expected_commands)
    
    def test_icx_invalid_args_acl_ipv6_permit(self):
        ''' Test for invalid ip_protocol_name'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(seq_num='10',rule_type='permit',ip_protocol_name='acp',source=dict(ipv6_prefix_prefix_length='2001:DB8::/64'),destination=dict(any='yes'),routing='yes',dscp_matching_dscp_value='21',log='yes'))]))
        result = self.execute_module(failed=True)

    def test_icx_invalid_args_acl_ipv6_deny(self):
        ''' Test for invalid seq_num'''
        set_module_args(dict(acl_name='acl1',
                             rule=[(dict(seq_num='aa',rule_type='deny',ip_protocol_name='tcp',source=dict(any='yes'),destination=dict(any='yes'),dscp_matching_dscp_value='21',log='yes'))]))
        result = self.execute_module(failed=True)

    
    