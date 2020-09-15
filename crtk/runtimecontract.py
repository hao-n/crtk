# -*- coding: utf-8 -*-
# Smart Contract Reverse Engineering Toolkit: Runtime Contract Class
#
# Copyright (C) 2019-2020 crtk Project
# Author: Hao-Nan Zhu <hao-n.zhu@outlook.com>
# URL: <https://github.com/hao-n/crtk>
# For license information, see LICENSE

from crtk.contract import Contract
from crtk.utilities import get_function_signatures_list, get_function_definitions_list, check_ERC_standard, get_opcode_list


class RuntimeContract(Contract):
    def __init__(self, bytecode, address=''):
        super(RuntimeContract, self).__init__()

        if bytecode[:2] == '0x' or bytecode[:2] == '0X':
            self.bytecode = bytecode[2:].lower()
        else:
            self.bytecode = bytecode.lower()

        if len(address) > 0 and address[:2] != '0x':
            self.address = '0x' + address
        else:
            self.address = address

        self.opcode = get_opcode_list(self.bytecode)
        self.function_signatures = get_function_signatures_list(self.opcode)
        self.function_definitions = get_function_definitions_list(self.function_signatures)

        if len(self.function_signatures) > 0:
            self.real_contract = True
        else:
            self.real_contract = False

        if check_ERC_standard(self.function_signatures, standard='ERC20'):
            self.ERC20 = True
        if check_ERC_standard(self.function_signatures, standard='ERC721'):
            self.ERC721 = True
        if check_ERC_standard(self.function_signatures, standard='ERC777'):
            self.ERC777 = True

    def is_runtime_contract(self):
        return True

