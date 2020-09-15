# -*- coding: utf-8 -*-
# Smart Contract Reverse Engineering Toolkit: Contract Class
#
# Copyright (C) 2019-2020 crtk Project
# Author: Hao-Nan Zhu <hao-n.zhu@outlook.com>
# URL: <https://github.com/hao-n/crtk>
# For license information, see LICENSE

from crtk.utilities import opcode_occurrence


class Contract(object):
    def __init__(self):
        # contract type
        self.real_contract = False

        # contract standard
        self.ERC20 = False
        self.ERC721 = False
        self.ERC777 = False

        # contract attributes
        self.address = ''
        self.bytecode = ''
        self.opcode = []
        self.function_signatures = []
        self.function_definitions = []

    def get_bytecode(self):
        return self.bytecode

    def get_opcode(self):
        return self.opcode

    def get_function_signature_list(self):
        return self.function_signatures

    def get_function_definition_list(self):
        return self.function_definitions

    def get_opcode_occurrence(self, collapse=0):
        opcode_list = [item[2] for item in self.opcode]
        return opcode_occurrence(opcode_list, collapse)

    def get_address(self):
        return self.address

    def is_ERC20(self):
        return self.ERC20

    def is_ERC721(self):
        return self.ERC721

    def is_ERC777(self):
        return self.ERC777

    def is_real_contract(self):
        return self.real_contract
