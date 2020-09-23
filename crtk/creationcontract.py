# -*- coding: utf-8 -*-
# Smart Contract Reverse Engineering Toolkit: Creation Contract Class
#
# Copyright (C) 2019-2020 crtk Project
# Author: Hao-Nan Zhu <hao-n.zhu@outlook.com>
# URL: <https://github.com/hao-n/crtk>
# For license information, see LICENSE

from crtk.runtimecontract import RuntimeContract
from crtk.contract import Contract
from crtk.utilities import split_bytecode, get_opcode_list


class CreationContract(Contract):
    def __init__(self, bytecode, address=''):
        self.bytecode = bytecode
        self.address = address

        self.deployment_bytecode, self.runtime_bytecode, self.bzzr, self.constructor_arguments = split_bytecode(
            bytecode=self.bytecode)

        self.runtime_contract = RuntimeContract(bytecode=self.runtime_bytecode, address=self.address)

        if self.deployment_bytecode[:2] == '0x':
            self.deployment_bytecode = self.deployment_bytecode[2:]
        else:
            pass
        
        self.opcode = get_opcode_list(self.bytecode)
        self.deployment_opcode = get_opcode_list(self.deployment_bytecode)
        self.runtime_opcode = self.runtime_contract.get_opcode()
        
        self.opcode_occurrence = self.runtime_contract.get_opcode_occurrence()
        self.function_signatures = self.runtime_contract.get_function_signature_list()

        if len(self.function_signatures) > 0:
            self.real_contract = True
        else:
            self.real_contract = False

        self.ERC20 = self.runtime_contract.is_ERC20()
        self.ERC721 = self.runtime_contract.is_ERC721()
        self.ERC777 = self.runtime_contract.is_ERC777()
        
    def get_deployment_bytecode(self):
        return self.deployment_bytecode

    def get_runtime_bytecode(self):
        return self.runtime_bytecode

    def get_deployment_opcode(self):
        return self.deployment_opcode
    
    def get_runtime_opcode(self):
        return self.runtime_opcode

    def get_runtime_contract(self):
        return self.runtime_contract

    def get_constructor_arguments(self):
        return self.constructor_arguments

    def get_bzzr(self):
        return self.bzzr

    def is_runtime_contract(self):
        return False
