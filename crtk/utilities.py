# -*- coding: utf-8 -*-
# # Smart Contract Reverse Engineering Toolkit: Utilities
#
# Copyright (C) 2019-2020 CRTK Project
# Author: Hao-Nan Zhu <hao-n.zhu@outlook.com>
# URL: <https://github.com/hao-n/crtk>
# For license information, see LICENSE

import os

from crtk.mapping import opcode_mapping, push_mapping


def get_opcode_list(bytecode):
    """
    Convert bytecode to opcode list.

    input: string
    output: list of lists

    structure of an opcode: [address, bytecode, opcode, arguments if exist]
    """
    opcode_list = []
    push_skip_times = 0
    for i in range(0, len(bytecode), 2):
        code = bytecode[i:i+2]
        if push_skip_times == 0:
            loc = '0x'+str(hex(i//2))[2:].zfill(8)
            if code[0] != '6' and code[0] != '7':
                # is not a push-like opcode
                opcode = [loc, code, opcode_mapping.get(
                    code, '<------- ERROR'), '']
                opcode_list.append(opcode)
            else:
                # is a push-like opcode
                push_skip_times = push_mapping[code]
                opcode = [loc, code+bytecode[i+2:i+2+push_skip_times*2], opcode_mapping.get(
                    code, '<------- ERROR'), bytecode[i+2:i+2+push_skip_times*2]]
                opcode_list.append(opcode)
        else:
            push_skip_times -= 1
            continue
    return opcode_list


def clean_opcode(opcode_list):
    '''
    Clean opcode in a opcode list. Drop PUSH-like, DUP-like and SWAP-like opcodes, then replace all LOG-like opcodes with LOG.

    input: list of strings
    output: list of strings
    '''
    cleaned_opcode_list = []

    for opcode in opcode_list:
        if ("PUSH" not in opcode) and ("DUP" not in opcode) and ("SWAP" not in opcode):
            if "LOG" in opcode:
                cleaned_opcode_list.append(opcode.replace("LOG0", "LOG").replace("LOG1", "LOG").replace(
                    "LOG2", "LOG").replace("LOG3", "LOG").replace("LOG4", "LOG"))
            else:
                cleaned_opcode_list.append(opcode)

    return cleaned_opcode_list


def collapse_opcode(opcode_list, collapse):
    '''
    Collapse opcodes by certain level.  

    input: list of strings, int  
    output: list of strings  

    collapse  
    - 0: Count all opcodes including all the PUSH-like, DUP-like and SWAP-like ones.  
    - 1: Collapse all PUSH-like opcodes to PUSH, DUP-like opcodes to DUP, SWAP-like opcodes to SWAP and LOG-like opcode to LOG.  
    - 2: Drop PUSH-like, DUP-like and SWAP-like opcodes, then replace all LOG-like opcodes with LOG.  
    - 3: Drop all PUSH-like, DUP-like, SWAP-like and LOG-like opcodes.  
    '''
    collapsed_opcode_list = []

    if collapse == 0:
        collapsed_opcode_list = opcode_list
    elif collapse == 1:
        for opcode in opcode_list:
            if 'PUSH' in opcode:
                collapsed_opcode_list.append('PUSH')
            elif 'DUP' in opcode:
                collapsed_opcode_list.append('DUP')
            elif 'SWAP' in opcode:
                collapsed_opcode_list.append('SWAP')
            elif 'LOG' in opcode:
                collapsed_opcode_list.append('LOG')
            else:
                collapsed_opcode_list.append(opcode)
    elif collapse == 2:
        for opcode in opcode_list:
            if not (('PUSH' in opcode) or ('DUP' in opcode) or ('SWAP' in opcode)):
                if 'LOG' in opcode:
                    collapsed_opcode_list.append('LOG')
                else:
                    collapsed_opcode_list.append(opcode)
            else:
                pass
    elif collapse == 3:
        for opcode in opcode_list:
            if not (('PUSH' in opcode) or ('DUP' in opcode) or ('SWAP' in opcode) or ('LOG' in opcode)):
                collapsed_opcode_list.append(opcode)
            else:
                pass
    else:
        raise ValueError('Parameter collapse can only be in [0, 1, 2, 3].')

    return collapsed_opcode_list


def opcode_occurrence(opcode_list, collapse=0):
    '''
    Count ccurences of each opcode by a certain opcode sequence.

    input: list of strings, int
    output: dict (string -> int)

    collapse
    - 0: Count all opcodes including all the PUSH-like, DUP-like and SWAP-like ones.
    - 1: Collapse all PUSH-like opcodes to PUSH, DUP-like opcodes to DUP, SWAP-like opcodes to SWAP and LOG-like opcode to LOG.
    - 2: Drop PUSH-like, DUP-like and SWAP-like opcodes, then replace all LOG-like opcodes with LOG.
    - 3: Drop all PUSH-like, DUP-like, SWAP-like and LOG-like opcodes.
    '''

    stat_opcode_list = collapse_opcode(
        opcode_list=opcode_list, collapse=collapse)

    occurrence_stat = dict.fromkeys(stat_opcode_list, 0)
    opcode_list = collapse_opcode(opcode_list, collapse)
    occurrence_stat['ERROR'] = 0

    for opcode in opcode_list:
        if 'ERROR' in opcode:
            occurrence_stat['ERROR'] += 1
        else:
            occurrence_stat[opcode] += 1

    return occurrence_stat


def get_function_signatures_list(opcode_list):
    '''
    Get all the funtcion signatures within given opcode.

    input: list of lists
    output: list

    structure of an opcode: [address, bytecode, opcode, arguments if exist]
    '''
    function_signatures = []
    for i in range(len(opcode_list)):
        if opcode_list[i][1] == '80':
            if opcode_list[i+1][1] == '63' and opcode_list[i+2][1] == '14' and (opcode_list[i+3][1] in push_mapping.keys()) and opcode_list[i+4][1] == '57':
                # found a function head here
                function_name_hash = opcode_list[i+1][3]
                function_signatures.append(function_name_hash)
    return function_signatures


def check_ERC_standard(function_signatures, standard='ERC20'):
    '''
    Check if contract follows certain ERC standards.

    input: list, string
    output: bool

    standard
    - ERC20: Check if the contract follows ERC20.
    - ERC721: Check if the contract follows ERC721.
    - ERC777: Check if the contract follows ERC777.
    '''
    ERC20_signatures = ['18160ddd', '70a08231',
                        'a9059cbb', 'dd62ed3e', '095ea7b3', '23b872dd']
    ERC721_signatures = ['70a08231', '6352211e', '095ea7b3', '081812fc',
                         'a22cb465', 'e985e9c5', '23b872dd', '42842e0e', 'b88d4fde']
    ERC777_signatures = ['18160ddd', '70a08231', '9bd9bbc6', 'a9059cbb', 'fe9d9303', 'd95b6371',
                         '959b8c3f', 'fad8b32a', '06e48538', '62ad1b83', 'fc673c4f', 'dd62ed3e', '095ea7b3', '23b872dd']

    if standard == 'ERC20':
        return True if set(ERC20_signatures) <= set(function_signatures) else False
    elif standard == 'ERC721':
        return True if set(ERC721_signatures) <= set(function_signatures) else False
    elif standard == 'ERC777':
        return True if set(ERC777_signatures) <= set(function_signatures) else False
    else:
        raise ValueError(
            'Parameter standard can only be in [\'ERC20\', \'ERC721\', \'ERC777\'].')


def split_bytecode(bytecode):
    '''
    Split contract creation code.

    input: string
    output: tuple 

    structure of contract creation code
    +-----------------------+
    | Deployment Bytecode   |
    +-----------------------+
    | Runtime Bytecode      |
    +-----------------------+
    | BZZR: Swarm Source    |
    +-----------------------+
    | Constructor Arguments |
    +-----------------------+
    '''

    runtime_start = 0
    bzzr_start = 0
    args_start = 0

    bzzr = ''
    arguments = []

    bytecode = bytecode.lower()

    runtime_start = bytecode.find('f300') + 4
    deployment_bytecode = bytecode[:runtime_start]

    bzzr_start = bytecode.find('a165627a7a72305820') + 18
    if bzzr_start < 18:
        bzzr_start = len(bytecode)
        args_start = len(bytecode)
    else:
        bzzr = 'bzzr: '+bytecode[bzzr_start:bzzr_start+64]
        args_start = bzzr_start + 64 + 4

    runtime_bytecode = bytecode[runtime_start:bzzr_start]

    for i in range(args_start, len(bytecode), 64):
        aug = str('Arg [{}]: '.format(
            str((i-args_start) // 64))+bytecode[i:i+64])
        arguments.append(aug)

    return deployment_bytecode, runtime_bytecode, bzzr, arguments


def function_to_signature(function_name):
    '''
    Convert function definition to function signature.

    input: string
    output: string
    '''
    import sha3
    signature = sha3.keccak_256(
        str(function_name).encode('utf-8')).hexdigest().lower()[:8]
    return signature


def signature_to_function(function_signature):
    '''
    Convert function signature to function definition by reverse query. Credit to https://www.4byte.directory/

    input: string
    output: list

    There might be several query results if hash collision encountered and also might be no result due to data vacancy.
    '''

    import requests
    request_res = requests.get(
        'https://www.4byte.directory/api/v1/signatures/?hex_signature={}'.format(function_signature)).json()
    res = []
    for item in request_res.json()['results']:
        res.append(item['text_signature'])
    return res


def get_function_definitions_list(function_signatures):
    '''
    Get function definitions by function siguature-to-definition convertion.

    input: list
    output:list
    '''

    definition_list = []
    try:
        for signature in function_signatures:
            definition_list.append(signature_to_function(signature))
    except:
        definition_list = ['Function Signature Database not Avaliable.']
    return definition_list


def fix_hex_string(hex_string):
    '''
    Fix truncated hex strings. '4e' -> '0x0000004e'

    input: string 
    output: string
    '''
    decimal_value = int(hex_string, 16)
    return '0x'+str(hex(decimal_value))[2:].zfill(8)
