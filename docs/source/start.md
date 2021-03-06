# Getting Start with CRTK

CRTK simplifies converting and parsing of Ethereum smart contracts, and provids many great features for reverse engineering researchers including:

- Load contract by type(runtime or creation) 
- Get contract attributes such as bytecode, opcode, swarm source and constructor arguments
- Analysis for contract such as opcode occurrence and ERC standard checking

## Quick start

Assuming you have Python already, install pysha3 for [keccak](https://github.com/XKCP/XKCP):

``` bash
$ pip install pysha3
```

Then install CRTK:

``` bash
$ pip install crtk
```

Check installation in python interactive shell:

``` python
>>> import crtk
```
