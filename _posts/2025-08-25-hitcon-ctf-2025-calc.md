---
title: HITCON CTF 2025 -- calc
categories:
- write-ups
date: '2025-08-25 09:49:01'
tags:
- CTF
- Pwnable
- HITCON
- use_after_free
- arm
- aarch64
- PAC
- BTI
- relative_vtables
---

## Intro
It all started when [CK](https://x.com/bletchley13) asked me if I could create challenges for this year's HITCON CTF. As a retired CTF player, I initially replied, "Well... maybe? I'll see what I can come up with, but there's no guarantee. It's better for you to ask some of the younger guys instead of an old, retired player like me."

A few weeks later, he reached out to me again to see if I had come up with anything. At that time, I was busy with other things, so obviously the answer was no. However, that made me realize they were really short on challenge creators this year ( otherwise, he wouldn't have had to ask an old guy like me 😅 ).

So after I wrapped up my work and had some free time, I started seriously thinking about whether I had encountered anything interesting in my job that might be worth turning into a CTF challenge. I then recalled some challenges I had faced while working on an Android exploit: [BTI](https://en.wikipedia.org/wiki/Indirect_branch_tracking) and [relative vtables](https://llvm.org/devmtg/2021-11/slides/2021-RelativeVTablesinC.pdf). That led me to think, "What if I create an AArch64 pwn challenge that requires participants to bypass PAC, BTI, and relative vtables?"

After a few days of experimentation, I successfully created a QEMU environment that could emulate PAC and BTI. I also learned how to compile programs and libraries with PAC, BTI, and relative vtables enabled. At that point, I knew I was capable of creating a CTF challenge. I then spent a few more days designing a simple AArch64 pwn challenge and successfully wrote an exploit that could bypass all the mitigations mentioned above. 

And that's how [calc](https://ctf2025.hitcon.org/dashboard/#21) was born.

## Challenge description

According to the provided challenge files, we can determine that the challenge binary is executed within a QEMU VM. The challenge binary `calc` can be found under `/home/user/` after decompressing `initramfs.cpio.gz`.

Running checksec on `calc`:
```
Arch:       aarch64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
```

It is an AArch64 binary, with all mitigations enabled except for the stack canary. In addition, we can use `readelf -n calc` to inspect other security features:

```
> readelf -n ./calc
....................
Displaying notes found in: .note.gnu.property
  Owner                Data size        Description
  GNU                  0x00000010       NT_GNU_PROPERTY_TYPE_0
      Properties: AArch64 feature: BTI, PAC
```

We can see that the binary has both PAC and BTI enabled. For those interested in learning more about PAC and BTI, here are some recommended resources: ( [link1](https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64), [link2](https://sipearl.com/wp-content/uploads/2023/10/SiPearl-White_Paper_Control_Flow_Integrity-on-Arm64.pdf) ). Below is a brief overview:

* PAC ( Pointer Authentication Code ) : This security feature is designed to protect sensitive pointers ( such as return addresses ) from being overwritten, making stack-based attacks like buffer overflows significantly more difficult. RET2 Systems has an [excellent article](https://blog.ret2.io/2021/06/16/intro-to-pac-arm64/) that explains this mechanism in detail.

* BTI ( Branch Target Identification ) : This is a mitigation targets indirect branch exploits, such as those using BR or BLR instructions. Similar to [Intel's CET](https://lpc.events/event/2/contributions/147/attachments/72/83/CET-LPC-2018.pdf), with BTI enabled, all indirect branches must land on valid branch target landing pads, such as `bti c` instructions or PAC-related instructions ( e.g., `paciasp` ). **This makes ROP attack nearly impossible, as you can no longer jump into the middle of a function.**

The QEMU environment used in this challenge also supports PAC and BTI. To confirm this, we can modify the `initramfs.cpio.gz` to gain access to the QEMU VM. After that, run `cat /proc/cpuinfo` to check for the relevant features:

```
~ # cat /proc/cpuinfo
processor       : 0
BogoMIPS        : 125.00
Features        : fp ...... paca pacg ...... bti
CPU implementer : 0x00
CPU architecture: 8
CPU variant     : 0x0
CPU part        : 0x051
CPU revision    : 0
```

We can see the "Features" field lists `paca`, `pacg`, and `bti`. If you're interested, you can write a simple test program to attempt an indirect jump via the BLR instruction to an invalid instruction. This will trigger a `SIGILL`  ( illegal instruction ) signal and cause the program to crash.

The goal of this challenge is to test whether participants can exploit a simple UAF vulnerability in `calc` to bypass the aforementioned security features ( we'll get into relative vtables later ) and achieve RCE on the target service.

## The vulnerability
Before explaining the vulnerability, let's briefly go over the general behavior of the program.

The program allows the user to create an integer array ( `int_arr` ) and a `calc` object. It also provides options to delete them. Once both are created, the user can perform a "calculation". There are five available operations: XOR, MOD, ADD, SUB, and MUL. During the calculation, the program first sums all the values in the integer array and stores the result in `int_arr[0]`. Then, it performs the selected operation between `int_arr[0]` and `calc->num`. For example, if the user chooses XOR, the program effectively performs `sum(int_arr) ^ calc->num`.

The vulnerability is quite simple and straightforward: the program doesn't nullify the pointer after freeing the `calc` object and `int_arr`, resulting in a typical UAF ( Use-After-Free ) vulnerability. With this bug, we can easily overlap `int_arr` and the `calc` object ( no need for complex scudo heap exploitation ! ), allowing us corrupting the vtable of `calc` and hijack the control flow. Sounds like an easy challenge, huh ? ( ͡° ͜ʖ ͡°)

## Exploitation
### Overlapping `int_arr` and `calc`

Overlapping `int_arr` and `calc` is simple, we can achieve this using the following sequence:

```
Create calc -> Delete calc -> Create int_arr
```


At this point, `int_arr` and `calc` occupy the same memory region, resulting in the following memory layout:

```
int_arr                           calc                                                          
┌─────────┬──────────┐            ┌────────────────────┐   
│         │          │            │                    │   
│ int_1   │  int_0   │ ◄───────►  │      vtable        │   
├─────────┼──────────┤            ├────────────────────┤   
│         │          │            │                    │   
│ int_3   │  int_2   │ ◄───────►  │      num           │   
├─────────┼──────────┤            ├────────────────────┤   
│         │          │            │                    │   
│ int_5   │  int_4   │ ◄───────►  │      status        │   
│         │          │            │                    │   
└─────────┴──────────┘            └────────────────────┘                                                         
```

As we can see, by controlling `int_0` through `int_5`, we can forge the entire `calc` object, including its vtable, allowing us to hijack the control flow.

### Exploitation plan

There are several approaches to exploitation after hijacking the vtable. A common technique is to pivot the stack to a controllable heap buffer and then perform a ROP-based attack to achieve arbitrary code execution. However, due to BTI this method is not feasible in this challenge.

Fortunately, there are publicly documented techniques for bypassing control-flow integrity ( CFI ) protections like BTI. One of them is [COOP](https://ieeexplore.ieee.org/document/7163058) ( Counterfeit Object-Oriented Programming ). As early as 2015, researchers demonstrated that it is possible to forge C++ objects -- including their vtables -- to hijack the control flow by chaining virtual functions in the program. For example, consider the following virtual function:

```c++
void Obj::func() {
  return this-a->b;
}
```

If the attacker is able to forge `Obj`, this effectively becomes an arbitrary read primitive: by forging `this->a` pointer, it is possible to read from an arbitrary address. Similarly, by crafting fake C++ objects and identifying useful virtual functions, an attacker can build arbitrary read/write primitives, ultimately leading to arbitrary code execution.

COOP is a powerful exploitation technique. It can bypass not only BTI, but also other CFI mechanisms such as Windows CFG. For more real-world examples of COOP, you can refer to the following resources:
* [Cleanly Escaping the Chrome Sandbox](https://theori.io/blog/cleanly-escaping-the-chrome-sandbox)
* [Bypassing Intel CET with Counterfeit Objects (COOP)](https://static1.squarespace.com/static/5c2f61585b409bfa28a47010/t/64fb2ce1e4c6f107868c1484/1694182627599/COOP.pdf)

Given that BTI is enabled in this challenge, COOP seems like a promising direction. However, before diving into the exploitation, let's first examine the assembly code responsible for invoking a virtual function in this binary:

```asm
LDRSW  X9, [X8,#0xC] ; X8 = vtable
ADD    X8, X8, X9 
BLR    X8 
```

Woah, what's...this ?

Unlike the typical virtual function calls we're familiar with -- where execution jumps to `[vtable + index]` -- it does something quite different: it jumps to `vtable + [vtable + index]`. I still remember how surprised I was when I first saw this while working on an Android exploit. I had no idea virtual functions could be invoked this way, not to mention it immediately made exploitation far more challenging.

And that, right there, is the final boss of this challenge: **relative vtables**.

This is a feature supported by the Clang/LLVM toolchain. When enabled, the vtable no longer stores raw function pointers. Instead, each entry contains a 4-byte offset that is added to the base address of the vtable at runtime to resolve the actual address of the virtual function. This design eliminates the need for dynamic relocations in vtables and reduces memory usage -- especially on 64-bit systems -- since it replaces 8-byte pointers with 4-byte offsets.

As mentioned in the [introductory slides](https://llvm.org/devmtg/2021-11/slides/2021-RelativeVTablesinC.pdf), the primary goal of relative vtables is to optimize the performance of Position-Independent Code ( PIC ). Technically, it's not a security mitigation. However, from an exploitation perspective, it introduces significant challenges:

* Forging a vtable becomes infeasible
    - Since the control flow jumps to `vtable + [vtable + index]` rather than directly dereferencing a function pointer, placing a fake vtable in a writable region like the heap is no longer viable. The 4-byte offset is treated as a relative jump from the vtable base, and because the heap is typically non-executable, any jump to `heap + [heap + index]` is likely to result in a crash. **This severely restricts the memory regions where vtables can safely reside**.

* Without the ability to forge a vtable, attackers can no longer call arbitrary virtual functions.

As a result, conventional COOP techniques -- where forged vtables are placed in attacker-controlled memory -- are no longer applicable.

So, does that mean COOP is completely off the table? Not quite. 

Let's take a step back and look at what we can still do:

* We still have control over the vtable pointer.
* The program's "calculation" feature allows us to invoke five different virtual functions. Specifically, starting from vtable entry 0, we can invoke entries 2 through 6 using this feature.

In other words, while relative vtables constrain us to using only legitimate vtables located in the program's read-only sections, **we can still search those sections for useful virtual functions to help our exploitation**.

At this point, our strategy becomes clear: enumerate all relative vtables in the binary, identify useful virtual functions, and use them to build our exploit primitives. It's still COOP -- just with much stricter constraints on vtable placement.

### Enumerating relative vtables and virtual functions

To identify useful virtual functions for exploitation, there are a few things that need to be done first:
* Locate all relative vtable addresses.
* Locate all virtual function addresses.
* A way to trace a virtual function address back to its corresponding vtable and entry.

Here I used IDA Python to achieve these tasks. First, we can enumerate relative vtables in the binary using the following logic:

1. Scan both `.rodata` and `.data.rel.ro` sections.
2. A relative vtable typically has the following characteristics:  
  a. `vtable + [vtable + index]` points to a valid function entry.  
  b. The first vtable entry ( index 0 ) is always 0, and the second entry ( index 1 ) stores a `type_info` offset. Therefore, we start validating from the third entry ( index 2 ) onward by checking whether the calculated address points to a valid function entry.

With the help of ChatGPT, it was quite easy to write an IDA Python script that meets these requirements. You can find the full code [here](https://github.com/bruce30262/CTF_challenge_public/blob/master/hitcon2025_qual/calc/solution/ida_scripts/dump_all_RT_func.py) (  ignore the Chinese characters since it's generated by AI 😅).

Once we have all the relative vtables, we can iterate through them to collect all virtual function addresses. We can also apply some heuristics to further filter the results. For example, some virtual functions are very large and call functions such as `realloc()`, which are obviously not useful for exploitation. Therefore I also added some logic to filter out any virtual functions that call `realloc()`.

After gathering these candidate virtual functions, the next step is to analyze which ones can actually help with our exploit. Before doing that, we need a way to trace a virtual function address back to its vtable and entry. This makes it easier to replace vtable in the `calc` object once we identify a useful function. Implementing this is simple: we just iterate over all vtables and their entries. [Here's the full code](https://github.com/bruce30262/CTF_challenge_public/blob/master/hitcon2025_qual/calc/solution/ida_scripts/find_vtable_from_func.py).

With these tools ready and a list of virtual functions in hand, we can finally begin searching for useful virtual functions. The first step, of course, is to find a function that can help leak the binary's base address.

### Leaking binary's base address

How can we control `calc`'s vtable -- and ultimately leak the binary's base address -- without knowing the base address in the first place ?

Let's first review how we can use a UAF to overlap `int_arr` with the `calc` object. As mentioned earlier, there are two ways to achieve this overlap:

1. `Create calc -> Delete calc -> Create int_arr`
2. `Create int_arr -> Delete int_arr -> Create calc`

The key difference is that in the 2nd approach, after creating the `calc` object, the `int_0` and `int_1` values in `int_arr` will contain the vtable address from the `calc` object:

```
int_arr                                     calc                                                                        
┌───────────────┬──────────────┐            ┌────────────────────┐     
│high 32 bit of │low 32 bit of │            │                    │     
│vtable (int_1) │vtable (int_0)│ ◄───────►  │      vtable        │     
├───────────────┼──────────────┤            ├────────────────────┤     
│high 32 bit of │low 32 bit of │            │                    │     
│num (int_3)    │num (int_2)   │ ◄───────►  │      num           │     
├───────────────┼──────────────┤            ├────────────────────┤     
│      0        │     0        │            │                    │     
│   (int_5)     │  (int_4)     │ ◄───────►  │      status        │     
│               │              │            │                    │     
└───────────────┴──────────────┘            └────────────────────┘     
```

When creating a `calc` object, the value of `calc->num` is set, which in turn affects `int_2` and `int_3`. **The critical part here is that when we trigger the calculation, the program will invoke `calc->sum()`, which sums all integers in `int_arr` and stores the result in `int_0`**. Because we can control `int_2` and `int_3` -- and since `int_4` and `int_5` are zero by default -- we can actually control the value of `int_0` through the calculation, and thus shift the vtable address:

```
int_arr                                     calc                                                                        
┌───────────────┬──────────────┐            ┌────────────────────┐     
│high 32 bit of │ sum(int_arr) │            │                    │     
│vtable (int_1) │ (int_0)      | ◄───────►  │      vtable        │     
├───────────────┼──────────────┤            ├────────────────────┤     
│high 32 bit of │low 32 bit of │            │                    │     
│num (int_3)    │num (int_2)   │ ◄───────►  │      num           │     
├───────────────┼──────────────┤            ├────────────────────┤     
│      0        │     0        │            │                    │     
│   (int_5)     │  (int_4)     │ ◄───────►  │      status        │     
│               │              │            │                    │     
└───────────────┴──────────────┘            └────────────────────┘
```

For example, if the original vtable address is `0xaaaa000077C4`, after calling `calc->sum()`, the resulting vtable address would become:

```
0xaaaa000077C4  
+ int_0 (low 32 bits, originally 0x77C4)  
+ int_1 (high 32 bits, originally 0xaaaa)  
+ int_2  
+ int_3  
+ int_4 (default 0)  
+ int_5 (default 0)
```

By controlling `int_2` and `int_3`, we can shift the vtable to an arbitrary location.

At this point, you might wonder: doesn't `int_1` ( the high 32 bits of the vtable address ) get randomized by ASLR ? The answer is: not in this case. You can verify this by inspecting the memory map via GDB or simply by reading `/proc/<pid>/maps`. You'll find that in this QEMU VM environment, although the binary is AArch64, **the high 32 bits of the binary's base address is always `0xaaaa`** -- meaning that `int_1` will always be `0xaaaa`.

This makes controlling `sum(int_arr)` much easier. For example, if we want to shift the vtable to `0xaaaa000078C4` ( move it forward by 0x100 bytes -- regardless of whether this is a valid vtable ), we can simply set `calc->num` like this:

`-0xaaaa + 0x100 + 1`

Here, `-0xaaaa` "cancels out" `int_1`, `0x100` is the intended shift, and the final `+1` is necessary because `calc->num` will ultimately be treated as a 64-bit negative integer, causing `int_3` to become `0xffffffff` ( i.e., -1 ), so we need to add 1 to compensate.

Once we are able to control the vtable, the next goal is to leak the binary's base address. The first step is to identify where in the program we can trigger a potential leak.

Through reverse engineering, we can see that most of the program's output consists of static strings -- it generally does not print user-controlled data. The only place where we can potentially leak information is after a calculation is performed, when the program prints its "status":

```c
  switch ( i )
  {
    case 1:
      v2 = ((__int64 (*)(void))(*(_QWORD *)calc + *(int *)(*(_QWORD *)calc + 8LL)))();
      return printf("Status: %d\n", v2);
    case 2:
      v3 = ((__int64 (*)(void))(*(_QWORD *)calc + *(int *)(*(_QWORD *)calc + 12LL)))();
      return printf("Status: %d\n", v3);
    case 3:
      v4 = ((__int64 (*)(void))(*(_QWORD *)calc + *(int *)(*(_QWORD *)calc + 16LL)))();
      return printf("Status: %d\n", v4);
    case 4:
      v5 = ((__int64 (*)(void))(*(_QWORD *)calc + *(int *)(*(_QWORD *)calc + 20LL)))();
      return printf("Status: %d\n", v5);
    case 5:
      v6 = ((__int64 (*)(void))(*(_QWORD *)calc + *(int *)(*(_QWORD *)calc + 24LL)))();
      return printf("Status: %d\n", v6);
    default:
      return printf("Status: %d\n", 2);
  }
```

We can see that the `status` value is determined by the return value of the virtual function that was executed. Therefore, **if we can trigger a virtual function that returns a pointer to somewhere inside the binary, we can leak the binary's base address when `status` is printed.**

The next challenge is: how do we find a virtual function that returns such a value ? For this, I recommend using [angr](https://angr.io/) to analyze all the virtual functions. Symbolic execution engines are not only useful for finding functions that return pointers into the binary, but also for discovering virtual functions that are capable of arbitrary read/write ( which we'll cover later ).

So, how exactly do we use angr to find virtual functions that return a pointer inside the binary ? After some trial and error, I decided to use the following approach:

1. For each virtual function, simulate the function in angr and check the value of the X0 register ( the return value ) after execution.
    * For this step, we first set the binary base address to `0`
2. Check whether this return value points to an address within the binary.
3. Set the binary base address to `0x400000`, and repeat steps 1 and 2.
    * This helps avoid false positives: if both runs produce a return value pointing inside the binary, we can safely conclude that the function meets our needs.

The full code for this process can be found [here](https://github.com/bruce30262/CTF_challenge_public/blob/master/hitcon2025_qual/calc/solution/angr_scripts/find_bin_addr.py). My approach was to first dump all virtual functions into a JSON file, and then load that file for analysis.

The results looked something like this:

```
1/195: 0x18428
2/195: 0x18474
3/195: 0x184e4
4/195: 0x18568
5/195: 0x1861c
6/195: 0x18698
7/195: 0x18714
8/195: 0x1ac08
9/195: 0x1ac10
10/195: 0x1ac3c
[!!] Function 0x1ac3c set X0 to binary address !
11/195: 0x1ac4c
12/195: 0x1ac78
[!!] Function 0x1ac78 set X0 to binary address !
13/195: 0x1ac9c
14/195: 0x1acc8
[!!] Function 0x1acc8 set X0 to binary address !
15/195: 0x1acec
16/195: 0x1ad18
[!!] Function 0x1ad18 set X0 to binary address !
17/195: 0x1ad28
18/195: 0x1ad30
19/195: 0x1ad38
..................
```

As you can see, there are quite a few virtual functions that match our criteria. In the end, I chose the virtual function at `0x1ac3c`, which belongs to the relative vtable at `0x7878` ( with entry at `0x7888` ):

```
.text:000000000001AC3C ; const char *sub_1AC3C()
.text:000000000001AC3C sub_1AC3C
.text:000000000001AC3C ; __unwind {
.text:000000000001AC3C                 BTI             c
.text:000000000001AC40                 NOP
.text:000000000001AC44                 ADR             X0, aStdException ; "std::exception"
.text:000000000001AC48                 RET
.text:000000000001AC48 ; } // starts at 1AC3C
```

At this point, we have both the target virtual function and its vtable information. Now we can try replace the vtable in `calc` and leak the binary's base address. The process looks like this:

1. Use the sequence `Create int_arr -> Delete int_arr -> Create calc` to overlap `int_arr` and the `calc` object.
2. When creating `calc`, set `calc->num` so that after calling `calc->sum()`, the vtable will become `0x7880`.
3. Perform a calculation, which will trigger `calc->sum()` and replace the vtable. The next time we call `calc->eor()` ( XOR calculation ), it will trigger our target virtual function at `0x1ac3c`.
4. Perform one more calculation and call `calc->eor()`. This time the return value will be a pointer to the string `std::exception` inside the binary. Since this return value is printed as part of the status, we can use it to leak the binary's base address.

### Arbitrary read/write primitives

Once we have the binary's base address, controlling the vtable becomes much easier. We can first trigger an overlap using the sequence `Create calc -> Delete calc -> Create int_arr`, and during `Create int_arr` , we can directly set `int_0` and `int_1` to fully control the vtable address. The next step is to find suitable virtual functions to build arbitrary read/write primitives.

Let's start with arbitrary read. Again, we use angr to analyze the virtual functions. First, let's clarify a few things:
* When a virtual function is called, the X0 register holds the `this` pointer -- the address of the `calc` object.
* Since we can control `int_0` ~ `int_5`, we can forge the entire `calc` object, meaning that X0 will actually point to a controllable memory buffer ( 24 bytes in size ).

Ideally, we want to find a virtual function that looks something like this:

```c++
void Obj::func() {
  return this-a->b;
}
```

Since `this->a` is fully controlled, returning `this->a->b` would allow us to read arbitrary memory.

To use angr identify such functions, I used the following logic:
1. Before simulating a virtual function, set X0 to point to a memory buffer and symbolize its contents.
    - In other words, variables like `this->a` will be symbolic.
2. Add a callback for memory reads. If the function performs a memory read from an address that contains a symbolic variable, we can detect it.
    - Since `this->a` is symbolic, dereferencing it will trigger this detection.
3. Finally, check if X0 ( the return value ) contains a symbolic variable after the function finishes.
    - If so, it means the function's return value depends on the `this` pointer and may be useful for arbitrary read.

By combining steps 2 and 3, we can filter out candidate virtual functions that may provide an arbitrary read primitive. The full code can be found [here](https://github.com/bruce30262/CTF_challenge_public/blob/master/hitcon2025_qual/calc/solution/angr_scripts/find_symbolic_x0.py).

Here's what the output of the angr script looks like:

```
[-] Function at 0x35b5c does not perform symbolic reads
119/195: 0x35c40
************** Trying function: 0x35c40 ********************

[-] Function at 0x35c40 does not perform symbolic reads
120/195: 0x361d4
WARNING  | 2025-06-02 12:55:16,888 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0xffff800000000000 with 8 unconstrained bytes referenced from 0x361dc (offset 0x361dc in calc.strip (0x361dc))
WARNING  | 2025-06-02 12:55:17,057 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0xfffffffffffe0018 with 4 unconstrained bytes referenced from 0x361e0 (offset 0x361e0 in calc.strip (0x361e0))
WARNING  | 2025-06-02 12:55:17,484 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 mem_ffff800000000000_770_64 + SignExt(32, mem_fffffffffffe0018_771_32)>
************** Trying function: 0x361d4 ********************

[+] Function at 0x361d4 performs symbolic reads:
	At 0x361dc, read from symbolic addr: <BV64 Reverse(sym_buf_768_512[319:256])>
	At 0x361e0, read from symbolic addr: <BV64 mem_ffff800000000000_770_64 + 0x18>
121/195: 0x361ec
************** Trying function: 0x361ec ********************
......................................
```

Since the output is quite large, we can filter it using tools like `grep`:

```
> grep "symbolic X0" ./symbolic_x0.log

[+] Function at 0x1af00 has symbolic X0: <BV64 0x0 .. (if sym_buf_110_512[447:440] == 0 && sym_buf_110_512[439:432] == 0 && sym_buf_110_512[431:424] == 0 && sym_buf_110_512[423:416] == 0 && sym_buf_110_512[415:408] == 0 && sym_buf_110_512[407:400] == 0 && sym_buf_110_512[399:392] == 3 && sym_buf_110_512[391:384] == 0 then 0x1 else 0x0)>
[+] Function at 0x1af30 has symbolic X0: <BV64 0x0 .. (if (sym_buf_117_512[391:384] .. sym_buf_117_512[399:392] .. sym_buf_117_512[407:400] .. sym_buf_117_512[415:408] .. sym_buf_117_512[423:416] .. sym_buf_117_512[431:424] .. sym_buf_117_512[439:432] .. sym_buf_117_512[447:440]) == mem_f800000000000008_120_64 then 0x1 else 0x0)>
[+] Function at 0x36f70 has symbolic X0: <BV64 0xa148 + (mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31]
.. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32[31:31] .. mem_fffffffff000a148_799_32)>
[+] Function at 0x3ad64 has symbolic X0: <BV64 0x0 .. (if 64 <= mem_ffe0000000000009_976_8 then 0x0 else 0x1)>
[+] Function at 0x3ad98 has symbolic X0: <BV64 0x0 .. (if mem_fffffffffffff80a_981_8[1:0] == 0 then 0x1 else 0x0)>
[+] Function at 0x3adcc has symbolic X0: <BV64 0x0 .. (if mem_ffe0000000000009_985_16[11:10] == 0 then 0x1 else 0x0)>
[+] Function at 0x3bb80 has symbolic X0: <BV64 0x0 .. (if 64 <= mem_ff00000000000009_1026_8 then 0x0 else 0x1)>
[+] Function at 0x3bfb8 has symbolic X0: <BV64 0x0 .. (if 64 <= mem_ffffffffffe007f0_1037_8 then 0x0 else 0x1)>
[+] Function at 0x3c49c has symbolic X0: <BV64 0x0 .. (if 64 <= mem_fffffffffc000009_1045_8 then 0x0 else 0x1)>
[+] Function at 0x3ca94 has symbolic X0: <BV64 0x0 .. mem_fe00000000000000_1065_32>
```

We can see that several virtual functions meet the initial criteria. However, upon closer inspection, most of them look like this:

`.. (if 64 <= mem_ff00000000000009_1026_8 then 0x0 else 0x1)`

This means that X0 will return either 0 or 1 -- functions like these are not useful for our purposes and can be ignored.
In the end, there's one virtual function that meets our needs: `0x3ca94`, from relative vtable `0xa160`, with entry at `0xa174`:

```
.text:000000000003CA94                 BTI             c
.text:000000000003CA98                 SUB             SP, SP, #0x10
.text:000000000003CA9C                 STR             X0, [SP,#0x10+var_8]
.text:000000000003CAA0                 LDR             X8, [SP,#0x10+var_8]
.text:000000000003CAA4                 LDR             X8, [X8,#8]
.text:000000000003CAA8                 LDR             W0, [X8]
.text:000000000003CAAC                 ADD             SP, SP, #0x10
.text:000000000003CAB0                 RET
```

Looking at the assembly, we can see that by controlling the pointer at `[this + 8]`, we can achieve a 4-byte arbitrary read. With this primitive, we can read any memory address and leak the base address of libc.so.

For arbitrary write, the process is similar: use angr to analyze virtual functions and find a suitable target. Ideally, we want to find a function that look like this:

```c++
void Obj::func() {
  this->a->b = this->c;
}
```

Here's the approach I used:

1. Just like before, set X0 to point to a memory buffer and symbolize its contents.
2. Add a callback for memory writes, and detect:  
    (a) Whether the target address of the memory write contains a symbolic variable.  
    (b) Whether the value being written contains a symbolic variable.

Again, the full code is available [here](https://github.com/bruce30262/CTF_challenge_public/blob/master/hitcon2025_qual/calc/solution/angr_scripts/find_aaw.py).

With angr, we'll found another virtual function that matches our needs: `0x3CA70`, from relative vtable `0xa160`, with entry at `0xa170`:

```
.text:000000000003CA70                 BTI             c
.text:000000000003CA74                 SUB             SP, SP, #0x10
.text:000000000003CA78                 STR             X0, [SP,#0x10+var_8]
.text:000000000003CA7C                 LDR             X9, [SP,#0x10+var_8]
.text:000000000003CA80                 LDR             W8, [X9,#0x10]
.text:000000000003CA84                 LDR             X9, [X9,#8]
.text:000000000003CA88                 STR             W8, [X9]
.text:000000000003CA8C                 ADD             SP, SP, #0x10
.text:000000000003CA90                 RET
```

We can see that this function writes the value from `[this + 0x10]` into the pointer stored in `[this + 0x8]`. This gives us a 4-byte arbitrary write primitive.

> I'll admit that these two virtual functions were intentionally added to the challenge. The binary is kind of small so I have to cheat 😳. However, in real-world cases -- for example, in large Android apps -- it is actually not too difficult to find virtual functions with similar patterns. In Chrome, for example, [DictionaryIterator::Start](https://source.chromium.org/chromium/chromium/src/+/0229534930a7a1cf109e47eb459fe4f6b855944b:third_party/pdfium/core/fpdfapi/parser/cpdf_object_walker.cpp;l=58?q=DictionaryIterator::Start&ss=chromium) is a function that can be used for arbitrary read.
{: .prompt-info }


With these two virtual functions, we'll be able to achieve arbitrary read/write and proceed with further exploitation.

### Achieving code execution

Now that we have arbitrary read/write primitives, how can we turn this into an actual RCE ?

At first, I considered a few possible approaches:
* Overwriting the return address to hijack control flow: not possible, since PAC is enabled.
* Overwriting malloc hook or free hook: It's 2025, the "hook family" no longer works.

After several attempts and some online research, I came to a few realizations:
* The binary itself doesn't have many useful pointers that can be corrupted. It makes more sense to focus on corrupting pointers inside libc.so to hijack control flow.
* Besides return addresses and hooks, another potential vector is hijacking control flow during program termination -- specifically, by corrupting pointers used during cleanup.

That last idea caught my attention. I found several articles ( such as [this one](https://blog.csdn.net/a19106051385/article/details/145639028) ) mentioning that programs often perform cleanup at exit, and if we can corrupt certain pointers used during that phase, we may be able to achieve RCE.

So, I started digging into the libc.so used in this challenge. At startup, the program first calls `_libc_init(&a9, 0LL, main, v14);`, which then jumps into `main()`. After `main()` returns, `_libc_init` calls `exit()` to perform cleanup. While analyzing `exit()`, I noticed that it eventually calls a function named `_libc_stdio_cleanup()`, which contains the following code:

```c
void _libc_stdio_cleanup()
{
  v0 = &_sglue; // [1]
  do
  {
    v1 = *((_DWORD *)v0 + 2);
    if ( v1 >= 1 )
    {
      v2 = v0[2]; // [2]
      do
      {
        v4 = *(_DWORD *)(v2 + 16);
        if ( (v4 & 0x8008) == 8 )
        {
          v5 = *(_QWORD *)(v2 + 24);
          if ( v5 )
          {
            v6 = *(_DWORD *)v2;
            *(_QWORD *)v2 = v5;
            v7 = (v4 & 3) != 0 ? 0 : *(_DWORD *)(v2 + 32);
            v8 = v6 - v5;
            *(_DWORD *)(v2 + 12) = v7;
            if ( v6 - (int)v5 >= 1 )
            {
              while ( 1 )
              {
                v9 = (*(__int64 (__fastcall **)(_QWORD, __int64, _QWORD))(v2 + 80))( // [3]
                       *(_QWORD *)(v2 + 48),
                       v5,
                       (unsigned int)v8);
```

At [1], we can see that `v0` is a global data structure in libc.so. Then at [2], this data is loaded into `v2`, and finally at [3], the program reads a function pointer from `v2` and calls it ( with 1st argument also derived from `v2` ).

Looking at the assembly, we can confirm that libc.so does not use relative vtables here. This means that if we can control `v2`, we can control both the function pointer and its argument, allowing us to trigger something like `system("sh")`. Since we already have arbitrary read/write, this exploitation path is definitely viable.

I later found that this global variable is named `__sF`, which appears to be some kind of file stream structure. In fact, this technique is very similar to classic CTF pwn-style file stream attacks. However, there are a few things to watch out for when using this approach:

* We are overwriting a file stream pointer, and the main program might access it during runtime ( since it performs various I/O operations ). So, when overwriting the `__sF` pointer, we can only modify the lower 4 bytes ( via a single arbitrary write ).
    - Our arbitrary write primitive can only write 4 bytes at a time. If we try to overwrite 8 bytes ( in two writes ), there's a risk that after the first write, `__sF` will point to an invalid address ( or point to an invalid `__sF` structure ), causing the program to crash before the second write completes.
* Because we can only overwrite the lower 4 bytes, the fake `__sF` must located close to the original `__sF`, so that the high 32 bits remain unchanged.
    - In other words, we can't place the fake `__sF` on the heap.

In the end, I placed the fake `__sF` in libc.so's `.bss` section, so I didn't have to modify the high 32 bits of the pointer. By carefully crafting the fake structure -- adding the necessary data, a pointer to the "sh" string, and the address of `system()` -- I was able to trigger `system("sh")` during program exit, successfully spawning a shell.

The final exploit can be found [here](https://github.com/bruce30262/CTF_challenge_public/blob/master/hitcon2025_qual/calc/solution/exp/exp.py).

## Epilogue
In the end, only five teams managed to solve the challenge. This wasn’t too surprising, as it required a fair amount of effort ( e.g., using analysis tools ) to bypass the mitigations and ultimately spawn a shell.

Solutions shared by the teams during the post-game discussion on Discord include:
* Recovering RTTI and looking for suspicious classes and their vtables. I thought about this as well when preparing the challenge -- classic CTF-style solution 😄.
* Manually searching for suitable virtual functions. This is also feasible since there are only about 200 virtual functions stored in relative vtables, so once you get those functions with IDA script you could just scan through them all 😵.

As for other approaches, I'm curious about the possibility of leveraging AI ( e.g., MCP server ) to quickly filter out useful virtual functions for exploitation. [Shellphish was able to solve a binary challenge in just 12 minutes using AI at this year’s DEFCON](https://wilgibbs.com/blog/defcon-finals-mcp/) so I think it's doable. 

I'm also curious about how other teams managed to achieve code execution with arbitrary read/write primitives. While reviewing the network traffic during the competition, I noticed that four of the solving teams didn’t use my approach ( overwriting `__sF` and triggering it on program exit ) -- instead, they all relied on virtual functions in calc ( e.g., `calc->eor()` ) as the final trigger to spawn a shell. Interestingly, only one team ( team `[:]` if I recall correctly ) managed to spawn the shell upon exiting the program. I can’t help but wonder if they were using the same exploitation technique as mine, can't wait to see their write-ups :] .

Finally, special thanks to [Allen](https://x.com/nella17tw) for helping verify the challenge ( and to [Pumpkin](https://x.com/u1f383) and [Billy](https://x.com/st424204) for partially verifying it ). I hope you all enjoyed the challenge 😁.

Till next time !
## Reference
* [Relative VTables in C++](https://llvm.org/devmtg/2021-11/slides/2021-RelativeVTablesinC.pdf)
* [Enabling PAC and BTI on AArch64 for Linux](https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64)
* [Control Flow Integrity on Arm64 Systems](https://sipearl.com/wp-content/uploads/2023/10/SiPearl-White_Paper_Control_Flow_Integrity-on-Arm64.pdf)
* [angr - CTF wiki ( Chinese )](https://ctf-wiki.org/zh-tw/reverse/tools/simulate-execution/angr/)
* [CTF pwn 中 exit 利用姿势 ( Chinese )](https://blog.csdn.net/a19106051385/article/details/145639028)
