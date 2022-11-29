---
title: HITCON CTF 2022 -- Fourchain - Browser
categories:
- write-ups
date: '2022-11-28 12:19:22'
tags:
- CTF
- Pwnable
- heap
- shellcode
- use_after_free
- HITCON
- Browser
- Javascript
- Sandbox
- Chrome
---

Fourchain is a series of challenges created by me and Billy ( @st424204 ) for HITCON CTF 2022. The series consists of five pwnable challenges -- `Hole` ( V8 pwn ), `Sandbox` ( Chromium sandbox escaping ), `Kernel` ( Linux kernel LPE ), `Hypervisor` ( VirtualBox VM escaping ) and `One For All` ( From browser RCE to VM escape ). As you can see, challengers will have to pwn each service respectively, and create a fullchain exploits for all the vulnerable services in the final challenge.

In this post I'll cover some details about the browser part of the challenge. This won't be a full write-up since only some of them are about how to solve the challenges, the rest are just me rambling 😬.

If you want to see the whole browser fullchain exploit, [here's the link](https://gist.github.com/bruce30262/e1db7ebfb17c4724c5aee8629fb25f27).

<!-- more -->

## Fourchain - Hole

> Since the exploit method of this challenge has already been published to the public, this section is mainly about how I created this challenge.
{: .prompt-info }

The challenge is inspired by a vulnerability I analyzed back in April -- [CVE-2021-38003](https://bugs.chromium.org/p/chromium/issues/detail?id=1263462). I found the concept of exploiting the renderer by just leaking a single "Hole" value very interesting. So, after I done analyzing the vulnerability, I decided to create a simple CTF challenge based on this CVE and serve it as the first stage of the Fourchain series.

At first my idea was simple : I added a function in V8's array so the challenger can leak the Hole value with a simple `arr.hole();`. After that all they need to do is research the bug and write a RCE exploit. However, things didn't go as smooth as I planned ( they never did LOL ). 

First of all, the exploit method was later killed by [this patch](https://chromium-review.googlesource.com/c/v8/v8/+/3593783) ( submitted by @saelo. The patch was submitted just after I finished analyzing the CVE ). So now in order to make this challenge solvable, I had to remove this patch as well, which is not ideal to me since it will reveal the bug report and make the challenge easier. However, I later realized that the bug report only contains the PoC that will set a map's size into `-1` and nothing more. The challenger will still need to do the research and find a way to exploit it from there. So I thought "Hey, it might be easier, but it'll still take them some time to figure out the whole exploit. No need to worry about it...right ?" ( Spoil alert : I was wrong. So very wrong. )     

Fast forward to September, two months before the CTF, Numen Cyber Labs ( @numencyber ) published [this article](https://medium.com/numen-cyber-labs/from-leaking-thehole-to-chrome-renderer-rce-183dcb6f3078) about how you can exploit CVE-2021-38003 and turn it into a renderer RCE. Although it didn't provide the whole exploit, it did tell you how to use this bug to overwrite an array's length. After seeing this article, ~~I cried that day and mourned the death of my challenge.~~ I decided to just... let it go 😇. 

According to u1f383, the verifier of this challenge, he and me both agree that this is an easy challenge for an experienced browser pwner, and a medium challenge it you're new to browser exploitation. It's not like you can just copy and paste the exploit and get the flag right away, you still have to do some work, for example since the V8 sandbox is enabled you'll have to find another way to achieve RCE instead of just using the typical WASM trick. That being said I do believe the challenge become much more easier due to those public resources ( not complaining though, both @saelo and Numen Cyber Labs did an amazing job on patching and analyzing the vulnerability ).

As for the solution of this challenge, I recommend reading [this write-up](https://chovid99.github.io/posts/hitcon-ctf-2022/) by chovid99, it's detailed and very well written. Basically you overwrite an array's length with the bug, after that you should be able to create `addof` and arbitrary read/write primitive on V8 heap, then use [JIT spraying attack](https://mem2019.github.io/jekyll/update/2022/02/06/DiceCTF-Memory-Hole.html) to execute shellcode and achieve RCE. 

However, if you're using JIT spraying, there's one thing that you'll need to take care of : the offset of the JITed code. While I was testing my exploit on my Ubuntu VM, I found that the offset is slightly different than the one in the GCE instance. In order to get the exploit work, I solved it by increasing the offset one at a time, so was u1f383. I later found that this is a kernel issue since when I export the docker image ( using ubuntu 22.04 as base image ) on my local VM and import it into the GCE instance, the offset change automatically. 

After some discussions with u1f383, we both agreed that this could be a issue for the challenger. Considering that "figuring out why the exploit isn't working at remote side" is also part of the challenge in past CTFs, I didn't want to reveal too much details about the remote environment, so I ended up putting an extra note in challenge's README : "use Debian Linux 11.5.0", as I later found that it has the exact same offset as the remote one. The reason why I didn't release the docker configuration file is because even with the docker image, the exploit will still fail if you're on a Ubuntu machine, so there's no point releasing it. 

As expected, lots of players ran into this issue during the CTF. Most of them are able to solved it without asking too much questions. Others ran into problem like "I'm using a debian docker image, why it won't work ?", for such players I could only tell them "If it's not working, try something else. Other teams were able to solve it, so I can't reveal too much details.". Most of them were able to solve it in the end, so I don't think this issue was causing too much trouble.

Interestingly, after the CTF ended, team `organizers` show us a different approach in the discord channel:

![](/assets/images/Fourchain-Browser/b1.png)  

Basically they load the flag file into heap memory and read it out with the arbitrary read primitive in V8 heap ! That way they don't have to deal with the offset problem ! Interesting approach ! Although this also remind me that I should use a unique filename for the flag next time 😂.

Beside the "Hole" challenge itself, there are still some issues that need to be resolved though -- for example, although you can execute your own shellcode, how do you achieve arbitrary write and enable MojoJS for the Sandbox exploit ? Notice that the [trick](https://blog.kylebot.net/2022/02/06/DiceCTF-2022-memory-hole) that uses `imported_mutable_global` in WASM to achieve arbitrary read/write is no longer working since @saelo had submitted [another patch](https://chromium-review.googlesource.com/c/v8/v8/+/3845636) this August that killed this technique entirely. As for JIT spraying, since those floating-point numbers have to be fixed in order to get JITed, it's gonna be hard to leak the address first then generate the shellcode dynamically. So what should we do ? We'll continue this discussion in the later section.


## Fourchain - Sandbox

The Sandbox challenge is inspired by a well known bug pattern in the Mojo IPC, which is the misuse of `base::Unretained()`. Basically when you try to post a task in Chrome, you would do something like:

```cpp
// Posting TaskA ( a callback ) to a thread and execute it
task_runner->PostTask(FROM_HERE, base::BindOnce(&TaskA));
```

If the task is a member function of a class, then it would be something like:

```cpp
A a; // A is a class
task_runner_for_a->PostTask(
    FROM_HERE,
    // This is like calling A::AddValue(this, 42);
    base::BindOnce(&A::AddValue, base::Unretained(&a), 42) 
);
```

The `base::Unretained()` here means that it's the callback's ( `A::AddValue()` in this case ) responsibility to ensure that the `this` pointer of `a` is alive during the execution of the callback. If `a` got deleted before the thread execute the callback, it will cause a UAF. Normally it is recommended that we use `base::WeakPtr` instead of `base::Unretained()`, you can check the [official document](https://chromium.googlesource.com/chromium/src/+/master/docs/threading_and_tasks.md) from Chrome if you want to know more details. 

This kind of bug happens a lot in the Mojo IPC. While I was reading bug reports from Chromium bug tracker, lots of them were UAF caused by the misuse of `base::Unretained()`, and the patch of those bugs were mostly done by replacing `base::Unretained()` with weak pointers. 

So I thought this would be a suitable bug for a CTF challenge. The idea is to create a simple UAF bug caused by `base::Unretained()` that will allow attackers to gain code execution from it. Unfortunately, due to my ~~procrastination~~ busy schedule, I didn't have enough time and can only came up with a boring "sandbox" Mojo service that allow users to "pour sand" into boxes:

```cpp
void SandboxImpl::PourSand(const std::vector<uint8_t>& sand) {
    if ( this->isProcess_ || sand.size() > 0x1100 )  return;

    this->isProcess_ = true;
    content::GetIOThreadTaskRunner({})->PostTask(
        FROM_HERE,  
        base::BindOnce(&SandboxImpl::Pour, base::Unretained(this), sand) // [1]
    );
}

void SandboxImpl::Pour(const std::vector<uint8_t>& sand) {
    size_t sand_sz = sand.size(), i = 0;
    if (sand_sz > 0x800) {
        std::vector<uint8_t> sand_for_box(sand.begin(), sand.begin()+0x800);
        this->backup_ = std::make_unique<std::vector<uint8_t>>(sand.begin()+0x800, sand.end()); // [2]
        this->PourSand(sand_for_box); // [3]
    } else {
        for ( i = 0 ; i < sand_sz ; i++) {
            this->box_[i] = sand[i];
        }
    }
    this->isProcess_ = false;
}
```

The bug is quite obvious : at [1], the service post a task to the IO thread which will do `SandboxImpl::Pour()`. If we can delete the `SandImpl` object before the callback was called, you'll get a UAF during `SandboxImpl::Pour()`. At [2] you can do heap allocation with a controlled size, so if you control it correctly, you can reuse the memory that had just been deleted, making `this` ( now a dangling pointer ) and the data in `this->backup_` both using the same memory ( which its content is controllable ). After that, the service will call `SandboxImpl->PourSand()` again ( [3] ), and since it's a virtual function call, you'll be able to hijack the control flow. Here's the PoC:

```javascript
B = [];
for (i = 0; i < 0x100; i++) {
    B.push(null);
    B[i] = new blink.mojom.SandboxPtr();
    Mojo.bindInterface(blink.mojom.Sandbox.name, mojo.makeRequest(B[i]).handle);
}

let data = new ArrayBuffer(0x820 + 0x800);
let b64arr = new BigUint64Array(data);
let u8arr = new Uint8Array(data);

b64arr.fill(BigInt(0x4141414141414141));

// trigger vulnerability by racing PourSand() and delete
for (i = 0; i < 0x100; i++) {
    await B[i].pourSand(u8arr);
    await B[i].ptr.reset();
}
```

The reason why we set `ArrayBuffer`'s size into `0x820 + 0x800` is because `0x820` is the size of a `SandImpl` object ( you can confirm it by looking at the `content::SandboxImpl::Create()` function in gdb ). The first `0x800` bytes will be put into `this->box_`, and the rest of the `0x820` bytes will be allocated and put into `this->backup_`. If we can delete the `SandImpl` object before it allocate the data in `PourSand()`, we'll be able to control the dangling `SandImpl` object with our own data.

As for address leaking, there's `GetTextAddress` and `GetHeapAddress` to make your life easier. With these two functions we will be able to know the address of our ROP chain and the heap memory. Pick a heap buffer, put our ROP chain and a fake vtable on it, we should be able to hijack the control flow and achieve RCE when it calls `this->PourSand(sand_for_box);`. 

## Chaining it together

So this is where I consider to be the "fun part" of the challenge. 

We all know that in order to chain our renderer and Mojo exploits, we'll have to leak the base address of the chrome binary, figure out where the `blink::RuntimeEnabledFeaturesBase::is_mojo_js_enabled_` variable is, then overwrite the variable with `1`. 

However this is not an easy task if we're going to do it on a "modern" Chromium browser. The main reason is that since now V8 sandbox is enabled:

* Lots of pointers are now caged instead of being a raw pointer. This restrict our ability to do arbitrary read/write in the renderer.
* Also since most pointers are now caged, it's hard to find a pointer that points to the chrome binary on the V8 heap. Most of them are now compressed pointers or raw heap pointers. 
* Although we have shellcode execution and can use it to achieve arbitrary write, however those shellcode are in immediate numbers, meaning it has to be fixed before it got JITed. I haven't try it yet, but I think it would be a PITA if we try to leak the address first *then* generate the shellcode dynamically ( Not to mention JIT-ing function in the end of our exploit might break our primitives due to garbage collection ).

So now our challenge would be:
1. How can we leak chrome's base address in the renderer process ?
2. How can we achieve arbitrary write and overwrite `is_mojo_js_enabled_` ?

From what I know, in the past the first one can be solved by leaking the pointer in the `window` object ( [ref](https://balsn.tw/ctf_writeup/20210717-googlectf2021/#fullchain) ), or by reading pointers in a blink object such as `OfflineAudioContext` ( [ref](https://securitylab.github.com/research/in_the_wild_chrome_cve_2021_37975/) ). However, both techniques no longer work on modern Chromium browser now, so we'll have to find another way to achieve this.

While I was researching the V8 sandbox, I tried to see how ArrayBuffer store its data pointer, and this is what I found ( `0x3b740004990d` stores an ArrayBuffer ):

![](/assets/images/Fourchain-Browser/ab.png)

We can see that there's a heap buffer ( `0x18e0008efa80` ) in the ArrayBuffer's structure. By looking at that heap buffer, we'll notice that it stores another heap buffer ( `0x18e0008c6c20` ), which stores a pointer that points to the chrome binary. That pointer is actually `std::Cr::__shared_ptr_pointer<v8::internal::BackingStore*,std::Cr::default_delete<v8::internal::BackingStore>,std::Cr::allocator<v8::internal::BackingStore> > + 0x10`. We can use `nm` and try to get its offset in the chrome binary:

```
# nm ./chrome | grep "_ZTVNSt2Cr20__shared_ptr_pointerIPN2v88internal12BackingStoreENS_14default_deleteIS3_EENS_9allocatorIS3_EEEE"
# 000000000d9b63f0 d _ZTVNSt2Cr20__shared_ptr_pointerIPN2v88internal12BackingStoreENS_14default_deleteIS3_EENS_9allocatorIS3_EEEE
```

So, if we can traverse the structure of an ArrayBuffer, we can get that pointer and calculate the base address of chrome by doing `ptr - 0x10 - 0xd9b63f0`. After that, we can calculate the address of `is_mojo_js_enabled_` and overwrite it to enable MojoJS. The question is, how are we able to do that ?

Remember that we already have the ability to execute our own shellcode. By looking at the context of the moment we jump to our shellcode, we'll found that the **rdi register stores the address of the JITed function object itself**. This is what we can make use of : we can put an object that contains the chrome pointer inside the function object, then start traverse the object from the rdi register. After we traverse the object and get the chrome pointer, we then can calculate the address of `is_mojo_js_enabled_` and overwrite it to `1`.

In my final exploit, I ended up storing the heap buffer address ( `0x18e0008efa80`, which can be leaked by using the V8 heap arbitrary read primitive ) in my JITed function object, then write a shellcode that can traverse the pointers in the heap buffer and get the chrome pointer. After getting it the rest is easy, just overwrite the `is_mojo_js_enabled_` variable into `1` and reload the page, we'll be able to use MojoJS and start our sandbox exploit.

During the discussion in the discord channel after the CTF ended, `organizers` said they found a way to turn arbitrary r/w inside the cage ( V8 heap ) into arbitrary r/w everywhere. I'm really curious how they did it, can't wait to see their write-up !

## Epilogue

In the end, 25 teams solved the `Fourchain - Hole` challenge, while only 5 teams were able to solve `Fourchain - Sandbox`. I'm kind of surprised that Sandbox only got 5 solved, was expecting more since I thought the bug is not that hard to trigger, and after you found the crash the rest should be easy -- you already have the text and heap address, so just put your payload in a known address and jump to it. Anyway, either solved it or not, I hope you all enjoyed my browser challenges during the CTF 🙂.
