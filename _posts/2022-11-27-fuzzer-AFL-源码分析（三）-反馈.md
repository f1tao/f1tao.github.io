---
layout: post
title: fuzzer AFL 源码分析（三）-反馈
date: 2022-11-27
Author: f1tao
tags: [fuzz, afl]
comments: true
toc: true
---

上一部分对`afl-fuzz`的总流程进行了概要性的阐述，接下来将会对关键的代码模块进行详细的分析。

先对`afl-fuzz`过程中反馈与监控机制的实现进行分析，反馈是指`afl`在对目标程序的模糊测试过程中，目标程序可以将本次运行过程中的状态反馈给`afl`。本文主要介绍该`afl`是如何具体实现分支信息的记录以及更高效的运行目标程序的。

## 基础知识-system V共享内存

进行介绍前，要先对共享内存有一定的了解与掌握，详细的可以去看之前写的《进程共享内存技术》，这里只阐述和`afl`相关的`SYSTEM V`共享内存。

共享内存就是多个进程间共同使用同一段物理内存空间，它是通过将同一段物理内存映射到不同进程的虚空间中来实现的。由于映射到不同进程的虚拟地址空间中，不同进程可以直接使用,不需要进行内存的复制，所以共享内存的效率很高。

### 基本介绍

`System V`曾经也被称为`AT&T System V`，是`Unix`操作系统众多版本中的一支。它最初由`AT&T`开发，在1983年第一次发布。一共发行了4个`System V`的主要版本：版本1、2、3和4。

`System V`共享内存机制为了在多个进程之间交换数据，内核专门留出了一块内存区域用于共享，共享这个内存区域的进程就只需要将该区域映射到本进程的地址空间中即可。内核直接实现了`shmget/at`系统调用，最终也是靠`tmpfs`来实现的。

`System V`的`IPC`对象有共享内存、消息队列、信号灯(量)。注意：在`IPC`的通信模式下，不管是共享内存、消息队列还是信号灯，每个`IPC`的对象都有唯一的名字，称为"键(`key`)"。通过"键"，进程能够识别所用的对象。"键"与`IPC`对象的关系就如同文件名称于文件，通过文件名，进程能够读写文件内的数据，甚至多个进程能够公用一个文件。而在`IPC`的通信模式下，通过"键"的使用也能使得一个`IPC`对象能为多个进程所共用。

### 使用步骤

共享内存的使用过程可分为 创建->连接->使用->分离->销毁 这几步。

1. 创建/打开共享内存
2. 映射共享内存，即把指定的共享内存映射到进程的地址空间用于访问
3. 撤销共享内存的映射
4. 删除共享内存对象

执行过程先调用`shmget`，获得或者创建一个`IPC`共享内存区域，并返回获得区域标识符。类似于`mmap`中先`open`一个磁盘文件返回文件标识符一样。
再调用`shmat`，完成获得的共享区域映射到本进程的地址空间中，并返回进程映射地址。类似与`mmap`函数原理。
使用完成后，调用`shmdt`解除共享内存区域和进程地址的映射关系。每个共享的内存区，内核维护一个`struct shmid_ds`信息结构，定义在`sys/shm.h`头文件中

### 相关API

```c
#include<sys/ipc.h>
#include<sys/shm.h>

int shmget(key_t key, size_t size, int shmflg)
```

共享内存的创建使用`shmget`函数（`shared memory get`）函数。`shmget`根据`shm_key`创建一个大小为`page_size`的共享内存空间，参数`shmflag`是一系列的创建参数。如果`shm_key`已经创建，使用该`shm_key`会返回可以连接到该以创建共享内存的`id`。

调用成功返回一个`shmid`(类似打开一个或创建一个文件获得的文件描述符一样)，调用失败返回`-1`。

```c
#include<sys/types.h>
#include<sys/shm.h>

void * shmat(int shmid, const void *shmaddr, int shmflg);
```

创建后，为了使共享内存可以被当前进程使用，必须紧接着进行连接操作。使用函数`shmat`（`shared memory attach`），参数传入通过`shmget`返回的共享内存`id`即可。
`shmat`返回映射到进程虚拟地址空间的地址指针，这样进程就能像访问一块普通的内存缓冲一样访问共享内存。

```c
int shmdt(const void * shmadr);
```

当共享内存使用完毕后，使用函数`shmdt` (`shared memory detach`)进行解连接。该函数以`shmat`返回的内存地址作为参数。

单个进程`detach`时，并不会从内核中删除该共享内存，而是把相关`shmid_ds`结构的`shm_nattch`域的值减`1`，当这个值为0时，内核才从物理上删除这个共享内存。即最后一个使用该共享内存的进程并`detach`该共享内存后，内核将会自动销毁该共享内存自动销毁。当然，最好能显式的进行销毁，以避免不必要的共享内存资源浪费。 

```c
#inlcude<sys/ipc.h>
#include<sys/shm.h>

int shmctl(int shmid, int cmd, struct shmid_ds *buf);
```

函数`shmctl` (`shared memory control`)可以返回共享内存的信息并对其进行控制。通过`cmd`指定相应的控制操作，具体包括`IPC_STAT`（得到共享内存的状态）`IPC_SET`（改变共享内存的状态）、`IPC_RMID`（删除共享内存）;`buf`是一个结构体指针，`IPC_STAT`时，获取内存状态并存储在`buf`种。如果要改变共享内存的状态，通过`buf`来进行设定。

### 示例

`writer`：

```c
/***** writer.c *******/
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv)
{
    int shm_id,i;
    key_t key;
    char buff[0x20];
    char* p_map;
    char* name = "./test_shm";

    setbuf(stdin, 0);
    setbuf(stdout, 0);

    key = ftok(name,0);
    if(key==-1)
        perror("ftok error");
  
    shm_id=shmget(key,4096,IPC_CREAT);    
    if(shm_id==-1)
    {
        perror("shmget error");
        return;
    }
    p_map=(people*)shmat(shm_id,NULL,0);
  
  	printf("[+] shared memory in writer's addr: %p\n", p_map);
    
  	printf("[+] input: ");
  	read(0, buff, 0x20);
  	memcpy(p_map, buff, strlen(buff));
    if(shmdt(p_map)==-1)
        perror(" detach error ");
}
```

`reader`：

```c
/********** reader.c ************/
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
int main(int argc, char** argv)
{
    int shm_id,i;
    key_t key;
    char* p_map;
    char* name = "./test_shm";
    key = ftok(name,0);
    if(key == -1) {
        perror("ftok error");
      	return -1;
    }
    shm_id = shmget(key,4096,IPC_CREAT);    
    if(shm_id == -1)
    {
        perror("shmget error");
        return -1;
    }
    p_map = (char *)shmat(shm_id,NULL,0);
    printf("%s\n",p_map);
    if(shmdt(p_map) == -1) {
        perror(" detach error ");
      	return -1;
    }
}
```

我试了试，需要用`root`权限运行。

运行结果：

![writer](https://raw.githubusercontent.com/f1tao/f1tao.github.io/master/images/2022-11-27-fuzzer-AFL-源码分析（三）-反馈/writer.png)

![reader](https://raw.githubusercontent.com/f1tao/f1tao.github.io/master/images/2022-11-27-fuzzer-AFL-源码分析（三）-反馈/reader.png)

## 反馈信息记录

`afl`是基于反馈的模糊测试工具，能够根据样本的运行记录目标程序的反馈信息并判断是否样例是否有效。一个理所当然的问题则是记录的反馈信息是什么？

根据`afl`的技术白皮书[Technical "whitepaper" for afl-fuzz](https://lcamtuf.coredump.cx/afl/technical_details.txt)，在目标程序运行过程中记录的信息是程序的覆盖率，而这个覆盖率具体落实则是边覆盖率。在程序插桩的过程中会在每个基本块插入一个随机值作为唯一编号，当样本从一个基本块运行到另一个基本块的时候会根据两个块的唯一的编号形成一条边，以此形成覆盖率。

具体来说，在`fuzzer`初始化的过程中会利用`system V`共享内存申请一片`64KB`大小的共享内存，并将对应的`id`值存入到环境变量当中，这片共享内存用于记录目标程序运行的边覆盖率；`forkserver`调用`fork`运行目标程序，目标程序运行到分支时，通过全局的当前基本块的唯一编号与前一个基本块的唯一编号的异或作为边的标记，并在对应的数组位置加`1`，以此来实现分支路径的覆盖以及分支运行次数的统计，公式如下所示。

```c
  cur_location = <COMPILE_TIME_RANDOM>;
  shared_mem[cur_location ^ prev_location]++; 
  prev_location = cur_location >> 1;
```

为什么后续要将`cur_location>>1`再放入到`prev_location`中，是为了避免路径`A->B`以及`B->A`二者值一致，也是为了避免`A->A`以及`B->B`出现的结果也是一致的情况。

记录的值有两个含义，初始化状态下每条边的值为`0`，当它存在值的时候说明该边已经运行过，值的多少说明该边在此次的样例运行个多少次。

前面说过每个基本块前插入的编号是随机值，随机值是从共享内存的大小`64KB`的空间内产生的，因此分支数量增加的时候，可能会出现分支得到的随机值是相同的情况（碰撞），总的来说，应用程序的分支路径在`2k`到`10k`的数量级的随机值的碰撞情况还是可以接受的。

```bash
   Branch cnt | Colliding tuples | Example targets
  ------------+------------------+-----------------
        1,000 | 0.75%            | giflib, lzo
        2,000 | 1.5%             | zlib, tar, xz
        5,000 | 3.5%             | libpng, libwebp
       10,000 | 7%               | libxml
       20,000 | 14%              | sqlite
       50,000 | 30%              | -
```

## forkserver

一般来说正常的基于反馈式的模糊测试工具的工作原理是对目标程序进行代码插桩，然后`fuzzer`通过调用`execve`来运行目标程序，记录运行过程中记录目标程序的运行状态，目标程序通过进程通信机制等将运行状态反馈给`fuzzer`，`fuzzer`判断此次运行的样本是否为有效样本，如果有效则保存该样本，如果无效则丢弃。下一轮循环时再调用`execve`进行新一轮的目标程序模糊测试。

每次运行目标程序都需要调用一次`execve`性能消耗太大，`execve`花费在进程初始化（外部库的加载、符号的解析）是多余且耗时的，为了更高效的运行，`afl`设计实现了[forkserver](https://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html)机制。

`fork`系统调用会继承父进程的状态，包括内存以及句柄等，因此可在通过插桩在目标程序初始化完成之后创建一个`forkserver`，由`forkserver`在循环中不断的调用`fork`去执行目标程序的主体功能，同时与`fuzzer`进行通信，从而减少了`execve`初始化过程中的性能消耗。

具体来说`fuzzer`先创建两个管道`st_pipe`以及`ctl_pipe`，`st_pipe`用于`forkserver`向`fuzzer`传递状态，`ctl_pipe`用于`fuzzer`向`forkserver`传递控制信息。`fuzzer`调用`fork`函数创建子进程调用`execve`启动目标程序，目标程序经过插桩后，在`main`函数执行的时候会形成`forkserver`；`forkserver`通过`ctl_pipe`，`st_pipe`与`fuzzer`进行通信。根据`fuzzer`的指令，`forkerver`再循环调用`fork`去执行目标程序，并记录相应的反馈信息。

## 源码分析

下面从源码的角度详细阐述上面两个过程。

### 反馈信息记录

在`afl-as`对汇编代码插桩的过程中我们已分析过，`afl`会在相应的分支位置插入插桩代码。插入的代码如下所示，可以看到会调用`R(MAP_SIZE)`生成路径编号随机值，通过格式化字符串的形式将`trampoline_fmt_64`或`trampoline_fmt_32`插入到代码。

```c
// afl-as.c: 270
fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));

// types.h: 82
#  define R(x) (random() % (x))

// config.h: 328
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
```

后面通过`64`位的代码（`trampoline_fmt_64`以及`main_payload_64`）来学习相应的插桩代码，先看`trampoline_fmt_64`，如下所示：

```c
static const u8* trampoline_fmt_64 =

  "\n"
  "/* --- AFL TRAMPOLINE (64-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leaq -(128+24)(%%rsp), %%rsp\n"
  "movq %%rdx,  0(%%rsp)\n"
  "movq %%rcx,  8(%%rsp)\n"
  "movq %%rax, 16(%%rsp)\n"
  "movq $0x%08x, %%rcx\n"
  "call __afl_maybe_log\n"
  "movq 16(%%rsp), %%rax\n"
  "movq  8(%%rsp), %%rcx\n"
  "movq  0(%%rsp), %%rdx\n"
  "leaq (128+24)(%%rsp), %%rsp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";
```

代码开辟新的栈空间，然后保存`rdx`、`rcx`以及`rax`三个后续会被破坏的寄存器（`scratch register`），同时将该代码块的编号（随机值）保存到`rcx`中（`R(MAP_SIZE)`的值）；后调用`__afl__maybe_log`函数记录分支，函数调用完成后恢复现场并继续程序原有功能的运行。

跟进去`__afl_maybe_log`函数，在`main_payload_64`中，如下所示，功能是：

`lahf`指令将标志寄存器的低八位送入`AH`寄存器，即将标志寄存器`FLAGS中`的`SF`、`ZF`、`AF`、`PF`、`CF`五个标志位分别传送到`AH`的对应位（八位中有三位是无效的）；`seto`指令将溢出寄存器`OF`保存到`al`中，前两条指令的作用是保存标志寄存器到`ax`中。

然后查看`__afl_area_ptr`全局变量中的值是否为空。如果是空，说明`forkserver`未初始化，共享内存指针没有值，需要跳到`__afl_setup`处去初始化`forkserver`；如果不为空则可以直接在共享内存将此次的分支运行次数加`1`。

此处先介绍记录分支（`__afl_store`）的过程，`forkserver`初始化部分后面再进行介绍。

上条分支的编号值在`__afl_prev_loc`全局变量中，与当前分支的编号值`rcx`进行异或，保存在`rcx`寄存器中的值；将异或后的`rcx`值再与`__afl_prev_loc`全局变量异或保存在`__afl_prev_loc`全局变量中，实现将当前变量的编号保存在`__afl_prev_loc`中；而后将该变量值右移一位完成`prev_location = cur_location >> 1`步骤；将异或后的`rcx`加上共享内存指针`__afl_area_ptr`，并将该处的值加`1`实现分支信息的记录，完成`shared_mem[cur_location ^ prev_location]++`步骤。

`addb $127, %al`恢复溢出寄存器标识位（前面如果被置位的话，这里加`127`会溢出，实现置位），`sahf`指令恢复其余的标志位寄存器，恢复现场，`__afl_maybe_log`结束，分支记录完成。

```c
static const u8* main_payload_64 = 

  "\n"
  "/* --- AFL MAIN PAYLOAD (64-BIT) --- */\n"
  "\n"
  ".text\n"
  ".att_syntax\n"
  ".code64\n"
  ".align 8\n"
  "\n"
  "__afl_maybe_log:\n"
  "\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9f /* lahf */\n"
#else
  "  lahf\n"
#endif /* ^__OpenBSD__, etc */
  "  seto  %al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movq  __afl_area_ptr(%rip), %rdx\n"
  "  testq %rdx, %rdx\n"
  "  je    __afl_setup\n"
  "\n"
  "__afl_store:\n"
  "\n"
  "  /* Calculate and store hit for the code location specified in rcx. */\n"
  "\n"
#ifndef COVERAGE_ONLY
  "  xorq __afl_prev_loc(%rip), %rcx\n"
  "  xorq %rcx, __afl_prev_loc(%rip)\n"
  "  shrq $1, __afl_prev_loc(%rip)\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%rdx, %rcx, 1)\n"
#else
  "  incb (%rdx, %rcx, 1)\n"
#endif /* ^SKIP_COUNTS */
  "\n"
  "__afl_return:\n"
  "\n"
  "  addb $127, %al\n"
#if defined(__OpenBSD__)  || (defined(__FreeBSD__) && (__FreeBSD__ < 9))
  "  .byte 0x9e /* sahf */\n"
#else
  "  sahf\n"
#endif /* ^__OpenBSD__, etc */
  "  ret\n"
  "\n"
  ".align 8\n"
  "\n"
```

### forkserver

下面来看`forkserver`的创建过程。

`forkserver`的创建主要包括`fuzzer`初始化共享内存，调用`fork`运行目标程序，在目标程序中初始化`forkserver`。

共享内存的初始化是`afl-fuzz`的`main`函数中的`setup_shm`函数实现的，如下所示。可以看到用`SYSTEM V`共享内存机制创建了`64KB`大小的共享内存，并将`id`存放到了环境变量`SHM_ENV_VAR`中。

```c
/* Configure shared memory and virgin_bits. This is called at startup. */

EXP_ST void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode) setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (trace_bits == (void *)-1) PFATAL("shmat() failed");

}
```

初始化`forkserver`的函数则是`init_forkserver`，由`calibrate_case`函数调用，当`forksrv_pid`没有值的时候，说明`forkserver`尚未初始化，调用`init_forkserver`。

```c
// afl-fuzz.c: 2567
static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  ...
	// afl-fuzz.c: 2601
  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);
```

跟进去`init_forkserver`，如下所示。先调用`pipe`函数创建了状态传输管道`st_pipe`以及控制传输管道`ctl_pipe`。

```c
// 
EXP_ST void init_forkserver(char** argv) {

  ...

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();
```

在子进程中调用`setrlimit`函数为子进程设定相应的资源空间，具体包括申请足够的文件句柄（因为子进程中需要用`FORKSRV_FD`来传输）、创建足够的内存空间（`-m`参数指定的）、设置内存转储文件大小为`0`（崩溃后转储会影响性能，因此设置它为0）。

调用`setsid`让子进程成为独立的进程，不受父进程影响。

将子进程的标准输出以及标准错误句柄重定向到`null`句柄，如果目标程序的输入是来自于文件的话，则将子进程的标准输入也重定向到`null`句柄（因为无需从标准输入获取数据，所以就没用了），如果目标程序的输入来源于标准输入，则将标准输入重定向到`out_fd`，`out_fd`是变异后的样例文件的路径。

将控制管道的读句柄（`ctl_pipe[0]`）重定向到`FORKSRV_FD`，用于读取`fuzzer`传递过来的控制信息；将状态管道的写句柄（`st_pipe[1]`）重定向到`FORKSRV_FD + 1`，用于写运行样例后返回的状态，传递给`fuzzer`。

然后关掉不需要的句柄，并适当设置一些环境变量。

最后调用`execve`运行目标程序，因为`execve`不会返回，如果返回就意味着出错了，所以也在`execve`后面加上`*(u32*)trace_bits = EXEC_FAIL_SIG;`，父进程如果发现`trace_bits`的值是`EXEC_FAIL_SIG`，则说明目标程序没有运行起来，出现了错误。

```c
	// afl-fuzz.c: 2020
	if (!forksrv_pid) {

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }
```

看完了子进程，我们再来看看父进程干了啥，代码如下所示。

先关闭`ctl_pipe[0]`及`st_pipe[1]`，因为这是子进程用到的句柄，父进程不需要。将控制管道的写句柄（`ctl_pipe[1]`）保存到全局变量`fsrv_ctl_fd`，将状态管道的读句柄（`st_pipe[0]`）保存到全局变量`fsrv_st_fd`中。然后调用`setitimer`函数设置超时时限，调用`read(fsrv_st_fd, &status, 4)`函数等待状态管道传回数据（前面子进程起来以后，会传回`4`字节的`hello`消息），接收到该信息后（`rlen == 4`）表明`forkserver`已经正常启动了；否则说明`forkserver`启动失败，通过子进程返回的消息以及看`trace_bits`是否是`EXEC_FAIL_SIG`去看失败的原因。

```c
	// afl-fuzz.c: 2127
	/* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {
		...
  }
	if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    ...
  }
	FATAL("Fork server handshake failed");
```

分析完成以后我们再看子进程启动以后目标程序干了什么，在前面反馈信息记录中我们已经分析过插桩代码在判断全局变量共享内存指针`__afl_area_ptr`为空的时候，会跳到`__afl_setup`去初始化`forkserver`，跟进去该标签代码。

开始判断是否已经初始化失败（`__afl_setup_failure`为`1`）过一次了，如果是的话则直接返回；查看全局变量`__afl_global_area_ptr`是否有值，如果有的话，说明已经初始化过了可直接跳到`__afl_store`，否则去`__afl_setup_first`标签处进行初始化。

```c
  // afl-as.h: 442
	"__afl_setup:\n"
  "\n"
  "  /* Do not retry setup if we had previous failures. */\n"
  "\n"
  "  cmpb $0, __afl_setup_failure(%rip)\n"
  "  jne __afl_return\n"
  "\n"
  "  /* Check out if we have a global pointer on file. */\n"
  "\n"
#ifndef __APPLE__
  "  movq  __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
  "  movq  (%rdx), %rdx\n"
#else
  "  movq  __afl_global_area_ptr(%rip), %rdx\n"
#endif /* !^__APPLE__ */
  "  testq %rdx, %rdx\n"
  "  je    __afl_setup_first\n"
  "\n"
  "  movq %rdx, __afl_area_ptr(%rip)\n"
  "  jmp  __afl_store\n" 
  "\n"
```

来看`__afl_setup_first`处的代码，如下所示。可以看到一开始是开辟新的栈空间，然后保存所有的寄存器，这一步主要是保存现场环境，避免初始化破坏了程序原有的运行环境。

```c
  // afl-as.h: 463
	"__afl_setup_first:\n"
  "\n"
  "  /* Save everything that is not yet saved and that may be touched by\n"
  "     getenv() and several other libcalls we'll be relying on. */\n"
  "\n"
  "  leaq -352(%rsp), %rsp\n"
  "\n"
  "  movq %rax,   0(%rsp)\n"
  "  movq %rcx,   8(%rsp)\n"
  "  movq %rdi,  16(%rsp)\n"
  "  movq %rsi,  32(%rsp)\n"
  "  movq %r8,   40(%rsp)\n"
  "  movq %r9,   48(%rsp)\n"
  "  movq %r10,  56(%rsp)\n"
  "  movq %r11,  64(%rsp)\n"
  "\n"
  "  movq %xmm0,  96(%rsp)\n"
  "  movq %xmm1,  112(%rsp)\n"
  "  movq %xmm2,  128(%rsp)\n"
  "  movq %xmm3,  144(%rsp)\n"
  "  movq %xmm4,  160(%rsp)\n"
  "  movq %xmm5,  176(%rsp)\n"
  "  movq %xmm6,  192(%rsp)\n"
  "  movq %xmm7,  208(%rsp)\n"
  "  movq %xmm8,  224(%rsp)\n"
  "  movq %xmm9,  240(%rsp)\n"
  "  movq %xmm10, 256(%rsp)\n"
  "  movq %xmm11, 272(%rsp)\n"
  "  movq %xmm12, 288(%rsp)\n"
  "  movq %xmm13, 304(%rsp)\n"
  "  movq %xmm14, 320(%rsp)\n"
  "  movq %xmm15, 336(%rsp)\n"
  "\n"
```

然后是调用`getenv`函数从环境变量中`SHM_ENV_VAR`获取之前`setup_shm`函数存放的共享内存的`id`，然后调用函数`shmat`获取共享内存的地址，并将其存放到`__afl_area_ptr`变量中。

```c
  // afl-as.h: 496
	"  /* Map SHM, jumping to __afl_setup_abort if something goes wrong. */\n"
  "\n"
  "  /* The 64-bit ABI requires 16-byte stack alignment. We'll keep the\n"
  "     original stack ptr in the callee-saved r12. */\n"
  "\n"
  "  pushq %r12\n"
  "  movq  %rsp, %r12\n"
  "  subq  $16, %rsp\n"
  "  andq  $0xfffffffffffffff0, %rsp\n"
  "\n"
  "  leaq .AFL_SHM_ENV(%rip), %rdi\n"
  CALL_L64("getenv")
  "\n"
  "  testq %rax, %rax\n"
  "  je    __afl_setup_abort\n"
  "\n"
  "  movq  %rax, %rdi\n"
  CALL_L64("atoi")
  "\n"
  "  xorq %rdx, %rdx   /* shmat flags    */\n"
  "  xorq %rsi, %rsi   /* requested addr */\n"
  "  movq %rax, %rdi   /* SHM ID         */\n"
  CALL_L64("shmat")
  "\n"
  "  cmpq $-1, %rax\n"
  "  je   __afl_setup_abort\n"
  "\n"
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  movq %rax, %rdx\n"
  "  movq %rax, __afl_area_ptr(%rip)\n"
  "\n"
#ifdef __APPLE__
  "  movq %rax, __afl_global_area_ptr(%rip)\n"
#else
  "  movq __afl_global_area_ptr@GOTPCREL(%rip), %rdx\n"
  "  movq %rax, (%rdx)\n"
#endif /* ^__APPLE__ */
  "  movq %rax, %rdx\n"
  "\n"
```

获取了共享内存以后，目标程序已经获取了必要的运行基础，已经有了记录分支的必要条件。接下来就是向`fuzzer`发送信息看状态管道以及控制管道的通信是否正常，调用`write`向`FORKSRV_FD + 1`（状态管道的写句柄）写入了`4`字节的`hello`消息。这里可以和上面父进程等待子进程`4`字节的消息呼应起来，证明`forkserver`初始化成功。

```c
  // afl-as.h: 536
	"__afl_forkserver:\n"
  "\n"
  "  /* Enter the fork server mode to avoid the overhead of execve() calls. We\n"
  "     push rdx (area ptr) twice to keep stack alignment neat. */\n"
  "\n"
  "  pushq %rdx\n"
  "  pushq %rdx\n"
  "\n"
  "  /* Phone home and tell the parent that we're OK. (Note that signals with\n"
  "     no SA_RESTART will mess it up). If this fails, assume that the fd is\n"
  "     closed because we were execve()d from an instrumented binary, or because\n"
  "     the parent doesn't want to use the fork server. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi       /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  cmpq $4, %rax\n"
  "  jne  __afl_fork_resume\n"
  "\n"
```

初始化成功后，来看`forkserver`的具体工作机制是如何实现的，前面说过是`forkserver`在循环中每次调用`fork`来运行目标程序的功能。

在循环中先调用`read`函数从`FORKSRV_FD`（控制管道读句柄）中接收`4`字节信息，每次从`FORKSRV_FD`接收到`4`字节信息说明`fuzzer`要进行新一轮的运行。

```c
  // afl-as.h: 557
  "__afl_fork_wait_loop:\n"
  "\n"
  "  /* Wait for parent by reading from the pipe. Abort if read fails. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi             /* file desc */\n"
  CALL_L64("read")
  "  cmpq $4, %rax\n"
  "  jne  __afl_die\n"
  "\n"
```

当新的一轮运行开始以后`forkserver`调用`fork`函数启动运行。

```c
  "  /* Once woken up, create a clone of our process. This is an excellent use\n"
  "     case for syscall(__NR_clone, 0, CLONE_PARENT), but glibc boneheadedly\n"
  "     caches getpid() results and offers no way to update the value, breaking\n"
  "     abort(), raise(), and a bunch of other things :-( */\n"
  "\n"
  CALL_L64("fork")
  "  cmpq $0, %rax\n"
  "  jl   __afl_die\n"
  "  je   __afl_fork_resume\n"
  "\n"
```

子进程对应去到`__afl_fork_resume`标签，调用`close`关闭相应的控制及状态管道（因为用不到），然后恢复栈以及寄存器环境，最后跳到`__afl_store`去记录分支信息，该标签在前面已经说过，不需要再说了。

```c
  "__afl_fork_resume:\n"
  "\n"
  "  /* In child process: close fds, resume execution. */\n"
  "\n"
  "  movq $" STRINGIFY(FORKSRV_FD) ", %rdi\n"
  CALL_L64("close")
  "\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi\n"
  CALL_L64("close")
  "\n"
  "  popq %rdx\n"
  "  popq %rdx\n"
  "\n"
  "  movq %r12, %rsp\n"
  "  popq %r12\n"
  "\n"
  "  movq  0(%rsp), %rax\n"
  "  movq  8(%rsp), %rcx\n"
  "  movq 16(%rsp), %rdi\n"
  "  movq 32(%rsp), %rsi\n"
  "  movq 40(%rsp), %r8\n"
  "  movq 48(%rsp), %r9\n"
  "  movq 56(%rsp), %r10\n"
  "  movq 64(%rsp), %r11\n"
  "\n"
  "  movq  96(%rsp), %xmm0\n"
  "  movq 112(%rsp), %xmm1\n"
  "  movq 128(%rsp), %xmm2\n"
  "  movq 144(%rsp), %xmm3\n"
  "  movq 160(%rsp), %xmm4\n"
  "  movq 176(%rsp), %xmm5\n"
  "  movq 192(%rsp), %xmm6\n"
  "  movq 208(%rsp), %xmm7\n"
  "  movq 224(%rsp), %xmm8\n"
  "  movq 240(%rsp), %xmm9\n"
  "  movq 256(%rsp), %xmm10\n"
  "  movq 272(%rsp), %xmm11\n"
  "  movq 288(%rsp), %xmm12\n"
  "  movq 304(%rsp), %xmm13\n"
  "  movq 320(%rsp), %xmm14\n"
  "  movq 336(%rsp), %xmm15\n"
  "\n"
  "  leaq 352(%rsp), %rsp\n"
  "\n"
  "  jmp  __afl_store\n"
  "\n"
```

父进程则是将子进程运行的`pid`通过状态管道的写句柄传回给`fuzzer`；然后调用`waitpid`等待子进程运行结束（子进程运行结束，表明该轮的模糊测试完成），将子进程返回的状态码`status`返回给`fuzzer`，以判断程序的运行结果（崩溃、超时等）。

最后跳回到`__afl_fork_wait_loop`标签等待下一次运行。

```c
  // afl-as.h: 578
	"  /* In parent process: write PID to pipe, then wait for child. */\n"
  "\n"
  "  movl %eax, __afl_fork_pid(%rip)\n"
  "\n"
  "  movq $4, %rdx                   /* length    */\n"
  "  leaq __afl_fork_pid(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi             /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  movq $0, %rdx                   /* no flags  */\n"
  "  leaq __afl_temp(%rip), %rsi     /* status    */\n"
  "  movq __afl_fork_pid(%rip), %rdi /* PID       */\n"
  CALL_L64("waitpid")
  "  cmpq $0, %rax\n"
  "  jle  __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  "  movq $4, %rdx               /* length    */\n"
  "  leaq __afl_temp(%rip), %rsi /* data      */\n"
  "  movq $" STRINGIFY((FORKSRV_FD + 1)) ", %rdi         /* file desc */\n"
  CALL_L64("write")
  "\n"
  "  jmp  __afl_fork_wait_loop\n"
  "\n"
```

## 总结

`afl`的反馈过程总的来说使用了两个技术：一个是共享内存技术用来记录分支的运行信息，使得可以有效的获取程序的运行状态；一个是`forkserver`技术来避免进程初始化所占用的不必要的性能消耗，使得可以更高效的对目标程序进行模糊测试。

通过状态以及控制管道来实现`fuzzer`和`forkserver`之间的通信也是非常的巧妙。

貌似现在挺多的`fuzzer`都是用的这一套机制来进行模糊测试，前段时间看的`fuzzilli`也是用这一套共享内存以及管道来实现的模糊测试。

文章首发于[跳跳糖社区](https://tttang.com/archive/1707/)

## 参考

1. [Technical "whitepaper" for afl-fuzz](https://lcamtuf.coredump.cx/afl/technical_details.txt)



