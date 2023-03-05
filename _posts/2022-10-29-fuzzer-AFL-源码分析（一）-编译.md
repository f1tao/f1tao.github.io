---
layout: post
title: fuzzer AFL 源码分析（一）- 编译
date: 2022-10-29
Author: f1tao
tags: [fuzz, afl]
comments: true
toc: true
---

学习经典的`fuzz`框架`AFL`，通过源码的阅读学习`fuzz`，为以后针对特定目标进行模糊测试打下基础。

`AFL`的基础使用可以去看《通过afl-training学习afl》，具体的使用不再进行说明。

此次源码分析的目的是搞清楚两条命令的执行过程：

```bash
afl-gcc harness.c -o fuzzer
afl-fuzz -i in -o out ./fuzzer
```

第一条命令是对模糊测试源码进行插桩编译，生成可以用来模糊测试的目标二进制程序；第二条命令是启动模糊测试命令，对特定的二进制程序进行模糊测试。

本文源码分析的第一部分，主要包含第一条命令（`afl-gcc harness.c -o fuzzer`）的主要实现过程，即从源码编译出可以进行模糊测试的二进制的过程，涉及到的源码主要是`afl-gcc.c`以及`afl-as.c`。

## 基础知识-gcc编译过程

`gcc`对编译程序的过程如下图所示，将一个`demo`程序`hello.c`编译成可执行的二进制文件需要经过`hello.i`、`hello.s`、`hello.o`、`hello`四个步骤。

![gcc-compile-flow](https://raw.githubusercontent.com/f1tao/f1tao.github.io/master/images/2022-10-29-fuzzer-AFL-源码分析（一）-编译/gcc-compile-flow.png)

命令`gcc hello.c -o hello`生成二进制文件`hello`的过程可以分解为：

1. 预处理：展开头文件和宏定义等，命令`gcc -E hello.c -o hello.i`；
2. 编译：将预处理得到的源代码转换成汇编文件（得到汇编文件），命令`gcc -S hello.i -o hello.s`；
3. 汇编：将汇编代码转成不可执行的机器码文件（得到机器码文件），命令`gcc -c hello.s -o hello.o`；
4. 链接：将不可执行的机器码文件转成可执行的文件，把各种符号引用和符号定义转换成为可执行文件中的合适信息，通常是虚拟地址（得到可执行文件），命令`gcc hello.o -o hello`。

可以加入参数`--verbose`来看`gcc`的工作流程，如下所示：

```bash
$ gcc --verbose hello.c -o hello
...
## 编译阶段，生成/tmp/ccBXIO2Z.s
 /usr/lib/gcc/x86_64-linux-gnu/9/cc1 -quiet -v -imultiarch x86_64-linux-gnu hello.c -quiet -dumpbase hello.c -mtune=generic -march=x86-64 -auxbase hello -version -fasynchronous-unwind-tables -fstack-protector-strong -Wformat -Wformat-security -fstack-clash-protection -fcf-protection -o /tmp/ccBXIO2Z.s
...
## 汇编阶段，生成/tmp/ccsJO3ZZ.o
 as -v --64 -o /tmp/ccsJO3ZZ.o /tmp/ccBXIO2Z.s
...
## 链接阶段，生成hello
 /usr/lib/gcc/x86_64-linux-gnu/9/collect2 -plugin /usr/lib/gcc/x86_64-linux-gnu/9/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-linux-gnu/9/lto-wrapper -plugin-opt=-fresolution=/tmp/ccA18jp1.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr -m elf_x86_64 --hash-style=gnu --as-needed -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -z now -z relro -o hello /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/Scrt1.o /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crti.o /usr/lib/gcc/x86_64-linux-gnu/9/crtbeginS.o -L/usr/lib/gcc/x86_64-linux-gnu/9 -L/usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu -L/usr/lib/gcc/x86_64-linux-gnu/9/../../../../lib -L/lib/x86_64-linux-gnu -L/lib/../lib -L/usr/lib/x86_64-linux-gnu -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-linux-gnu/9/../../.. /tmp/ccsJO3ZZ.o -lgcc --push-state --as-needed -lgcc_s --pop-state -lc -lgcc --push-state --as-needed -lgcc_s --pop-state /usr/lib/gcc/x86_64-linux-gnu/9/crtendS.o /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crtn.o
```

## 整体流程

`afl-gcc`实质上是对`gcc`的封装（`wrapper`），它在编译的命令行参数中加入了一定的参数并调用`gcc`进行编译生成汇编代码；然后调用`afl-as`来对汇编代码进行插桩，`afl-as`实质上也是对`as`的封装（`wrapper`），主要对前面编译生成的汇编代码进行插桩，而后调用`as`进行汇编生成相应的目标文件。

仍然加入`--verbose`来看`afl-gcc`的编译过程，如下所示。

可以看到在编译阶段，加入了`-funroll-loops`、`-g`以及`-O3`等参数；汇编阶段调用的`as`也是`afl/as `，不是标准的`as`。

```bash
$ afl-gcc --verbose hello.c -o hello
...
## 编译阶段，生成/tmp/ccMlZxm3.s
 /usr/lib/gcc/x86_64-linux-gnu/9/cc1 -quiet -v -imultiarch x86_64-linux-gnu -D __AFL_COMPILER=1 -D FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1 hello.c -quiet -dumpbase hello.c -mtune=generic -march=x86-64 -auxbase hello -g -O3 -version -funroll-loops -fasynchronous-unwind-tables -fstack-protector-strong -Wformat -Wformat-security -fstack-clash-protection -fcf-protection -o /tmp/ccMlZxm3.s
...
## 汇编阶段，生成/tmp/cc9Ro1Q1.o
 /usr/local/lib/afl/as -v --64 -o /tmp/cc9Ro1Q1.o /tmp/ccMlZxm3.s
...
## 链接阶段，生成hello
 /usr/lib/gcc/x86_64-linux-gnu/9/collect2 -plugin /usr/lib/gcc/x86_64-linux-gnu/9/liblto_plugin.so -plugin-opt=/usr/lib/gcc/x86_64-linux-gnu/9/lto-wrapper -plugin-opt=-fresolution=/tmp/ccGQk7B0.res -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --eh-frame-hdr -m elf_x86_64 --hash-style=gnu --as-needed -dynamic-linker /lib64/ld-linux-x86-64.so.2 -pie -z now -z relro -o hello /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/Scrt1.o /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crti.o /usr/lib/gcc/x86_64-linux-gnu/9/crtbeginS.o -L/usr/local/lib/afl -L/usr/lib/gcc/x86_64-linux-gnu/9 -L/usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu -L/usr/lib/gcc/x86_64-linux-gnu/9/../../../../lib -L/lib/x86_64-linux-gnu -L/lib/../lib -L/usr/lib/x86_64-linux-gnu -L/usr/lib/../lib -L/usr/lib/gcc/x86_64-linux-gnu/9/../../.. /tmp/cc9Ro1Q1.o -lgcc --push-state --as-needed -lgcc_s --pop-state -lc -lgcc --push-state --as-needed -lgcc_s --pop-state /usr/lib/gcc/x86_64-linux-gnu/9/crtendS.o /usr/lib/gcc/x86_64-linux-gnu/9/../../../x86_64-linux-gnu/crtn.o
```

## 源码分析

下面来进行源码分析，主要对`afl-gcc`以及`afl-as`进行分析，来看是这两部分代码是如何对`gcc`以及`as`进行封装的。

### afl-gcc

`afl-gcc`主要是加入了一定的编译参数并调用`gcc`进行编译生成汇编代码，入口函数`main`如下所示：

```c
// afl-gcc.c: 310
int main(int argc, char** argv) {

  ...

  find_as(argv[0]);

  edit_params(argc, argv);

  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}
```

同时开启`gdb`动态调试进行查看：

```assembly
$1 = 4
pwndbg> print argv[0]
$2 = 0x7fffffffe43d "/usr/local/bin/afl-gcc"
pwndbg> print argv[1]
$3 = 0x7fffffffe454 "hello.c"
pwndbg> print argv[2]
$4 = 0x7fffffffe45c "-o"
pwndbg> print argv[3]
$5 = 0x7fffffffe45f "hello"
pwndbg> print argv[4]
$6 = 0x0
```

`find_as`函数的功能是通过`argv[0]`（`gcc`）的路径来确定`as`的路径，跟进去该函数：

```c
// afl-gcc.c: 61
/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */

static void find_as(u8* argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/as", afl_path);

    if (!access(tmp, X_OK)) {
      as_path = afl_path;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

    tmp = alloc_printf("%s/afl-as", dir);

    if (!access(tmp, X_OK)) {
      as_path = dir;
      ck_free(tmp);
      return;
    }

    ck_free(tmp);
    ck_free(dir);

  }

  if (!access(AFL_PATH "/as", X_OK)) {
    as_path = AFL_PATH;
    return;
  }

  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");
 
}
```

它先尝试从环境变量中获取`AFL_PATH`，如果设置了`AFL_PATH`，则无需从`argv0`中提取相应的`afl`路径，可直接将该环境变量路径拼接上`/as`查看文件是否存在，存在的话该路径即可作为`as_path`。

如果找不到`AFL_PATH`环境变量，则尝试从`argv0`中提取`afl`相关文件路径，具体来说是从`argv0`路径找到最右侧的`/`（`strrchr(argv0, '/')`），然后将相应的路径拼接`afl-as`或`as`确定相应的`afl-as`文件存在后，将该路径作为`as_path`。

确定了`as`文件的路径，`find_as`函数返回。

`find_as`函数执行完成后，`main`函数调用`edit_params`来对参数进行处理，跟进去该函数。

首先确定是调用`afl-clang++`、`afl-clang`、`afl-g++`还是`afl-gcc`对目标代码进行编译，并将`cc_params[0]`设置成相应的`clang++`、`clang`、`g++`以及`gcc`。如果是`clang++`或`clang`的话，还会将标志位`clang_mode`设为`1`。

```c
// afl-gcc.c: 116
/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8 fortify_set = 0, asan_set = 0;
  u8 *name;

#if defined(__FreeBSD__) && defined(__x86_64__)
  u8 m32_set = 0;
#endif

  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name) name = argv[0]; else name++;

  if (!strncmp(name, "afl-clang", 9)) {

    clang_mode = 1;

    setenv(CLANG_ENV_VAR, "1", 1);

    if (!strcmp(name, "afl-clang++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
    }

  } else {

    /* With GCJ and Eclipse installed, you can actually compile Java! The
       instrumentation will work (amazingly). Alas, unhandled exceptions do
       not call abort(), so afl-fuzz would need to be modified to equate
       non-zero exit codes with crash conditions when working with Java
       binaries. Meh. */

#ifdef __APPLE__

    if (!strcmp(name, "afl-g++")) cc_params[0] = getenv("AFL_CXX");
    else if (!strcmp(name, "afl-gcj")) cc_params[0] = getenv("AFL_GCJ");
    else cc_params[0] = getenv("AFL_CC");

    if (!cc_params[0]) {

      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. Please use the\n"
           "    'afl-clang' utility instead of 'afl-gcc'. If you really have GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that compiler.\n");

      FATAL("AFL_CC or AFL_CXX required on MacOS X");

    }

#else

    if (!strcmp(name, "afl-g++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"g++";
    } else if (!strcmp(name, "afl-gcj")) {
      u8* alt_cc = getenv("AFL_GCJ");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcj";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"gcc";
    }

#endif /* __APPLE__ */

  }
```

在确定了`cc_params[0]`后，去处理剩下传入的命令行参数，`while`循环进行遍历，当参数是`-m32`、`-fsanitize=address`（`-fsanitize=memory`）以及`FORTIFY_SOURCE`的时候，设置相应的标志位`m32_set`、`asan_set`以及`fortify_set`；同时将参数传入到`cc_params`进行存储。

```c
  // afl-gcc.c: 188
        while (--argc) {
    u8* cur = *(++argv);

    if (!strncmp(cur, "-B", 2)) {

      if (!be_quiet) WARNF("-B is already set, overriding");

      if (!cur[2] && argc > 1) { argc--; argv++; }
      continue;

    }

    if (!strcmp(cur, "-integrated-as")) continue;

    if (!strcmp(cur, "-pipe")) continue;

#if defined(__FreeBSD__) && defined(__x86_64__)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    cc_params[cc_par_cnt++] = cur;

  }
```

上面我们编译传入的参数已经处理完成，`argv[0]`的`afl-gcc`变成了`gcc`，其余的参数也都传入到了`cc_params`中。

接下来便看`afl-gcc`在调用`gcc`前还加入了哪些参数了，如下所示：

```c
        // afl-gcc.c: 116
        cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt++] = as_path;

  if (clang_mode)
    cc_params[cc_par_cnt++] = "-no-integrated-as";

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set)
      cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (asan_set) {

    /* Pass this on to afl-as to adjust map density. */

    setenv("AFL_USE_ASAN", "1", 1);

  } else if (getenv("AFL_USE_ASAN")) {

    if (getenv("AFL_USE_MSAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("ASAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=address";

  } else if (getenv("AFL_USE_MSAN")) {

    if (getenv("AFL_USE_ASAN"))
      FATAL("ASAN and MSAN are mutually exclusive");

    if (getenv("AFL_HARDEN"))
      FATAL("MSAN and AFL_HARDEN are mutually exclusive");

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory";


  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

#if defined(__FreeBSD__) && defined(__x86_64__)

    /* On 64-bit FreeBSD systems, clang -g -m32 is broken, but -m32 itself
       works OK. This has nothing to do with us, but let's avoid triggering
       that bug. */

    if (!clang_mode || !m32_set)
      cc_params[cc_par_cnt++] = "-g";

#else

      cc_params[cc_par_cnt++] = "-g";

#endif

    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* Two indicators that you're building for fuzzing; one of them is
       AFL-specific, the other is shared with libfuzzer. */

    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  }

  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

  cc_params[cc_par_cnt] = NULL;

}
```

可以看到了加入了`-B`选项，`-B`选项用于设置编译器的搜索路径；设置该选项的作用是从该路径下搜索相应的`as`，从而实现在汇编的时候调用的汇编器是`afl-as`；如果环境变量`AFL_HARDEN`存在的话，则加入编译参数`-fstack-protector-all`来开启更多的保护以更好的检测`crash`；根据相应的标志位`asan_set`、`fortify_set`以及`clang_mode`设置相应的参数选项；根据相应的环境变量`AFL_USE_MSAN`、`AFL_USE_ASAN`以及`AFL_DONT_OPTIMIZE`设置相应的参数选项。

参数`-funroll-loops`是进行循环展开，减少循环次数提高性能；`#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`是与`libfuzzer`共用的一个标志位；`__AFL_COMPILER`是`AFL`的标志位。

参数处理完成后，`edit_params`函数返回。

`main`函数最终调用`execvp`来调用`gcc`对目标进行编译，最终的参数如下：

```bash
pwndbg> print cc_params[0]
$21 = (u8 *) 0x5555555576ac "gcc"
pwndbg> print cc_params[1]
$22 = (u8 *) 0x7fffffffe47b "/home/f1tao/Desktop/hello.c"
pwndbg> print cc_params[2]
$23 = (u8 *) 0x555555557794 "-B"
pwndbg> print cc_params[3]
$24 = (u8 *) 0x55555555a2a8 "/home/f1tao/Desktop/AFL"
pwndbg> print cc_params[4]
$25 = (u8 *) 0x55555555781c "-g"
pwndbg> print cc_params[5]
$26 = (u8 *) 0x55555555781f "-O3"
pwndbg> print cc_params[6]
$27 = (u8 *) 0x555555557823 "-funroll-loops"
pwndbg> print cc_params[7]
$28 = (u8 *) 0x555555557832 "-D__AFL_COMPILER=1"
pwndbg> print cc_params[8]
$29 = (u8 *) 0x555555557610 "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"
pwndbg> print cc_params[9]
$30 = (u8 *) 0x0
```

#### 小结

总结来说，`afl-gcc`是对`gcc`的封装，主要是在相应的编译选项中加入`-B`参数（当然也加入一些优化的参数），指定特定的编译器搜索路径，实现在编译完成后，调用`afl-as`来进行汇编。

### afl-as

根据前面打印出来的信息，我们知道`afl-gcc`只是简单的处理了命令行参数后，就调用原生的`gcc`进行编译了。汇编的时候是调用`afl-as`对汇编代码进行汇编，命令是`/usr/local/lib/afl/as -v --64 -o /tmp/cc9Ro1Q1.o /tmp/ccMlZxm3.s`，来看`afl-as`实现的具体过程。

`main`函数关键代码如下所示：

```c
// afl-as.c: 477
int main(int argc, char** argv) {

  ...

  edit_params(argc, argv);

  ...

  if (!just_version) add_instrumentation();

  if (!(pid = fork())) {

    execvp(as_params[0], (char**)as_params);
    FATAL("Oops, failed to execute '%s' - check your PATH", as_params[0]);

  }

  ...

  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  ...

}
```

关键函数也是三个，`edit_params`函数根据传入的参数进行处理；`add_instrumentation`对汇编代码进行插桩；`execvp`调用`as`对汇编代码进行汇编。

先来看`edit_params`函数，如下所示。

第一部分是确定`tmp`目录的位置，确定系统的汇编器（`as`），如果是`clang_mode`则设定标志位`use_clang_as`，并为全局变量`as_params`分配空间。

```c
// afl-as.c: 92
/* Examine and modify parameters to pass to 'as'. Note that the file name
   is always the last parameter passed by GCC, so we exploit this property
   to keep the code simple. */

static void edit_params(int argc, char** argv) {

  u8 *tmp_dir = getenv("TMPDIR"), *afl_as = getenv("AFL_AS");
  u32 i;

#ifdef __APPLE__

  u8 use_clang_as = 0;

  ...

  if (clang_mode && !afl_as) {

    use_clang_as = 1;

    afl_as = getenv("AFL_CC");
    if (!afl_as) afl_as = getenv("AFL_CXX");
    if (!afl_as) afl_as = "clang";

  }

#endif /* __APPLE__ */

        ...

  if (!tmp_dir) tmp_dir = getenv("TEMP");
  if (!tmp_dir) tmp_dir = getenv("TMP");
  if (!tmp_dir) tmp_dir = "/tmp";

  as_params = ck_alloc((argc + 32) * sizeof(u8*));

  as_params[0] = afl_as ? afl_as : (u8*)"as";

  as_params[argc] = 0;
```

第二部分是处理剩余的参数，`for`循环对单个`argv`进行处理，通过`--64`或`--32`设定标志位`use_64bit`；跳过参数`-q`或`-Q`；将其余的参数赋值到`as_params`中。

```c
  // afl-as.c: 143
        for (i = 1; i < argc - 1; i++) {

    if (!strcmp(argv[i], "--64")) use_64bit = 1;
    else if (!strcmp(argv[i], "--32")) use_64bit = 0;

#ifdef __APPLE__

    ...

    if (clang_mode && (!strcmp(argv[i], "-q") || !strcmp(argv[i], "-Q")))
      continue;

#endif /* __APPLE__ */

    as_params[as_par_cnt++] = argv[i];

  }
```

最后一部分是对输入文件进行处理，因为后续会对原有的汇编文件`.s`进行插桩，插桩后的`.s`文件会保存至`tmp`目录下，因此需要将最终汇编的文件路径修改。

具体来说，因为在`gcc`中`.s`文件是最后一个参数，因此先将最后一个参数赋值给`input_file`。如果最后一个参数是`--version`，则说明不是进行汇编，而是显示`version`，将`just_version`标志位设置为`1`；否则将`modified_file`设为`"%s/.afl-%u-%u.s", tmp_dir, getpid(), (u32)time(NULL)`，即在`tmp`目录下的文件，并将该值作为最后一个参数保存在`as_params`中，用于后续汇编。

```c
  // afl-as.c: 187
        input_file = argv[argc - 1];

  if (input_file[0] == '-') {

    if (!strcmp(input_file + 1, "-version")) {
      just_version = 1;
      modified_file = input_file;
      goto wrap_things_up;
    }

    if (input_file[1]) FATAL("Incorrect use (not called through afl-gcc?)");
      else input_file = NULL;

  } else {

    /* Check if this looks like a standard invocation as a part of an attempt
       to compile a program, rather than using gcc on an ad-hoc .s file in
       a format we may not understand. This works around an issue compiling
       NSS. */

    if (strncmp(input_file, tmp_dir, strlen(tmp_dir)) &&
        strncmp(input_file, "/var/tmp/", 9) &&
        strncmp(input_file, "/tmp/", 5)) pass_thru = 1;

  }

  modified_file = alloc_printf("%s/.afl-%u-%u.s", tmp_dir, getpid(),
                               (u32)time(NULL));

wrap_things_up:

  as_params[as_par_cnt++] = modified_file;
  as_params[as_par_cnt]   = NULL;
```

`edit_params`处理完成后，回到`main`函数中，如果`just_version`没有被置位的话，会调用`add_instrumentation`对汇编代码进行插桩。这个函数是插桩的具体实现，很关键。

跟进去该函数，首先是打开原有的汇编文件`input_file`以及创建插桩后的文件`modified_file`。

```c
// afl-as.c: 224
/* Process input file, generate modified_file. Insert instrumentation in all
   the appropriate places. */

static void add_instrumentation(void) {

        ...

  if (input_file) {

    inf = fopen(input_file, "r");
    if (!inf) PFATAL("Unable to read '%s'", input_file);

  } else inf = stdin;

  outfd = open(modified_file, O_WRONLY | O_EXCL | O_CREAT, 0600);

  if (outfd < 0) PFATAL("Unable to write to '%s'", modified_file);

  outf = fdopen(outfd, "w");

  if (!outf) PFATAL("fdopen() failed"); 
```

接着逐行读取文件，查看是否需要插桩。

对于读入的每一行，先判断插桩的条件是否满足（`!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok && instrument_next`），如果满足则直接插入插桩代码（`trampoline_fmt_64` 或`trampoline_fmt_32`，根据是`32`位还是`64`位），插桩完成后，表明该基本块已经完成插桩，后面的代码无需插桩，将`instrument_next`置位`0`。

无论是否插桩，结束后都将当行代码写入到`modified_file`中。

至于何时需要插桩（插桩条件的满足），则在后面逐步进行判断。

```c
  // afl-as.c: 260
        while (fgets(line, MAX_LINE, inf)) {

    /* In some cases, we want to defer writing the instrumentation trampoline
       until after all the labels, macros, comments, etc. If we're in this
       mode, and if the line starts with a tab followed by a character, dump
       the trampoline now. */

    if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
        instrument_next && line[0] == '\t' && isalpha(line[1])) {

      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));

      instrument_next = 0;
      ins_lines++;

    }

    /* Output the actual line, call it a day in pass-thru mode. */

    fputs(line, outf);
```

`pass_thru`标志位是在`edit_params`中设定的；`skip_next_label`标志位是为了处理`OpenBSD`系统上的跳转表而设置的标志位；`\t.text`、`\t.section\t.text`等开头的行则说明接下来是`text`段，可能需要进行插桩因此要设置`instr_ok`标志位，再次遇到`\t.section`或`\t.bss`等说明到了其它的段，需要将`instr_ok`标志位置`0`。`skip_csect`则是用来标志`off-flavor assembly `；`skip_intel`用来处理`intel`汇编语法，`afl`只对`AT&T`汇编表示进行插桩；`skip_app`用来标志`ad-hoc __asm__`（不太明白这是啥）。

小结来说，感觉这些标志位最需要关注的是`instr_ok`标志位，该标志位用来表示是否处于`text`段，如果处于则可能需要进行插桩，否则无需进行插桩。其它标志位正常情况下在`ubuntu`系统下`gcc`生成的汇编代码，应该不会有对应的代码出现。

```c
    if (pass_thru) continue;

    /* All right, this is where the actual fun begins. For one, we only want to
       instrument the .text section. So, let's keep track of that in processed
       files - and let's set instr_ok accordingly. */

    if (line[0] == '\t' && line[1] == '.') {

      /* OpenBSD puts jump tables directly inline with the code, which is
         a bit annoying. They use a specific format of p2align directives
         around them, so we use that as a signal. */

      if (!clang_mode && instr_ok && !strncmp(line + 2, "p2align ", 8) &&
          isdigit(line[10]) && line[11] == '\n') skip_next_label = 1;

      if (!strncmp(line + 2, "text\n", 5) ||
          !strncmp(line + 2, "section\t.text", 13) ||
          !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
          !strncmp(line + 2, "section __TEXT,__text", 21)) {
        instr_ok = 1;
        continue; 
      }

      if (!strncmp(line + 2, "section\t", 8) ||
          !strncmp(line + 2, "section ", 8) ||
          !strncmp(line + 2, "bss\n", 4) ||
          !strncmp(line + 2, "data\n", 5)) {
        instr_ok = 0;
        continue;
      }

    }

    /* Detect off-flavor assembly (rare, happens in gdb). When this is
       encountered, we set skip_csect until the opposite directive is
       seen, and we do not instrument. */

    if (strstr(line, ".code")) {

      if (strstr(line, ".code32")) skip_csect = use_64bit;
      if (strstr(line, ".code64")) skip_csect = !use_64bit;

    }

    /* Detect syntax changes, as could happen with hand-written assembly.
       Skip Intel blocks, resume instrumentation when back to AT&T. */

    if (strstr(line, ".intel_syntax")) skip_intel = 1;
    if (strstr(line, ".att_syntax")) skip_intel = 0;

    /* Detect and skip ad-hoc __asm__ blocks, likewise skipping them. */

    if (line[0] == '#' || line[1] == '#') {

      if (strstr(line, "#APP")) skip_app = 1;
      if (strstr(line, "#NO_APP")) skip_app = 0;

    }
```

对于在`text`段，需要插桩的代码，注释中有比较良好的说明，如下所示。

主要是需要在各个基本块的入口进行插桩，具体来说：

* 对于`main`函数的入口（`^main:`）需要插桩，因为需要初始化；对于条件条件的标签后面（`gcc`是`^.L0:`，`clang`是`^.LBB0_0:`）需要插桩，因为它是条件跳转的目标地址；对于跳转指令（`^\tjnz foo`）后面也需要插桩，因为该指令的后面形成了分支。
* 而对于注释（`^# BB#0:`以及`^ # BB#0:`）不需要插桩；绝对跳转的目标地址（`^.Ltmp0:`、`^.LC0 `以及`^.LBB0_0:`）不需要插桩，因为没有形成新的分支或路径；绝对跳转指令（`^\tjmp foo`）也无需插桩。
* 对于条件跳转指令，需要在条件跳转指令后面以及在跳转指令的目标标签后面都需要插桩，因为在条件跳转指令后形成了两条分支，需要对其插桩监控以查看是否执行了更多的路径。

```c
                 /* If we're in the right mood for instrumenting, check for function
       names or conditional labels. This is a bit messy, but in essence,
       we want to catch:

         ^main:      - function entry point (always instrumented)
         ^.L0:       - GCC branch label
         ^.LBB0_0:   - clang branch label (but only in clang mode)
         ^\tjnz foo  - conditional branches

       ...but not:

         ^# BB#0:    - clang comments
         ^ # BB#0:   - ditto
         ^.Ltmp0:    - clang non-branch labels
         ^.LC0       - GCC non-branch labels
         ^.LBB0_0:   - ditto (when in GCC mode)
         ^\tjmp foo  - non-conditional jumps

       Additionally, clang and GCC on MacOS X follow a different convention
       with no leading dots on labels, hence the weird maze of #ifdefs
       later on.

     */
     
     /* Conditional branch instruction (jnz, etc). We append the instrumentation
       right after the branch (to instrument the not-taken path) and at the
       branch destination label (handled later on). */
```

下面来看具体实现，当指令是条件跳转指令不是绝对跳转指令的时候（`line[1] == 'j' && line[2] != 'm'`），在该指令的后面直接插入插桩代码。

```c
                // afl-as.c: 372
                if (line[0] == '\t') {

      if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {

        fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                R(MAP_SIZE));

        ins_lines++;

      }

      continue;

    }
```

当是条件跳转的标签时，需要在该标签后的指令插入插桩代码（`instrument_next`标志位置位），判断的方式则是去看标签的内容。

```c
                // afl-as.c: 387
                /* Label of some sort. This may be a branch destination, but we need to
       tread carefully and account for several different formatting
       conventions. */

#ifdef __APPLE__

    /* Apple: L<whatever><digit>: */

    if ((colon_pos = strstr(line, ":"))) {

      if (line[0] == 'L' && isdigit(*(colon_pos - 1))) {

#else

    /* Everybody else: .L<whatever>: */

    if (strstr(line, ":")) {

      if (line[0] == '.') {

#endif /* __APPLE__ */

        /* .L0: or LBB0_0: style jump destination */

#ifdef __APPLE__

        /* Apple: L<num> / LBB<num> */

        if ((isdigit(line[1]) || (clang_mode && !strncmp(line, "LBB", 3)))
            && R(100) < inst_ratio) {

#else

        /* Apple: .L<num> / .LBB<num> */

        if ((isdigit(line[2]) || (clang_mode && !strncmp(line + 1, "LBB", 3)))
            && R(100) < inst_ratio) {

#endif /* __APPLE__ */

          /* An optimization is possible here by adding the code only if the
             label is mentioned in the code in contexts other than call / jmp.
             That said, this complicates the code by requiring two-pass
             processing (messy with stdin), and results in a speed gain
             typically under 10%, because compilers are generally pretty good
             about not generating spurious intra-function jumps.

             We use deferred output chiefly to avoid disrupting
             .Lfunc_begin0-style exception handling calculations (a problem on
             MacOS X). */

          if (!skip_next_label) instrument_next = 1; else skip_next_label = 0;

        }

      } else {

        /* Function label (always instrumented, deferred mode). */

        instrument_next = 1;
    
      }

    }

  }
```

总的来说，确定在哪条指令处需要插桩最为关键的标志位我觉得是`instr_ok`以及`instrument_next`，前者表示当前遍历的汇编代码处于`text`代码段，可能需要插桩；后者确定当前汇编代码的下一条指令需要插桩。

在整个汇编代码遍历完成后，如果无需插桩的话，则不需要加入额外的`main_payload`汇编代码；如果经历过插桩的话，则加入`main_payload`，`main_payload`的作用是插桩代码的主体功能的实现。

最终关闭相应的文件句柄，并输出信息，完成`.s`文件的插桩。

```c
  // afl-as.c: 454
  if (ins_lines)
    fputs(use_64bit ? main_payload_64 : main_payload_32, outf);

  if (input_file) fclose(inf);
  fclose(outf);

  if (!be_quiet) {

    if (!ins_lines) WARNF("No instrumentation targets found%s.",
                          pass_thru ? " (pass-thru mode)" : "");
    else OKF("Instrumented %u locations (%s-bit, %s mode, ratio %u%%).",
             ins_lines, use_64bit ? "64" : "32",
             getenv("AFL_HARDEN") ? "hardened" : 
             (sanitizer ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio);
 
  }
```

至于在基本块前面加入的插桩跳板代码`trampoline_fmt`以及插桩的功能代码`main_payload`是用来记录程序运行的执行路径，为`fuzz`提供反馈信息，不在此次的讨论范围内，在下一部分详细阐述。

`add_instrumentation`插桩完成之后，`modified_file`也已经生成，此时返回到`main`函数中，调用`execvp`原来的`gcc as`来对汇编代码进行汇编，生成对应的二进制文件。

#### 小结

`afl-as`的主体功能是逐行对前面编译生成的汇编代码进行遍历，在恰当的位置插入相应的插桩代码（`trampoline_fmt`）并在最末尾插入相应的功能代码（`main_payload`），最终调用原生的`as`来生成二进制文件，实现对二进制文件的插桩。

## 总结

第一部分阐述了`afl-gcc harness.c -o fuzzer`编译二进制程序涉及的过程，对`afl-gcc`以及`afl-as`代码进行了分析。`afl-gcc`在整个编译的过程中实现了对`gcc`的封装，通过在汇编器`as`的封装，实现了在汇编的过程中在基本块中加入插桩代码，实现了路径等反馈信息的记录与提交，从而实现了支持反馈式模糊测试二进制的生成。

至于具体的插桩代码的解析（`trampoline_fmt`以及`main_payload`），留至下一部分再进行说明。

文章首发于[跳跳糖](https://tttang.com/archive/1595/)。

## 参考

1. [AFL内部实现细节小记](http://rk700.github.io/2017/12/28/afl-internals/)
3. [AFL afl_fuzz.c 详细分析](https://bbs.pediy.com/thread-254705.htm)
4. [Technical “whitepaper” for afl-fuzz](http://lcamtuf.coredump.cx/afl/technical_details.txt) 
5. [GCC简单编译流程](https://blog.csdn.net/qq_36287943/article/details/103601371)










