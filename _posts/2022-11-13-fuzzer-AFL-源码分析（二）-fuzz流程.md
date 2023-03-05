---
layout: post
title: fuzzer AFL 源码分析（二）-fuzz流程
date: 2022-11-13
Author: f1tao
tags: [fuzz, afl]
comments: true
toc: true
---

第一部分介绍了`afl`插桩编译的过程，思考了很久才定下第二部分写些什么。本来打算第二部分详细解释插桩部分和`forkserver`的代码的，但是感觉如果对`afl-fuzz`的整体流程没有大致掌握的话，直接去描述细节会让人不理解为什么`afl`这部分要这样去设计，因此决定在第二部分将`afl-fuzz`的主要流程（`main`）和部分不是关键代码的函数给说清楚，后续再逐步对关键代码模块进行详细分析，j继而实现对`afl`模糊测试的解析。

简单来说，本章节主要是对`afl-fuzz -i in -o out ./fuzzer`命令所涉及到的代码进行概要性的分析，为后续对关键代码模块进行详细分析做铺垫。

## afl-fuzz 工作流

命令`afl-fuzz -i in -o out ./fuzzer`运行后，其中`-i`指定`in`目录是种子输入文件目录，`-o`指定`out`目录是输出文件目录，`fuzzer`是经过编译插桩的二进制文件，是待模糊测试的目标。

`afl-fuzz`的整个模糊测试流程如下图所示，可以概括为：

1. 基于源码编译生成支持反馈式模糊测试的二进制程序（第一部分介绍过的`afl-gcc`），记录代码覆盖率（`code coverage`）；
2. 提供种子文件，作为初始测试集加入输入队列（`queue`）；
3. 将队列中的文件按一定的策略进行“突变”；
4. 将变异后的文件作为输入去运行目标二进制程序并监控其状态；
5. 如果经过变异文件更新了覆盖范围，则将其保留添加到队列中;
6. 上述过程会一直循环进行，期间触发了`crash`的文件会被记录下来。

![afl-fuzz-flow](https://raw.githubusercontent.com/f1tao/f1tao.github.io/master/images/2022-11-13-fuzzer-AFL-源码分析（二）-fuzz流程/afl-fuzz-flow.png)

## afl-fuzz 源码分析

上面讲述了`afl-fuzz`的主要流程，下面从源码的角度来阐述流程的主要实现过程。

主要是对`afl-fuzz.c`的`main`函数进行分析，通过`main`函数的流程来对`afl-fuzz`的工作流程来进行初步的理解，这个过程中不会跟进子函数，只对每个函数的功能进行大致的介绍，涉及到核心功能模块的子函数在后续的文章中会进行详细说明。

一开始是初始化`afl-fuzz`的运行环境，下面来看环境初始化的整个过程。

第一部分主要是参数解析，关键代码如下所示。可以看到常用的`-i`参数指定种子目录保存在全局的`in_dir`变量中；`-o` 变量指定的输出目录保存在全局变量`out_dir`中；`-x`字典模式，字典文件的路径或目录保存在`extras_dir`变量中；`-m`设定内存，保存在变量`mem_limit`中。

```c
// afl-fuzz.c: 7778
int main(int argc, char** argv) {

  ...

  while ((opt = getopt(argc, argv, "+i:o:f:m:b:t:T:dnCB:S:M:x:QV")) > 0)

    switch (opt) {

      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': { /* master sync ID */
          ...
      case 'S': 
        ...
      case 'f': /* target file */
			...
      case 'x': /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': { /* timeout */
          ...
      }

      case 'm': { /* mem limit */

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;
      
      case 'b': { /* bind CPU core */
          ...
      }

      case 'd': /* skip deterministic */
        ...
      case 'B': /* load bitmap */
        ...
      case 'C': /* crash mode */
        ...
      case 'n': /* dumb mode */
        ...
      case 'T': /* banner */
        ...
      case 'Q': /* QEMU mode */
        ...
      case 'V': /* Show version number */
        ...
      default:

        usage(argv[0]);

    }
```

在参数解析完成后，调用`setup_signal_handlers`来注册一些信号处理的函数，包括在退出的时候杀掉对应的`fuzz`程序、在屏幕大小变化的时候调整屏幕等等；后面调用`check_asan_opts`来检查用户传入的`ASAN_OPTIONS`是否正确（如不能用`abort_on_error=1`），如果不正确则直接退出；然后查看一些环境变量是否存在以及依据它们的值来设置一些全局的控制变量，因此可以通过环境变量的设定来指定`fuzz`的行为（如设定`AFL_NO_ARITH`环境变量，可以使得在变异的时候不进行`ARITH`变异）。

```c
  // afl-fuzz.c: 7991
	setup_signal_handlers();
  check_asan_opts();

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if (dumb_mode) {

    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)  FATAL("-Q and -n are mutually exclusive");

  }

  if (getenv("AFL_NO_FORKSRV"))    no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED"))    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))      no_arith         = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue    = 1;
  if (getenv("AFL_FAST_CAL"))      fast_cal         = 1;

  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");
```

然后是一些运行环境设定以及对系统状态进行检查（`PS`：可以通过这几个函数学习如何获取系统状态），如下所示，具体包括：

* 调用`save_cmdline`函数来将传入的参数`argv`保存到全局变量`orig_cmdline `中；
* 调用`fix_up_banner`函数来设定`use_banner`变量，用于后续`UI`显示中标题的展示；
* 调用`check_if_tty`函数检查是否处于`UI`环境下（可以通过调用`ioctl(1, TIOCGWINSZ, &ws)`函数获取`terminal`的一些参数）；
* 调用`get_core_count`函数获取系统`cpu`的个数如果定义了`HAVE_AFFINITY`标志，调用`bind_to_free_cpu`函数将当前的进程绑定到`cpu`上；
* 调用`check_crash_handling`来检查当进程崩溃时系统如何`dump`文件，这也是为啥没有设置好`/proc/sys/kernel/core_pattern`的时候，`afl`会提醒设置`echo core >/proc/sys/kernel/core_pattern`的函数。这样设置的原因是因为`core_pattern`指定了当发生崩溃的时候如何处理崩溃，系统中默认会将崩溃信息通过管道发送给外部程序，运行效率很低，影响`fuzz`效率，因此需要将它保存为本地的文件以提高效率。
* `check_cpu_governor`是检查`cpu`的调节器，来使得`cpu`可以处于高效的运行状态。

```c
  // afl-fuzz.c: 8028
  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  get_core_count();

	#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
	#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();
```

完成对系统状态的检查以及运行环境的设定以后，可以初步处理输入输出文件以及需要`fuzz`的目标文件了，具体来说：

* 调用`setup_post`函数：如果指定了环境变量`AFL_POST_LIBRARY`，则会从指定的动态链接库`so`中加载函数`afl_postprocess`并将函数指针存储到`post_handler`当中，每次在运行样例前都会尝试调用该函数。这样做的内涵是提供一个接口来让用户`hook`模糊测试，在模糊测试过程中执行自定义的功能代码。
* `setup_shm`：初始化样例路径覆盖状态变量`virgin_bits`、超时样例路径覆盖状态变量`virgin_tmout`、崩溃样例路径覆盖状态变量`virgin_crash`，用于后续存储样例覆盖目标程序运行路径的状态；使用`SYSTEM V`申请共享内存`trace_bits`（详情可以看《进程共享内存技术》），用于后续存储每次样例运行所覆盖的路径。
* `init_count_class16`：初始化`count_class_lookup16`数组，该数组的作用是帮助快速归类统计路径覆盖的数量。
* `setup_dirs_fds`：创建所有的输出目录，打开部分全局的文件句柄。创建输出目录`queue`、`crashes`、`hangs`等，打开文件句柄`dev_null_fd`、`dev_urandom_fd `以及`plot_file`等。
* `read_testcases`：逐个读取种子目录下的输入文件列表，并调用`add_to_queue`函数将相关信息（文件名称、大小等）存入到全局的种子队列`queue`当中，作为后续模糊测试的种子来源。单个种子信息保存在结构体`queue_entry`当中，形成单链表。
* `load_auto`：尝试在输入目录下寻找自动生成的字典文件，调用`maybe_add_auto`将相应的字典加入到全局变量`a_extras`中，用于后续字典模式的变异当中。
* `pivot_inputs`：根据相应的种子文件路径在输出目录下创建链接或拷贝至该目录下，形成`orignal`文件，文件命名的规则是`%s/queue/id:%06u,orig:%s", out_dir, id, use_name`，并更新至对应的种子信息结构体`queue_entry`中。
* `load_extras`：如果指定了`-x`参数（字典模式），加载对应的字典到全局变量`extras`当中，用于后续字典模式的变异当中。
* `find_timeout`：如果指定了`resuming_fuzz`即从输出目录当中恢复模糊测试状态，会从之前的模糊测试状态`fuzzer_stats`文件中计算中`timeout`值，保存在`exec_tmout`中。
* `detect_file_args`：检测输入的命令行中是否包含`@@`参数，如果包含的话需要将`@@`替换成目录文件`"%s/.cur_input", out_dir`，使得模糊测试目标程序的命令完整；同时将目录文件`"%s/.cur_input"`路径保存在`out_file`当中，后续变异的内容保存在该文件路径中，用于运行测试目标文件。
* `setup_stdio_file`：如果目标程序的输入不是来源于文件而是来源于标准输入的话，则将目录文件`"%s/.cur_input"`文件打开保存在`out_fd`文件句柄中，后续将标准输入重定向到该文件中；结合`detect_file_args`函数实现了将变异的内容保存在`"%s/.cur_input"`文件中，运行目标测试文件并进行模糊测试。
* `check_binary`：对二进制进行一系列的检查，包括检查二进制是否是`bash`文件、是否是`ELF`文件、是否包含共享内存标志、是否包含插桩的标志等。

```c
  // afl-fuzz.c: 8043
  setup_post();
  setup_shm();
  init_count_class16();

  setup_dirs_fds();
  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir) load_extras(extras_dir);

  if (!timeout_given) find_timeout();

  detect_file_args(argv + optind + 1);

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;
```

在完成运行环境初始化以及一系列检查以后，就可以对种子文件进行初步的运行测试查看`fuzzer`的运行状态，对种子文件根据有效性进行初步的排序，进行`UI`显示等。

具体来说：

* `perform_dry_run`：将每个种子文件作为输入，运行目标程序一次，查看系统运行的状态是否正确；该函数里面调用的`calibrate_case`函数是具体运行样本的函数，`calibrate_case`函数对样本的运行状态进行校验，这个函数比较重要，后续也会重点进行分析。
* `cull_queue`：将运行过的种子根据运行的效果进行排序，后续模糊测试根据排序的结果来挑选样例进行模糊测试。
* `show_init_stats`：因为所有运行的基础已经具备了，因此可以进行初始的`UI`显示了。
* `find_start_position`：如果是恢复运行，则调用该函数来寻找到对应的样例的位置。
* `write_stats_file`：进行状态文件的写入，进行保存。
* `save_auto`：保存自动提取的`token`，用于后续字典模式的`fuzz`。

```c
  // afl-fuzz.c: 8070
	perform_dry_run(use_argv);

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;
```

接下来就是循环进行模糊测试了，单次循环的流程是：对种子队列进行排序（`cull_queue`）；刷新`UI`显示状态（`show_stats`）；调用`fuzz_one`函数进行单词的模糊测试运行。

在`fuzz_one`函数中会根据种子队列排序的结果挑选有效的种子，根据一定的策略进行变异运行，运行的结果反馈给`fuzzer`，更新路径覆盖的状态以及种子队列的状态等，如果崩溃保存样本，如果样本是有效样本则加入到种子队列中，结束本轮的运行，继续下一轮。该函数也是关键函数，后面也会详细进行介绍。

```c
  // afl-fuzz.c: 8091
	while (1) {

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        current_entry++;
        seek_to--;
        queue_cur = queue_cur->next;
      }

      show_stats();

      ...
      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing) cycles_wo_finds++; else use_splicing = 1;

      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;

      ...

    }

    skipped_fuzz = fuzz_one(use_argv);

    ...

    queue_cur = queue_cur->next;
    current_entry++;

  }
```

## 总结

总的来说，`afl-fuzz`的流程是根据指定的输入目录形成初步的种子队列，从队列中挑选样本进行变异模糊测试目标程序，监控目标程序运行状态更新相应的种子队列或保存崩溃样本，可以有效的更新迭代对目标程序的模糊测试。

此次分析只是对`afl-fuzz`的流程进行概念性的分析，后续会对监控运行以及样本变异的核心模块进行详细介绍。

文章首发于[跳跳糖](https://tttang.com/archive/1686/)。

## 参考

1. [AFL 漏洞挖掘技术漫谈（一）：用 AFL 开始你的第一次 Fuzzing](https://paper.seebug.org/841/)