---
layout: post
title: fuzzer AFL 源码分析（四）-监控
date: 2022-12-18
Author: f0cus77
tags: [fuzz, afl]
comments: true
toc: true
---

上一部分对`afl`如何实现反馈进行了较为详细的介绍，本文将对`afl`如何实现监控进行分析。监控是指`afl`能够成功运行目标程序、获取目标程序的反馈信息（运行状态）并判定此次运行是否有效（此次运行的样例是否增加了模糊测试的覆盖率、是否崩溃或超时），以更有效的指导下一次模糊测试及保存崩溃。

## 目标程序的运行

### 原理

样本的运行主要是基于前面分析过的`forkserver`机制进行的，`forkserver`起来之后，`fuzzer`将样本进行变异之后只需将样本写入到指定的文件路径，并通过控制管道写句柄通知`forkserver`进行新一轮次的运行，即可实现目标程序的模糊测试。

### 源码分析

在`fuzz_one`函数中，对种子进行一次变异后会调用`common_fuzz_stuff`对目标程序进行模糊测试，该函数代码如下所示。

```c
// afl-fuzz.c: 4646
/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

EXP_ST u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  if (post_handler) {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;

  }

  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {
      cur_skipped_paths++;
      return 1;
    }

  } else subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

     skip_requested = 0;
     cur_skipped_paths++;
     return 1;

  }

  /* This handles FAULT_ERROR for us: */

  queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}
```

其中`write_to_testcase`及`run_target`函数属于目标程序运行中的内容，在本章节介绍；`save_if_interesting`属于样本有效性分析中的内容，在下一章节介绍。

`post_handler`是用户自定义的函数，在`setup_post`函数中初始化，如果定义了`AFL_POST_LIBRARY`环境变量则会将该环境变量的值作为`lib`库加载到内存中并将该库中的函数`afl_postprocess`保存为`post_handler`，实现在模糊测试具体运行前`hook`模糊测试，执行用户自定义的代码。

`write_to_testcase`是保存变异后的样本数据到指定的路径，该函数代码如下所示。种子队列中保存的是文件的路径，当前运行的样例的路径也是指定的，实际的数据并未写入，而是在这里真正快要运行的时候才进行写入。`out_buf`指向的是是经过变异后的数据，`len`是数据的长度。如果`out_file`变量存在值的话，说明目标程序是从文件中获取数据，调用`unlink`函数删除之前保存的样本，将新的数据保存到该文件中；否则说明目标程序是从标准输入中获取数据，则调用`lseek`将句柄重置到最开始的地方，并将新的数据写入到该句柄当中。

```c
// afl-fuzz.c: 2504
/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  ck_write(fd, mem, len, out_file);

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}
```

`write_to_testcase`将变异后的数据保存好后，即调用`run_target`函数运行目标程序，代码如下所示。

先将记录覆盖率的共享内存`trace_bits`恢复成初始状态。

```c
// afl-fuzz.c: 2287
/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv, u32 timeout) {

  ...

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
```

接着函数分为三个部分，一个是如果模糊测试的模式是`dumb`模式，即没有基于反馈插桩的模式，则调用`fork`函数创建子进程调用`execve`来实现目标程序的运行。

```c
	// afl-fuzz.c: 2313
	if (dumb_mode == 1 || no_forkserver) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

      }

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

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(dev_null_fd);
      close(out_dir_fd);
      close(dev_urandom_fd);
      close(fileno(plot_file));

      ...

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }
```

如果目标程序经过`afl`编译插桩，说明在这之前`forkserver`已经起来了，则只需要通过控制管道向`forkserver`写入新的一轮模糊测试运行开始运行的控制指令，并等待`forkserver`通过状态管道将目标程序运行的`pid`传回实现了目标程序的运行。

```c
  // afl-fuzz.c: 2390
  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }
```

最后一部分则是目标运行状态的判定，是否崩溃、超时，样本覆盖的路径是否增加。

先来看超时是如何实现的，调用`setitimer`函数设定超时时间`timeout`，因为`waitpid`及`read`函数是阻塞函数，如果在这段时间内没有接收到子进程信号（`dumb`模式）或从状态管道未接收到数据（反馈模式）则会触发超时的函数，超时处理函数是`handle_timeout`函数，它会杀掉对应的运行进程，并将`child_timed_out`标志位置位。完成之后恢复超时的时间，并将运行次数`+1`

``` c
  // afl-fuzz.c: 2415
  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");

    }

  }
  if (!WIFSTOPPED(status)) child_pid = 0;

  getitimer(ITIMER_REAL, &it);
  exec_ms = (u64) timeout - (it.it_value.tv_sec * 1000 +
                             it.it_value.tv_usec / 1000);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  total_execs++;
```

接下来是对目标程序的运行状态进行初步的判定，先调用`classify_counts`函数对共享内存`trace_bits`进行处理，这个函数在后面样本有效性分析再进行详细介绍。然后对目标程序运行后的返回状态码`status`进行判定，通过分析结果来将运行结果返回，崩溃是`FAULT_CRASH`，超时是`FAULT_TMOUT`等。

```c
  // afl-fuzz.c: 2460
  tb4 = *(u32*)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon) {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  /* It makes sense to account for the slowest units only if the testcase was run
  under the user defined timeout. */
  if (!(timeout > exec_tmout) && (slowest_exec_ms < exec_ms)) {
    slowest_exec_ms = exec_ms;
  }

  return FAULT_NONE;

}
```

## 样本有效性的判定

### 原理

样本的有效性是指目标程序使用该样本运行后，该样本是否增加了目标程序的覆盖率、是否导致目标程序崩溃以及是否导致目标程序崩溃。在目标程序完成运行后，覆盖率信息都记录在共享内存`trace_bits`中。会将记录的覆盖率信息进行的简单的处理后，调用`save_if_interesting`函数来看此次运行的样例是否有效。

在`save_if_interesting`函数中，会调用`has_new_bits`函数查看是否有新增的路径，如果有的话将该样本添加到种子队列中；然后调用`calibrate_case`函数来校正样例的运行行为；对于新增到种子队列中的样例会调用`update_bitmap_score`函数根据样例运行的状态对总的种子情况进行新的排序，以决定下次运行时挑选对输入种子；最后根据目标程序的运行结果（超时、崩溃）保存到对应的路径当中。

### 源码分析

在进行具体分析前，先来看几个和样本有效性判断的数据结构的定义。`trace_bits`是共享内存，由`fuzzer`以及目标程序共享，记录每次样本运行的覆盖率；`virgin_bits`用来比对路径是否新增，初始值是全`0xff`，运行过后是`trace_bits`位的取反；`virgin_tmout`用来比对是否是新出现的超时的样例，初始值是全`0xff`，运行过后是`trace_bits`位的取反；`virgin_crash`用来比对是否是新出现的崩溃，初始值是全`0xff`，运行过后是`trace_bits`位的取反；`top_rated`数组是存储的是针对每条边挑选当前最适合的种子。

```c
// afl-fuzz.c: 151
EXP_ST u8* trace_bits;                /* SHM with instrumentation bitmap  */

EXP_ST u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
           virgin_tmout[MAP_SIZE],    /* Bits we haven't seen in tmouts   */
           virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

// afl-fuzz.c: 275
static struct queue_entry*
  top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */
```

反馈信息记录的过程如下所示，通过共享内存记录了路径的运行次数。

```
  cur_location = <COMPILE_TIME_RANDOM>;
  shared_mem[cur_location ^ prev_location]++; 
  prev_location = cur_location >> 1;
```

路径运行的次数随着运行数值的增加（如`10000`次与`10001`次），次数相差不大的话对于覆盖率或者说对程序的运行行为不会有太大影响，因此可以忽略。为了减少运行次数带来的区别，`afl`设计实现了一个集合数组来表示运行的次数，当运行的次数在一个范围的时候，都会被归类为同一运行次数（如`4`、`5`、`6`、`7`都会被归为`8`次）。

```c
// afl-fuzz.c: 1139
/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};
```

上面说过的`classify_counts`便是对运行次数进行处理的函数，代码如下所示，通过在数组中查表实现对运行次数的快速处理。

```c
// afl-fuzz.c: 1175
static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}
```

再来看`save_if_interesting`函数是怎样判断一个样本是否是`interesting`的。

`crash_mode`默认情况是`FAULT_NONE`，正常模糊测试情况下都会进到该分支下面。首先会调用`has_new_bits`来与总覆盖率的状态`virgin_bits`进行比对，来看在本次运行过程中是否有新的路径产生，如果有的话就调用`add_to_queue`将它作为新的种子存入到种子队列当中并调用`hash32`计算它本次运行的所覆盖率的哈希值；没有的话，则直接返回。

```c
// afl-fuzz.c: 3159
/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  if (fault == crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (!(hnb = has_new_bits(virgin_bits))) {
      if (crash_mode) total_crashes++;
      return 0;
    }    

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(fn, len, 0);

    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      queued_with_cov++;
    }

    queue_top->exec_cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

```

来看`has_new_bits`函数的实现，如下所示。比对的方法是遍历查看所有的本次样例运行路径覆盖的状态数组是否有值以及参数路径覆盖状态该位是否被置位。如果`trace_bits`有值且`virgin_map`为`0xff`，说明本次路径覆盖了该边且之前的样例都没有覆盖该边，发现了新的路径，此时返回的`new_bits`级别是`2`；如果`trace_bits`有值，且`virgin_map`对应的值不为`0xff`，说明之前样例已经覆盖了本条边，但本次路径覆盖了的路径所运行的次数与之前存储的次数不一致，发现了新的路径运行次数，返回级别是`1`；上述两种情况都需要将`virgin_map`对应更新。

如果没有更新，返回级别是`0`，如果有更新的话，且传入的参数是总路径覆盖率状态数组的话，要将`bitmap_changed`置位。

```c
// afl-fuzz.c: 899
/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen. 
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

static inline u8 has_new_bits(u8* virgin_map) {

#ifdef WORD_SIZE_64

  u64* current = (u64*)trace_bits;
  u64* virgin  = (u64*)virgin_map;

  u32  i = (MAP_SIZE >> 3);

#else

  u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^WORD_SIZE_64 */

  u8   ret = 0;

  while (i--) {

    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */

    if (unlikely(*current) && unlikely(*current & *virgin)) {

      if (likely(ret < 2)) {

        u8* cur = (u8*)current;
        u8* vir = (u8*)virgin;

        /* Looks like we have not found any new bytes yet; see if any non-zero
           bytes in current[] are pristine in virgin[]. */

#ifdef WORD_SIZE_64

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
            (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
            (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
        else ret = 1;

#else

        if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^WORD_SIZE_64 */

      }

      *virgin &= ~*current;

    }

    current++;
    virgin++;

  }

  if (ret && virgin_map == virgin_bits) bitmap_changed = 1;

  return ret;

}
```

再回到`save_if_interesting`函数中，判断完是否有新的路径产生后，会调用`calibrate_case`对样例运行的状态进行校正，实现保证它运行的状态是确定的；然后将样例的数据保存到对应的文件路径中。

```c
		// afl-fuzz.c: 3203
		/* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

```

跟进去`calibrate_case`函数看它是怎么做校验的，如下所示。如果`forksrv_pid`没有值的话，说明`forkserver`还没启动，此时需要初始化`forkserver`，调用`init_forkserver`函数去实现。

如果`q->exec_cksum`有值，说明该种子已经被运行过，将之前运行的路径状态保存到`first_trace`中。

根据`fast_cal`是否被置位，设置循环次数是`3`还是`CAL_CYCLES`，用样例作为输入并执行目标程序相应次数（`write_to_testcase`以及`run_target`函数）。如果当前本次运行的哈希值`cksum`与之前运行的哈希值`q->exec_cksum`不一致，说明相同的输入形成的路径不一致，不一致的地方可以被标记为变量`var_bytes`并将标志位`var_detected`置位。

```c
// afl-fuzz.c: 2567
/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  ...

  q->cal_failed++;

  stage_name = "calibration";
  stage_max  = fast_cal ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);

  if (q->exec_cksum) {

    memcpy(first_trace, trace_bits, MAP_SIZE);
    hnb = has_new_bits(virgin_bits);
    if (hnb > new_bits) new_bits = hnb;

  }

  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode) goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < MAP_SIZE; i++) {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {

            var_bytes[i] = 1;
            stage_max    = CAL_CYCLES_LONG;

          }

        }

        var_detected = 1;

      } else {

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);

      }

    }

  }
```

循环执行完成之后，根据执行的时间等保存样例所运行的状态；然后调用`update_bitmap_score`函数来计算该样例的得分并更新总的样例的有效状态；最后看样例运行过程中是否有变量行为，在种子链表的结构体中设置对应的标志位。

```c
	// afl-fuzz.c: 2669
	stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    queued_with_cov++;
  }

  /* Mark variable paths. */

  if (var_detected) {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior) {
      mark_as_variable(q);
      queued_variable++;
    }

  }

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) show_stats();

  return fault;

}
```

`update_bitmap_score`函数是一个比较关键的函数，代码如下所示。

一个种子的得分是运行时间乘以种子长度（`q->exec_us * q->len`），得分越少说明种子所消耗的性能越少，该种子的价值越高。循环遍历`trace_bits`数组内容，当前样例覆盖该路径时，查看总的路径队列中已保存的种子，如果当前种子的得分比之前保存的种子得分要少，说明该要覆盖该路径时，当前的样例是更优的选择，更新`top_rated`数组，同时将样例的`top_rated`引用次数`tc_ref`加`1`（之前的种子`tc_ref`减`1`）；并将`score_changed`置位，表明所有种子队列的排名已经发生了变化，`top_rated`存储的是要覆盖该边所消耗性能最小的样本，对于后续选择哪个种子进行新一轮的循环比较重要。

```c
// afl-fuzz.c: 1255
/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of top_rated[] entries
   for every byte in the bitmap. We win that slot if there is no previous
   contender, or if the contender has a more favorable speed x size factor. */

static void update_bitmap_score(struct queue_entry* q) {

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;

         /* Looks like we're going to win. Decrease ref count for the
            previous winner, discard its trace_bits[] if necessary. */

         if (!--top_rated[i]->tc_ref) {
           ck_free(top_rated[i]->trace_mini);
           top_rated[i]->trace_mini = 0;
         }

       }

       /* Insert ourselves as the new winner. */

       top_rated[i] = q;
       q->tc_ref++;

       if (!q->trace_mini) {
         q->trace_mini = ck_alloc(MAP_SIZE >> 3);
         minimize_bits(q->trace_mini, trace_bits);
       }

       score_changed = 1;

     }

}
```

`calebrate_case`函数执行完成后，再回到`save_if_interesting`函数当中。根据目标程序运行返回的`status`（`fault`）来进行最终的处理。如果是超时（`FAULT_TMOUT`）且样例的覆盖路径使得超时的路径覆盖情况（`virgin_tmout`）发生了更新，则将该样例保存到`hang`目录中；如果是崩溃（`FAULT_CRASH`）且样例的覆盖路径使得崩溃的路径覆盖情况（`virgin_crash`）发生了更新，则将该样例保存到`crash`路径中。

```c
  // afl-fuzz.c: 3217
	switch (fault) {

    case FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      unique_tmouts++;

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_target(argv, hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      unique_hangs++;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef WORD_SIZE_64
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^WORD_SIZE_64 */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      unique_crashes++;

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}
```

至此，样例的有效性判定分析完成。

## 总结

本文阐述了`afl`对目标程序进行模糊测试时是如何运行运行目标程序以及对目标程序反馈的路径信息是如何处理的。反馈机制使得输入的种子与变异不再是毫无头绪与选择的，模糊测试的效率大大的提升。

后续`fuzzer`的设计应当考虑除了路径覆盖，还有哪些反馈的信息可以用来作为种子是否有效的判定。

## 参考

1. [Technical "whitepaper" for afl-fuzz](https://lcamtuf.coredump.cx/afl/technical_details.txt)

