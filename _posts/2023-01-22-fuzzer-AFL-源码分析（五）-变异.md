---
layout: post
title: fuzzer AFL 源码分析（五）-变异
date: 2023-01-22
Author: f0cus77
tags: [fuzz, afl]
comments: true
toc: true
---

前面几篇文章将`afl`的大部分内容都已经覆盖到了（编译、反馈到监控），最后一个部分主要讲`afl`是如何挑选样本并针对样本的数据进行变异的。通过之前的分析我们已经知道，编译的种子通过链表的形式形成种子队列，种子经过变异后如果能够触发目标程序新的行为，会作为新的种子队列存入到链表中。但是对于新一轮的模糊测试，挑选哪个种子进行变异以及如何变异尚未解决，本文主要阐述`afl`是如何挑选种子进行变异以及如何变异。

## 种子的挑选

种子的挑选会先将种子进行排序，调用`cull_queue`函数基于`top_rated`数组中的内容采用贪婪算法对当前种子的优先级进行排序，函数代码如下所示。

`temp_v`数组采用比特位来标记当前边的路径是否已经被当前遍历过的样例所覆盖，首先将`temp_v`数组初始化为`0xff`。

```c
// afl-fuzz.c: 1310
/* The second part of the mechanism discussed above is a routine that
   goes over top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */

static void cull_queue(void) {

  struct queue_entry* q;
  static u8 temp_v[MAP_SIZE >> 3];
  u32 i;

  if (dumb_mode || !score_changed) return;

  score_changed = 0;

  memset(temp_v, 255, MAP_SIZE >> 3);

  queued_favored  = 0;
  pending_favored = 0;
```

种子队列中结构体中有个标志位`favored`表明该种子样例在当前队列中是否是`favorite`的，先将种子队列中的所有标志位清空，然后循环遍历`top_rated`数组看对对应的种子`favored`置位。

```c
	// afl-fuzz.c: 1331
	q = queue;

  while (q) {
    q->favored = 0;
    q = q->next;
  }
```

对于当前边的最优种子选择`top_rated[i]`，查看当前边是否已经在前面被设置为`favored`的种子覆盖了（`(temp_v[i >> 3] & (1 << (i & 7)))`），如果覆盖了则跳过该种子；如果该边没有被前面被设置为`favored`的种子所覆盖，则设置当前的种子为`favored`（`top_rated[i]->favored = 1`），并且遍历该种子样例所覆盖的路径边数，同时将所对应的边的`temp_v`置位（`temp_v[j] &= ~top_rated[i]->trace_mini[j]`）。

`top_rated[i]->was_fuzzed`表示该种子已经被模糊测试过，如果某个种子该标志位没有被置位，说明种子队列中有没有被模糊测试的种子，将全局变量`pending_favored`加`1`。

通过该方法选择出在当前种子队列中可以覆盖最广情况的种子集合，将所对应的种子的`favored`位置位，后续对于`favored`置位的种子会以更高的概率进行变异。

```c

	// afl-fuzz.c: 1338
  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < MAP_SIZE; i++)
    if (top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7)))) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }
```

排序完成后，`main`函数通过种子队列链表对所有的种子进行遍历，对每个种子调用`fuzz_one`函数进行新的一轮的模糊测试。

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

      ...

    skipped_fuzz = fuzz_one(use_argv);

    ...

    queue_cur = queue_cur->next;
    current_entry++;

  }
```

对于每个种子是否进行模糊测试则是使用一定的策略来进行决定：

* 如果`pending_favored`有值，说明种子队列中存在没有被模糊测试且是`favored`的种子。对于当前种子来说，如果`queue_cur->was_fuzzed`被置位或`queue_cur->favored`没被置位，表明该种子已经被模糊测试过或不是`favored`，那么将有`99%`的概率跳过该种子；
* 如果`pending_favored`没有值，说明种子队列中没有没被模糊测试过且是`favored`的种子。对于当前种子来说，如果`favored`标志位没有被置位但该种子没有被模糊测试过，那么会有`75%`的概率跳过该种子；
* 如果`pending_favored`没有值，说明种子队列中没有没被模糊测试过且是`favored`的种子。对于当前种子来说，如果`favored`标志位没有被置位且该种子已经被模糊测试过，那么会有`95%`的概率跳过该种子；
* 除上述三种情况外，会对当前种子进行模糊测试。

```c
// afl-fuzz.c: 4999
static u8 fuzz_one(char** argv) {

  ...

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }
```

## 种子的变异

说明一下，变异阶段的文字大部分是直接搬运《[AFL技术实现分析](https://blog.csdn.net/qq_32464719/article/details/80592902)》的，因为这篇文章确实翻译和总结《[Technical “whitepaper” for afl-fuzz](http://lcamtuf.coredump.cx/afl/technical_details.txt)》的挺好了，也就懒得自己再写了。

`AFL`会对挑选的当前种子进行大量变异，并检查运行后是否会引起目标崩溃、发现新路径等结果。变异的主要类型如下：

* `bitflip`，按位翻转，`1`变为`0`，`0`变为`1`；
* `arithmetic`，整数加/减算术运算；
* `interest`，把一些特殊内容替换到原文件中；
* `dictionary`，把自动生成或用户提供的`token`替换/插入到原文件中；
* `havoc`，中文意思是“大破坏”，此阶段会对原文件进行大量变异；
* `splice`，中文意思是“绞接”，此阶段会将两个文件拼接起来得到一个新的文件；

其中，前四项`bitflip`, `arithmetic`, `interest`, `dictionary`是非`dumb mode`（`-d`）和主`fuzzer`（`-M`）会进行的操作，由于其变异方式没有随机性，所以也称为`deterministic fuzzing`；`havoc`和`splice`则存在随机性，所有的`fuzzer`都会执行的变异。

`AFL`会对文件队列的逐个个进行变异处理。当队列中的全部文件都变异测试后，就完成了一个`cycle`，这个就是`AFL`状态栏右上角的`cycles done`。而正如`cycle`的意思所说，整个队列又会从第一个文件开始，再次进行变异，不过与第一次变异不同的是，这一次就不需要再进行`deterministic fuzzing`了，即种子文件经过第一次变异后，会直接进入到`havoc`变异阶段。

```c
  // afl-fuzz.c: 5145
  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;
```

下面来看具体的实现。

在具体变异之前会先对种子进行裁剪，实现种子的最小化，使得模糊测试可以更高效的进行。如果当前种子没有经过裁剪（`!queue_cur->trim_done`），则会调用`trim_case`函数对种子进行裁剪。

```c
	// afl-fuzz.c: 5113
	/************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      cur_skipped_paths++;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */

    queue_cur->trim_done = 1;

    if (len != queue_cur->len) len = queue_cur->len;

  }
```

跟进去`trim_case`函数，如下所示。思路是根据一定的策略删除种子中的部分数据，用删除后的种子作为输入运行目标程序，如果路径覆盖率的`hash`值与删除前的`hash`值一致，说明数据被删除不影响代码覆盖率，可以删除。

具体来说会将种子数据依次进行片段删除，从种子总长度的`1/16`开始删除（第一次删除第一个`1/16`、第二次删除第二个`1/16`），每次删除运行目标程序并进行结果比对；删除至文件末尾之后，以`2`的指数倍来进行更小的细粒度的删除，第二次为`1/32`、第三次为`1/64`，一直到`1/1024`。

运行完成后如果种子被裁剪了，将最终的结果写回到种子文件中并调用`update_bitmap_score`更新种子得分。

```c
/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

static u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (q->len < 5) return 0;

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    stage_cur = 0;
    stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 cksum;

      write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(argv, exec_tmout);
      trim_execs++;

      if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2  = next_p2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {

          needs_write = 1;
          memcpy(clean_trace, trace_bits, MAP_SIZE);

        }

      } else remove_pos += remove_len;

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % stats_update_freq)) show_stats();
      stage_cur++;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }

abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}
```

裁剪完成后，调用`calculate_score`来计算当前种子的`perf_score`，该变量是用来衡量后续将种子用于随机破坏性变异的程度（次数）。

```c
  // afl-fuzz.c: 5139
  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);
```

函数代码如下所示，会根据当前种子作为输入的运行时间与所有种子作为输入的平均运行时间做比较，运行时间越短得分越低，运行时间越长得分越高；根据当前种子的路径覆盖面积与所有种子的平均覆盖面积做比较，覆盖面积越大得分越低，覆盖面积越小得分越高；根据发现当前种子`fuzzer`已进行的轮次（`handicap`）来进行计算，进行的轮次越少得分越低，进行轮次越多得分越高；根据当前种子的变异深度来进行计算，变异深度越浅得分越低，变异深度越深得分越高；如果得分超过了最大值，则将其设为最大值。

```c
// afl-fuzz.c: 4727 
/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    q->handicap--;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > HAVOC_MAX_MULT * 100) perf_score = HAVOC_MAX_MULT * 100;

  return perf_score;

}
```

接下来就是对种子进行具体的变异了。

### bitflip

`bitflip`是字节翻转，对比特位进行一定的翻转。会根据翻转量/步长进行多种不同的翻转，按照顺序依次为：
`bitflip 1/1`，每次翻转`1`个`bit`，按照每`1`个`bit`的步长从头开始。

```c
  // afl-fuzz.c: 5160
  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
```

在进行`bitflip 1/1`变异时，对于每个`byte`的最低位（`least significant bit`）翻转还进行了额外的处理：如果连续多个`bytes`的最低位被翻转后，程序的执行路径都未变化，而且与原始执行路径不一致那么就把这一段连续的bytes判断是一条token。

例如，PNG文件中用IHDR作为起始块的标识，那么就会存在类似于以下的内容：

```
    ........IHDR........
```

当翻转到字符I的最高位时，因为`IHDR`被破坏，此时程序的执行路径肯定与处理正常文件的路径是不同的；随后在翻转接下来`3`个字符的最高位时，`IHDR`标识同样被破坏，程序应该会采取同样的执行路径。由此，`AFL`就判断得到一个可能的`token`：`IHDR`并将其记录下来为后面的变异提供备选。
AFL采取的这种方式是非常巧妙的：就本质而言，这实际上是对每个byte进行修改并检查执行路径；但集成到`bitflip`后，就不需要再浪费额外的执行资源了。

```c
    // afl-fuzz.c: 5219
		if (!dumb_mode && (stage_cur & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        a_len++;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        a_len++;

      }

    }

  }
```

`bitflip 2/1`，每次翻转相邻的`2`个`bit`，按照每`1`个`bit`的步长从头开始：

```c
	// afl-fuzz.c: 5266
	/* Two walking bits. */

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

```

`bitflip 4/1`，每次翻转相邻的`4`个`bit`，按照每`1`个`bit`的步长从头开始：

```c
  // afl-fuzz.c: 5293
	/* Four walking bits. */

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }
```

`bitflip 8/8`，每次翻转相邻的`8`个`bit`，按照每`8`个`bit`的步长从头开始，即依次对每个`byte`做翻转。

在进行`bitflip 8/8`变异时，`AFL`还生成了一个非常重要的信息：`effector map`。`effector map`几乎贯穿了整个`deterministic fuzzing`的始终。
具体地，在对每个`byte`进行翻转时，如果其造成执行路径与原始路径不一致，就将该`byte`在`effector map`中标记为`1`，即“有效”的，否则标记为`0`，即“无效”的。
这样做的逻辑是：如果一个`byte`完全翻转，都无法带来执行路径的变化，那么这个`byte`很有可能是属于`data`，而非`metadata`（例如`size`， `flag`等），对整个`fuzzing`的意义不大。所以，在随后的一些变异中，会参考`effector map`，跳过那些“无效”的`byte`，从而节省了执行资源。
由此，通过极小的开销（没有增加额外的执行次数），`AFL`又一次对文件格式进行了启发式的判断。

```c
  // afl-fuzz.c: 5337
	/* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    eff_cnt++;
  }

  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;

      if (cksum != queue_cur->exec_cksum) {
        eff_map[EFF_APOS(stage_cur)] = 1;
        eff_cnt++;
      }

    }

    out_buf[stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);

  } else {

    blocks_eff_select += eff_cnt;

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

```

`bitflip 16/8`，每次翻转相邻的`16`个`bit`，按照每`8`个`bit`的步长从头开始，即依次对每个`word`做翻转。如果相邻的两个`byte`在`eff_map`中都是无效的，则无需对这`16`个`bit`进行翻转。

```c
	// afl-fuzz.c: 5416
	/* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u16*)(out_buf + i) ^= 0xFFFF;


  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;
```

`bitflip 32/8`，每次翻转相邻的`32`个`bit`，按照每`8`个`bit`的步长从头开始，即依次对每个`dword`做翻转。如果相邻的四个`byte`在`eff_map`中都是无效的，则无需对这`32`个`bit`进行翻转。

```c
  // afl-fuzz.c: 5455
	/* Four walking bytes. */

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max--;
      continue;
    }

    stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    stage_cur++;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  if (no_arith) goto skip_arith;
```

### arithmetic

在`bitflip`变异全部进行完成后，便进入下一个阶段：`arithmetic`。与`bitflip`类似的是，`arithmetic`根据目标大小的不同，也分为了多个子阶段。

整个过程AFL还会智能地跳过某些`arithmetic`变异。第一种情况就是前面提到的`effector map`：如果一个整数的所有`bytes`都被判断为“无效”，那么就跳过对整数的变异。第二种情况是之前`bitflip`已经生成过的变异：如果加/减某个数后，其效果与之前的某种`bitflip`相同，那么这次变异肯定在上一个阶段已经执行过了，此次便不会再执行。

加减变异的上限，在`config.h`中的宏`ARITH_MAX`定义，默认为`35`。所以，对目标整数会进行`+1`,` +2`, …, `+35`,` -1`,` -2`, …, `-35`的变异。特别地，由于整数存在大端序和小端序两种表示方式，`AFL`会贴心地对这两种整数表示方式都进行变异。

`arith 8/8`，每次对`8`个bit进行加减运算，按照每`8`个`bit`的步长从头开始，即对文件的每个`byte`进行整数加减变异。

```c
  // afl-fuzz.c: 5497
	/* 8-bit arithmetics. */

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      r =  orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      out_buf[i] = orig;

    }

  }
```

`arith 16/8`，每次对`16`个`bit`进行加减运算，按照每`8`个`bit`的步长从头开始，即对文件的每个`word`进行整数加减变异：

```c
 	// afl-fuzz.c: 5561
	/* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;
 
      } else stage_max--;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u16*)(out_buf + i) = orig;

    }

  }
```

`arith 32/8`，每次对`32`个`bit`进行加减运算，按照每`8`个`bit`的步长从头开始，即对文件的每个`dword`进行整数加减变异：

```c
  // afl-fuzz.c: 5655
	/* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; j++) {

      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      *(u32*)(out_buf + i) = orig;

    }

  }
```

### interest

`interesting values`，是`AFL`预设的一些比较特殊的数：

```c
// afl-fuzz.c: 294
static s8  interesting_8[]  = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };
```

这些数的定义在config.h文件中，可以看到，用于替换的基本都是可能会造成溢出的数。

```c
// afl-fuzz.c: 227
/* List of interesting values to use in fuzzing. */

#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */
```

与之前类似，`effector map`仍然会用于判断是否需要变异；此外如果某个`interesting value`，是可以通过`bitflip`或者`arithmetic`变异达到，那么这样的重复性变异也是会跳过的。

具体可分为：

`interest 8/8`，每次对`8`个`bit`进替换，按照每`8`个`bit`的步长从头开始，即对文件的每个`byte`进行替换：

```c
  // afl-fuzz.c: 5753
	stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; i++) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); j++) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        stage_max--;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      stage_cur++;

    }

  }

```

`interest 16/8`，每次对`16`个`bit`进替换，按照每`8`个`bit`的步长从头开始，即对文件的每个`word`进行替换：

```c
  // afl-fuzz.c: 5804
	/* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; i++) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; j++) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u16*)(out_buf + i) = orig;

  }
```

`interest 32/8`，每次对`32`个`bit`进替换，按照每`8`个`bit`的步长从头开始，即对文件的每个`dword`进行替换：

```c
  // afl-fuzz.c: 5874
	/* Setting 32-bit integers, both endians. */

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; j++) {

      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        stage_cur++;

      } else stage_max--;

    }

    *(u32*)(out_buf + i) = orig;

  }
```

### dictionary

进入到这个阶段，就接近deterministic fuzzing的尾声了。

字典模式是指用用户提供的字典或在`bitflip`中提取的字典替换种子的输入，包括三个子阶段。。用户提供的`tokens`，是在词典文件中设置并通过`-x`选项指定的，如果没有则跳过相应的用户提供的字典变异的阶段

第一个阶段是`user extras (over)`，即使用用户提供的字典对种子的数据进行覆盖。对于用户提供的`tokens`，AFL先按照长度从小到大进行排序。这样做的好处是，只要按照顺序使用排序后的`tokens`，那么后面的`token`不会比之前的短，从而每次覆盖替换后不需要再恢复到原状。

随后，`AFL`会检查`tokens`的数量，如果数量大于预设的`MAX_DET_EXTRAS`（默认值为200），那么对每个`token`会根据概率来决定是否进行替换。

`effector map`在这里同样被使用了：如果要替换的目标`bytes`全部是“无效”的，那么就跳过这一段，对下一段目标执行替换。

```c
  // afl-fuzz.c: 5493
	/********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }
```

第二个阶段是`user extras (insert)`，即将用户提供的字典插入到种子文件中进行变异。对用户提供的`tokens`执行插入变异。不过与上一个子阶段不同的是，此时并没有对`tokens`数量的限制，所以全部`tokens`都会从原文件的第`1`个`byte`开始，依次向后插入；此外，由于原文件并未发生替换，所以`effector map`不会被使用。

这一子阶段最特别的地方，就是变异不能简单地恢复。之前每次变异完，在变异位置处简单取逆即可，例如`bitflip`后，再进行一次同样的`bitflip`就恢复为原文件。正因为如此，之前的变异总体运算量并不大。

但是，对于插入这种变异方式，恢复起来则复杂的多，`AFL`采取的方式是：将原文件分割为插入前和插入后的部分，再加上插入的内容，将这`3`部分依次复制到目标缓冲区中。而对每个`token`的每处插入，都需要进行上述过程。所以，如果用户提供了大量`tokens`，或者原文件很大，那么这一阶段的运算量就会非常的多。直观表现上，就是`AFL`的执行状态栏中，`user extras (insert)`的总执行量很大，执行时间很长。如果出现了这种情况，那么就可以考虑适当删减一些`tokens`。

```c
// afl-fuzz.c: 6007 
/* Insertion of user-supplied extras. */

  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; i++) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; j++) {

      if (len + extras[j].len > MAX_FILE) {
        stage_max--; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      stage_cur++;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }
```

最后一个阶段示`auto extras (over)`，这一项与`user extras (over)`很类似，区别在于，这里的`tokens`是最开始`bitflip`阶段自动生成的。另外，自动生成的`tokens`总量会由`USE_AUTO_EXTRAS`限制（默认为`10`）。

```c
 	// afl-fuzz.c: 6060
	stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; i++) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

        stage_max--;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      stage_cur++;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }
```

### havoc

对于非`dumb mode`的主`fuzzer`来说，完成了上述`deterministic fuzzing`后，便进入了充满随机性的这一阶段；对于`dumb mode`或者从`fuzzer`来说，则是直接从这一阶段开始。

`havoc`，顾名思义，是充满了各种随机生成的变异，是对原文件的“大破坏”。具体来说，`havoc`包含了对原文件的多轮变异，每一轮都是将多种方式组合而成：

- 随机选取某个`bit`进行翻转

  ```c
          // afl-fuzz.c: 6167
  				case 0:
  
            /* Flip a single bit somewhere. Spooky! */
  
            FLIP_BIT(out_buf, UR(temp_len << 3));
            break;
  ```

- 随机选取某个`byte`，将其设置为随机的`interesting value`：

  ```c
          // afl-fuzz.c: 6174
  				case 1: 
  
            /* Set byte to interesting value. */
  
            out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
            break;
  ```

- 随机选取某个`word`，并随机选取大、小端序，将其设置为随机的`interesting value`：

  ```c
          // afl-fuzz.c: 6181
  				case 2:
  
            /* Set word to interesting value, randomly choosing endian. */
  
            if (temp_len < 2) break;
  
            if (UR(2)) {
  
              *(u16*)(out_buf + UR(temp_len - 1)) =
                interesting_16[UR(sizeof(interesting_16) >> 1)];
  
            } else {
  
              *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
                interesting_16[UR(sizeof(interesting_16) >> 1)]);
  
            }
  
            break;
  ```

- 随机选取某个`dword`，并随机选取大、小端序，将其设置为随机的`interesting value`：

  ```c
          // afl-fuzz.c: 6201
  				case 3:
  
            /* Set dword to interesting value, randomly choosing endian. */
  
            if (temp_len < 4) break;
  
            if (UR(2)) {
    
              *(u32*)(out_buf + UR(temp_len - 3)) =
                interesting_32[UR(sizeof(interesting_32) >> 2)];
  
            } else {
  
              *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
                interesting_32[UR(sizeof(interesting_32) >> 2)]);
  
            }
  
            break;
  ```

- 随机选取某个`byte`，对其减去一个随机数：

  ```c
          // afl-fuzz.c: 6221
  				case 4:
  
            /* Randomly subtract from byte. */
  
            out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
            break;
  ```

- 随机选取某个`byte`，对其加上一个随机数：

  ```c
          // afl-fuzz.c: 6228
  				case 5:
  
            /* Randomly add to byte. */
  
            out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
            break;
  ```

- 随机选取某个`word`，并随机选取大、小端序，对其减去一个随机数：

  ```c
          // afl-fuzz.c: 6235
  				case 6:
  
            /* Randomly subtract from word, random endian. */
  
            if (temp_len < 2) break;
  
            if (UR(2)) {
  
              u32 pos = UR(temp_len - 1);
  
              *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
  
            } else {
  
              u32 pos = UR(temp_len - 1);
              u16 num = 1 + UR(ARITH_MAX);
  
              *(u16*)(out_buf + pos) =
                SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);
  
            }
  
            break;
  ```

- 随机选取某个`word`，并随机选取大、小端序，对其加上一个随机数：

  ```c
          // afl-fuzz.c: 6259
  				case 7:
  
            /* Randomly add to word, random endian. */
  
            if (temp_len < 2) break;
  
            if (UR(2)) {
  
              u32 pos = UR(temp_len - 1);
  
              *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
  
            } else {
  
              u32 pos = UR(temp_len - 1);
              u16 num = 1 + UR(ARITH_MAX);
  
              *(u16*)(out_buf + pos) =
                SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);
  
            }
  
            break;
  ```

- 随机选取某个`dword`，并随机选取大、小端序，对其减去一个随机数：

  ```c
          // afl-fuzz.c: 6283
  				case 8:
  
            /* Randomly subtract from dword, random endian. */
  
            if (temp_len < 4) break;
  
            if (UR(2)) {
  
              u32 pos = UR(temp_len - 3);
  
              *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
  
            } else {
  
              u32 pos = UR(temp_len - 3);
              u32 num = 1 + UR(ARITH_MAX);
  
              *(u32*)(out_buf + pos) =
                SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);
  
            }
  
            break;
  ```

- 随机选取某个`dword`，并随机选取大、小端序，对其加上一个随机数：

  ```c
          // afl-fuzz.c: 6307
  				case 9:
  
            /* Randomly add to dword, random endian. */
  
            if (temp_len < 4) break;
  
            if (UR(2)) {
  
              u32 pos = UR(temp_len - 3);
  
              *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
  
            } else {
  
              u32 pos = UR(temp_len - 3);
              u32 num = 1 + UR(ARITH_MAX);
  
              *(u32*)(out_buf + pos) =
                SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);
  
            }
  
            break;
  ```

- 随机选取某个`byte`，将其设置为随机数：

  ```c
          // afl-fuzz.c: 6331
          case 10:
  
            /* Just set a random byte to a random value. Because,
               why not. We use XOR with 1-255 to eliminate the
               possibility of a no-op. */
  
            out_buf[UR(temp_len)] ^= 1 + UR(255);
            break;
  ```

- 随机删除一段`bytes`：

  ```c
          // afl-fuzz.c: 6340
  				case 11 ... 12: {
  
              /* Delete bytes. We're making this a bit more likely
                 than insertion (the next option) in hopes of keeping
                 files reasonably small. */
  
              u32 del_from, del_len;
  
              if (temp_len < 2) break;
  
              /* Don't delete too much. */
  
              del_len = choose_block_len(temp_len - 1);
  
              del_from = UR(temp_len - del_len + 1);
  
              memmove(out_buf + del_from, out_buf + del_from + del_len,
                      temp_len - del_from - del_len);
  
              temp_len -= del_len;
  
              break;
  
            }
  ```

- 随机选取一个位置，插入一段随机长度的内容，其中`75%`的概率是插入原文中随机位置的内容，`25%`的概率是插入一段随机选取的数：

  ```c
          // afl-fuzz.c: 6365
  				case 13:
  
            if (temp_len + HAVOC_BLK_XL < MAX_FILE) {
  
              /* Clone bytes (75%) or insert a block of constant bytes (25%). */
  
              u8  actually_clone = UR(4);
              u32 clone_from, clone_to, clone_len;
              u8* new_buf;
  
              if (actually_clone) {
  
                clone_len  = choose_block_len(temp_len);
                clone_from = UR(temp_len - clone_len + 1);
  
              } else {
  
                clone_len = choose_block_len(HAVOC_BLK_XL);
                clone_from = 0;
  
              }
  
              clone_to   = UR(temp_len);
  
              new_buf = ck_alloc_nozero(temp_len + clone_len);
  
              /* Head */
  
              memcpy(new_buf, out_buf, clone_to);
  
              /* Inserted part */
  
              if (actually_clone)
                memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
              else
                memset(new_buf + clone_to,
                       UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);
  
              /* Tail */
              memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                     temp_len - clone_to);
  
              ck_free(out_buf);
              out_buf = new_buf;
              temp_len += clone_len;
  
            }
  
            break;
  ```

- 随机选取一个位置，替换为一段随机长度的内容，其中`75%`的概率是替换成原文中随机位置的内容，`25%`的概率是替换成一段随机选取的数：

  ```c
          // afl-fuzz.c: 6415
  				case 14: {
  
              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                 bytes (25%). */
  
              u32 copy_from, copy_to, copy_len;
  
              if (temp_len < 2) break;
  
              copy_len  = choose_block_len(temp_len - 1);
  
              copy_from = UR(temp_len - copy_len + 1);
              copy_to   = UR(temp_len - copy_len + 1);
  
              if (UR(4)) {
  
                if (copy_from != copy_to)
                  memmove(out_buf + copy_to, out_buf + copy_from, copy_len);
  
              } else memset(out_buf + copy_to,
                            UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);
  
              break;
  
            }
  ```

- 随机选取一个位置，用随机选取的`token`（用户提供的或自动生成的）替换：

  ```c
          // afl-fuzz.c: 6444
  				case 15: {
  
              /* Overwrite bytes with an extra. */
  
              if (!extras_cnt || (a_extras_cnt && UR(2))) {
  
                /* No user-specified extras or odds in our favor. Let's use an
                   auto-detected one. */
  
                u32 use_extra = UR(a_extras_cnt);
                u32 extra_len = a_extras[use_extra].len;
                u32 insert_at;
  
                if (extra_len > temp_len) break;
  
                insert_at = UR(temp_len - extra_len + 1);
                memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);
  
              } else {
  
                /* No auto extras or odds in our favor. Use the dictionary. */
  
                u32 use_extra = UR(extras_cnt);
                u32 extra_len = extras[use_extra].len;
                u32 insert_at;
  
                if (extra_len > temp_len) break;
  
                insert_at = UR(temp_len - extra_len + 1);
                memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);
  
              }
  
              break;
  
            }
  ```

- 随机选取一个位置，用随机选取的`token`（用户提供的或自动生成的）插入：

  ```c
          // afl-fuzz.c: 6481
  				case 16: {
  
              u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
              u8* new_buf;
  
              /* Insert an extra. Do the same dice-rolling stuff as for the
                 previous case. */
  
              if (!extras_cnt || (a_extras_cnt && UR(2))) {
  
                use_extra = UR(a_extras_cnt);
                extra_len = a_extras[use_extra].len;
  
                if (temp_len + extra_len >= MAX_FILE) break;
  
                new_buf = ck_alloc_nozero(temp_len + extra_len);
  
                /* Head */
                memcpy(new_buf, out_buf, insert_at);
  
                /* Inserted part */
                memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);
  
              } else {
  
                use_extra = UR(extras_cnt);
                extra_len = extras[use_extra].len;
  
                if (temp_len + extra_len >= MAX_FILE) break;
  
                new_buf = ck_alloc_nozero(temp_len + extra_len);
  
                /* Head */
                memcpy(new_buf, out_buf, insert_at);
  
                /* Inserted part */
                memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);
  
              }
  
              /* Tail */
              memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                     temp_len - insert_at);
  
              ck_free(out_buf);
              out_buf   = new_buf;
              temp_len += extra_len;
  
              break;
  
            }
  ```

`AFL`会生成一个随机数，作为变异组合的数量，并根据这个数量，每次从上面那些方式中随机选取一个（可以参考高中数学的有放回摸球），依次作用到文件上。如此这般丧心病狂的变异，原文件就大概率面目全非了，而这么多的随机性，也就成了`fuzzing`过程中的不可控因素，即所谓的“看天吃饭”了。

### splice

历经了如此多的考验，文件的变异也进入到了最后的阶段：`splice`。顾名思义，`splice`是将两个`seed`文件拼接得到新的文件，并对这个新文件继续执行`havoc`变异。

具体地，`AFL`在`seed`文件队列中随机选取一个，与当前的`seed`文件做对比。如果两者差别不大，就再重新随机选一个；如果两者相差比较明显，那么就随机选取一个位置，将两者都分割为头部和尾部。最后，将当前文件的头部与随机文件的尾部拼接起来，就得到了新的文件。在这里，`AFL`还会过滤掉拼接文件未发生变化的情况。

```c
	// afl-fuzz.c: 6575
	/************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      splicing_with++;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

    goto havoc_stage;

  }
```

## 总结

本文第一部分对`afl`如何进行种子的排序以及如何挑选种子进行变异进行了说明，第二部分对`afl`如何对种子进行变异进行了说明。

至此`afl`源码分析系列文章就结束了，经典之所以是经典是各方面都值得学习，从它的插桩、反馈、监控到变异，每部分的代码都值得借鉴和学习。

文章首发于[跳跳糖社区](https://tttang.com/archive/1796/)

## 参考

1. [AFL技术实现分析](https://blog.csdn.net/qq_32464719/article/details/80592902)
2. [Technical “whitepaper” for afl-fuzz](http://lcamtuf.coredump.cx/afl/technical_details.txt)





