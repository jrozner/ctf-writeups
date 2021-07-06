# House of Sice

Event: HSCTF 8
Category: 

## Recon

Looking at the binary it appears to be an amd64 linux executable. Checksec shows that all mitigations are enabled. A copy of libc-2.31 is included.

```
house_of_sice: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=fd3ac92ece10bd9f408f84865091ad24cca8ac5d, stripped
```


```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Opening the executable in Binary Ninja it looks pretty straight forward. The application uses a fairly typical menuing system to allow the user to allocate and free chunks of memory from the heap. It also conveniently leaks the address of system for us so that we don't have to worry about obtaining our our libc leak.

Note: The application has been rebased to `0x555555550000` to line up with GDB. Subtract it off to get original addresses.

```
555555554cd0  int32_t main(int32_t arg1, char** arg2, char** arg3) __noreturn
555555554ce1      void* fsbase
555555554ce1      int64_t var_10 = *(fsbase + 0x28)
555555554d00      setvbuf(fp: stdin, buf: nullptr, mode: 2, size: 0)
555555554d1e      setvbuf(fp: stdout, buf: nullptr, mode: 2, size: 0)
555555554d2a      puts(str: "Welcome to the House of Sice!")
555555554d36      puts(str: "We offer the finest deets in the…")
555555554d42      puts(str: "Thanks to our money-back guarant…")
555555554d5d      printf(format: "As per tradition, we shall sice …", system)
555555554d67      while (true)
555555554d67          print_main_menu()
555555554d78          printf(format: "> ")
555555554d7d          int32_t var_2c_1 = 0
555555554d95          void input
555555554d95          read(fd: 0, buf: &input, nbytes: 20)
555555554dab          int32_t num = strtoul(nptr: &input, endptr: nullptr, base: 10)
555555554db6          if (num == 2)
555555554dd6              sell()
555555554de4          else
555555554de4              if (num == 3)
555555554de4                  puts(str: "Come back soon!")
555555554de4                  break
555555554dc3              if (num != 1)
555555554dc3                  break
555555554dca              purchase()
555555554dee      exit(status: 0)
```

The main to options from the menu are to either purchase or sell. Taking a look at the function I've named `purchase` (0x555555554a2a) this is where the main allocation logic occurs.
```
555555554a32      void* fsbase
555555554a32      int64_t rax = *(fsbase + 0x28)
555555554a41      int64_t var_30 = 0
555555554a4e      int32_t allocations = check_allocations()
555555554a5d      puts(str: "What kind of deet do you want?")
555555554a69      puts(str: "1. Delightful Deet")
555555554a75      puts(str: "2. Devious Deet")
555555554a81      puts(str: "3. Flag")
555555554a92      printf(format: "> ")
555555554aa8      void input
555555554aa8      read(fd: 0, buf: &input, nbytes: 0x14)
555555554abe      uint64_t num = strtoul(nptr: &input, endptr: nullptr, base: 0xa)
555555554b62      if (num == 3)
555555554b62          puts(str: "Sorry, we're sold out!")
555555554b07      else if (num == 1)
555555554b07          alloc_pointers[sx.q(allocations)] = malloc(bytes: 8)
555555554b13      else if (num == 2)
555555554b13          if (created_devious != 0)
555555554b54              puts(str: "Out of stock!")
555555554b3d          else
555555554b3d              alloc_pointers[sx.q(allocations)] = calloc(n: 8, elem_size: 1)
555555554b41              created_devious = 1
555555554b73      if (num == 1 || num == 2)
555555554b73          puts(str: "Here's your deet!")
555555554b7f          puts(str: "As always, we follow a pay-what-…")
555555554b8b          puts(str: "How much are you willing to pay …")
555555554b9c          printf(format: "> ")
555555554bb2          read(fd: 0, buf: &input, nbytes: 20)
555555554bed          *alloc_pointers[sx.q(allocations)] = strtoul(nptr: &input, endptr: nullptr, base: 0xa)
555555554bf7          puts(str: "Done!")
555555554c00      int64_t rax_17 = rax ^ *(fsbase + 0x28)
555555554c11      if (rax_17 == 0)
555555554c11          return rax_17
555555554c0b      __stack_chk_fail()
555555554c0b      noreturn
```

One of the first things this function does it call `check_allocations` (0x5555555549aa) which checks the number of allocations that have been made. We can see that `purchase` stores pointers to each of the allocated chunks into an array at 0x555555554b07 or 0x555555554b3d depending on the type of allocation used. `check_allocations` traverses this array looking for NULL, which signifies that it's at the end of the allocation, or until it has iterated over 16 times. If it hit's 17 the program exits with failure. This ensure that we're only ever able to allocate at most 16 chunks. There's no obvious ways to attack this so we're going to need to perform some type of exploit using only 16 allocations.

If we're below the max number of allocations, the function prompts to select one of two options, purchasing a delightful or devious deet. The primary difference between these two options is that a delightful deet will use `malloc` and a devious deet will use `calloc`. It's worth noting that we're only allowed to purchase one devious deet but can purchase as many delightful deets as allocations we're allowed. In both cases we have no control over the size of the data but we do have control over the data itself. The size in both cases is exactly 8 bytes. Given the size, it means that any frees we perform are going to end up getting placed in the tcache bin or fastbin suggesting that we're likely going to perform some sort of fastbin dupe or tcache dupe.

Checking out the `sell` function (0x555555554c12), which calls `free`, we can see that there are no double free protections in place confirming that a double free is going to be possible and will be the likely solution. However, given that we're using glibc-2.31 there are protections in place from glibc that will detect a double free in the tcache or the fastbin.

```
555555554c1a      void* fsbase
555555554c1a      int64_t rax = *(fsbase + 0x28)
555555554c29      int32_t var_2c = 0
555555554c37      puts(str: "Which deet do you want to sell?")
555555554c48      printf(format: "> ")
555555554c5e      void input
555555554c5e      read(fd: 0, buf: &input, nbytes: 20)
555555554c74      int32_t num = strtoul(nptr: &input, endptr: nullptr, base: 10)
555555554c7c      if (num u> 15)
555555554cb5          puts(str: "Invalid index!")
555555554c9b      else
555555554c9b          free(mem: alloc_pointers[zx.q(num)])
555555554ca7          puts(str: "Done!")
555555554cbe      int64_t rax_6 = rax ^ *(fsbase + 0x28)
555555554ccf      if (rax_6 == 0)
555555554ccf          return rax_6
555555554cc9      __stack_chk_fail()
555555554cc9      noreturn
```

The full exploit is available in [x.py](x.py) but we'll walk through step by step how the exploit works below.

## The Exploit

The general strategy we're going to attempt to use is to leverage the double free into an arbitrary write and then overwrite one of the malloc hooks (eg. `__malloc_hook`, `__free_hook`) in order to gain code execution and drop a shell.

### Step 1: Leaking libc

This is more or less done for us since the program leaks the address for `system` when we start it. We're provided the glibc used by the server so we just need to subtract the offset of the symbol for `system` from our libc from the address of `system` that the program leaked to us. The relevant code is on lines 78-80 of x.py.

### Step 2: Obtaining a write primitive

#### Background

It took a number of attempts to get a working solution for this step because I kept coming up against the maximum number of allocations allowed. The first attempt I was able to conceptualize a full exploit chain that would land but required 20 allocations, 4 more than allowed. I eventually saw some optimizations that would allow it to be done in 18 allocations, still two more than permitted. Eventually I identified a strategy to do it within 16. All three of these strategies leveraged a double free but required slight variations of the ordering of operations and the types of allocations that were used. I'm only going to cover the final attempt that was used in the final exploit here.

A double free can give us a write primitive that will allow us to write whatever data we're able to write to the chunk wherever we want; in this case virtually anything within 8 bytes. We do this by getting a chunk freed twice into some combination of the tcache and/or fastbins such that we can re-allocate it twice. We take advantage of the fact that both the tcache bin and fast bin store the chunks as a singly linked list with the fd pointer to the next chunk stored in the writable area of the chunk that has been freed/allocated.

Ignoring mitigations in place that would prevent the below scenario we can imagine this two chunks in the tcache bin:

```
tcache bin -> chunk 1 -> chunk 1
```

The tcache bin holds the pointer for chunk 1 and the fd pointer in chunk 1 points back to itself because we have freed it twice. If we allocate a chunk that the tcache bin can satisfy we'll be able to pull the first copy out of the tcache bin and overwrite the fd pointer that is in the second copy to something we control. The resulting list for the tcache now becomes:

```
tcache bin -> chunk 1 -> ???
```

By allocating another chunk that the tcache bin can serve we get to:

```
tcache bin -> ???
```

Then one more allocation gives us our write to anywhere we want.

However, actually leveraging this is a bit more complicated due to mitigations that exist within glibc. When freeing a chunk that will end up in the tcache bin the entire bin (up to seven chunks) will be traversed to check whether or not the chunk is already present. If it is, free will abort. This can be defeated by duplicating the chunk into the fastbin which has slightly different behavior (the next chunk can't be a duplicate) or split between the tcache bin and the fastbin. Without the limited number of allocations the fastbin approach would work but in this case it's necessary to split between the bins in order to keep the number of allocations within the limit.

The other trick necessary to leverage here is that calloc in glibc 2.31 will never serve from the tcache bin but instead will start with the fastbins. This is just the behavior that exists and something that we can leverage to get the number of allocations down to our limited number.

#### Putting it all together

Now that we have the background we can put this all together into practice to setup our write primitive. This is the documented code from x.py:

We start by allocating seven chunks (from the top chunk) that we will use shortly to fill up the tcache bin.

```python
for i in range(7):
    chunks.append(delightful(20))
```

We then allocate one additional chunk (from the top chunk) that we're going to use to later put into the fastbin once we've filled the tcache. This is the chunk that we're going to double free.
```python
dup = delightful(20)
```

We then free each of our original seven chunks filling up the tcache so any following frees will not be able to get placed into the tcache bin.
```python
for num in range(7):
    sell(chunks[num])
```

With the fastbin free we can free our eighth chunk and get it placed into the fastbin.

```python
sell(dup)
```

We're going to allocate one more chunk, using `malloc`, which will be served by the tcache bin and opening a spot so that we can free another chunk into there.
```python
delightful(20)
```

We then free the chunk that we originally freed into the fastbin again, this time though it gets placed into the tcache bin defeating the double free protection of both the tcache bin and the fastbin.
```python
sell(dup)
```

At this point we've created the double free condition, where chunk 8 has been freed twice, and our heap looks like the following:

```
tcache bin -> chunk 8 -> chunk 6 -> chunk 5 -> chunk 4 -> chunk 3 -> chunk 2 -> chunk 1
fastbin -> chunk 8
```

Next we can setup our write to hijack control flow.

### Step 3: Gaining control flow

Checking glibc with checksec it was compiled with partial RELO enabled.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

This gives us some opportunity to overwrite function pointers as a method to gain control flow. The most straight forward approach seemed to be to use either `__malloc_hook` or `__free_hook`. At this point we've used 9 of our 16 allocations and we're still going to need at least three more to complete an overwrite. The `__free_hook` seemed like the better option, simply to avoid running out of allocations so I went with it. Normally with only `malloc` available to us, this would require eight allocations, one more than the amount we're allowed, due to the fact that we'd need to allocate the seven out of the tcache bin before we could allocate the one from the fastbin that would trigger the write that we setup when we allocate chunk 8 the first time. Due to the fact that we get a single use of `calloc` we can overcome this.

Using `calloc` we can allocate directly out of the fastbin and use this to overwrite the fd pointer of chunk with the address of the `__free_hook`
```python
devious(libc.sym.__free_hook)
```

We've now emptied out the fastbin and rewritten the tcache bin setting up our write.

```
tcache bin -> chunk 8 -> __free_hook
```

Performing one more allocation, using `malloc`, we'll take the duplicate copy of chunk 8 out of the tcache leaving the tcache pointing to the __free_hook as the next chunk. You can ignore the value used here for the allocation but it will become important in the next section.
```python
shchunk = delightful(u64(b'/bin/sh\0'))
```

Finally one more allocation will allocate a chunk starting at `__free_hook` allowing us to hijack control of the application by simply getting it to call `free`. Utilizing the `__free_hook` we can get it to call into anywhere we specify.
```python
delightful(libc.sym.system)
```

### Step 4: Dropping the shell

With control obtained the last step was identifying useful values for what we could call into. The obvious answer is to use a one gadget though after attempting it, none of the constraints could be met and an alternative approach needed to be used. `system` was the other straight forward option. `free` takes one argument, the chunk we want to free, and `system` takes one argument, the application you want to run. The address of `system` became the value to overwrite into the `__free_hook` and the only trick was finding a way to pass a path to `/bin/sh` to it. While glibc does provide the string `/bin/sh` in the library, that isn't a straight forward path to passing it to free in this application because we're only able to provide an index of the chunk, not the actual address. Luckily, we're able to write arbitrary values to the chunks we allocate, hence writing the value `/bin/sh` into the chunk before we trigger the write to `__free_hook` above.

Using this we have a pointer to the string `/bin/sh` and can pass that to `free` which will trigger the call to `system` before the chunk is freed and execute the shell.
