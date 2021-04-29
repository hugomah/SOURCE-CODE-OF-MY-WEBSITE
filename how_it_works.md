# handle-hijacking-user-mode-multi-AC-bypass-EAC-BE-tested-
Explanation of a Kernel attack module and how it works to bypass most of the current anti-cheats, might release something one day


Hey there,

I realise that I won't get started on my kernel bypass as long as I still have my little user-mode bypass working, so I decided to release it to motivate me 
Therefore, in this post I release my "ultimate" handle hijacking user-mode bypass. (By ultimate I only mean that it's my last, not that it's the absolute best, far from that)
As usual, I will not simply paste a bunch of code lines, I will walk you through the process I followed to design and build the bypass so you can learn as much as possible from it.
If you are not interested in the step by step explanation you can skip directly to the release section down below.
Intermediate users will certainly benefit the most out of it, since I make use and will present interesting techniques reusable in many other situations.
Advanced users might eventually get a few interesting things, but don't get too hyped and keep in mind that nothing in here is ground-breaking, it is more a usage of various known technique to push stealth closer to the limits of what user-mode only allows.
A few functions might be of interest, you'll be the judge.

## What is this bypass?

This bypass use handle hijacking techniques allowing to read and write a target process memory.
It is designed with external cheats in mind.
The performance is, I think, as good as it can get in a handle hijacking bypass (shared memory, minimalist IPC protocol, direct call to Zw functions, very little overhead).
It is written with stealth as a main objective, with a separate bypass installer binary and a minimalist bypass client class to integrate in your cheat for more safety.
However, we are unfortunately bound to the limits of what user-mode allow us to do with this bypass, and with anti-cheats operating at kernel level, we have a disadvantage, and with this bypass being release publicly they will know what to look for, so be creative and sneaky if you consider using it.

## Compatibility

Tested working on Windows 10 x64 and Windows 7 x64 (the only thing that changes between the 2 versions for these 2 OS is the function to get the handle ID, it needs a little adjustment for Windows 7)
It probably works on Windows 8 x64, but non tested.
I wrote this bypass for x64 OSes only (more specifically, for x64 abused processes), it can work for x86 but you'll have to adapt the shellcode and a few other things, otherwise I suggest that you join us in the x64 master race 
This bypass is compatible for both x86 and x64 games

## Current detection status (14/02/2021)

Detection wise, I have used it actively to cheat on DayZ (BattlEye protected) for the last 2-3 months without problem, however please note that I am releasing it to the public and therefore it will certainly get the anti-cheat attention and they will set up some detection for it I presume.
I will discuss in this article the possible detection vectors with possible mitigation you can and should put into place for more safety.
Following this release, it is likely that the shellcode gets sigged, that is why I organised the generation and assembly of my shellcode with modularity, so you can easily tweak all this (and most likely write better shellcode than I did, I am not very experienced in assembly).
Keep in mind that this is a cat and mouse game, and as any other bypass, this comes without any guarantee.

## Need background?

To understand this article and the source of the bypass you need to be familiar with the Windows API and the handle hijacking technique.
If all that is unclear, start by reading this article: [PoC] Remote memory operations using an existing handle
And if you want to see implementation examples, there are a few on the forum including these ones:
NoBastian - UNIVERSAL IPC/RPC based BattlEye/EAC/FaceIt/ESEA/MRAC bypass
lsass.exe Bypass [Battleye, EAC, Vac....]
And certainly others that I missed.

## Evolution of handle hijacking

My very first bypass was a handle hijacking bypass, I would compile it as a DLL and inject it in a process that had a valid handle and then I would send through an interprocess communication method my order to make the process having the handle do the memory operation and send me the result.
Handle hijacking techniques have attracted the attention of anti-cheats and they deployed security measures.
For example, the Program compatibility assistant service (PcaSvc) normally has a full access handle, but the anti-cheats now modify its permissions to make it unusable for cheating purposes.
For LSASS and CSRSS, it's a bit trickier, it seems that modifying or getting rid of these handles create instability, therefore the same security mechanism cannot safely be applied.
The next solution that AC had is then to monitor processes having a high potential for abuse looking for suspicious activity (e.g. injected DLLs, including trying to detect manually mapped ones, looking for additional executable memory pages, looking for handles that shouldn't be there, etc...)
This is certainly what they did, because my attempt at using my DLL led me to a ban a few months ago.
I investigated which detection vectors I had and I was astonished by how noisy the DLL injection alone was, even with reputable injectors and their so-called "stealth" option enabled.
In addition to this the bypass I wrote made use of named pipes or shared memory, semaphores and other objects that leave traces such as handles in the handle list of the process, so I wanted to re-write that from the ground up.

## Stealth objectives

Okay so before we get started let's make a list of possible detection vectors that we want to avoid in this bypass:
- No extra module loaded: No injection, we will use shellcode execution
- No new thread created: Threads that shouldn't be here can be detected with various ways, they have different start address than genuine ones, analysing their stack can reveal the thread's real purpose, etc...
- No addition executable memory page created: An additional executable memory page is a red flag, we'll therefore use existing executable memory like for code caves.
- No new handles: There shouldn't be a single additional handle to the process, since uncommon handles can be the sign of abuse (e.g. LSASS having a handle to a named pipe is pretty damn suspicious, since it doesn't normally use pipes at all)

Little precisions:
Since this bypass being compatible Windows 7+ I will abuse LSASS, but the same thing is certainly possible with CSRSS on Windows 7 natively, and on Windows 10 if you can get past PPL protection.
Since I targeted mainly BattlEye and EasyAntiCheat this bypass assumes that we can do some operations while the anti-cheat is not running, before starting the game for example.
Actually we will also minimise detection vectors by having 2 separate binaries: One to install the bypass that should be run before any anti-cheat is loaded, and a client that will be integrated in the cheat that is safe to execute at any time.

Okay let's tackle every challenge one by one.


## Getting a synchronised inter-process communication system without handles

First, I wanted to have an inter-process communication that is as fast as possible (I did not sacrifice performance at all in this bypass) and that complies with our stealth objectives stated above.
Both the named pipes and the shared memory generate a new handle (from CreateNamedPipe and CreateFile for named pipes, and from CreateFileMapping and OpenFileMapping for shared memory) and we want to avoid that.
There is a way to get shared memory without keeping a handle, read this extract from MSDN's remark section of CreateFileMapping:


>Mapped views of a file mapping object maintain internal references to the object, and a file mapping object does not close until all references to it are released. Therefore, to fully close a file mapping object, an application must unmap all mapped views of the file mapping object by calling UnmapViewOfFile and close the file mapping object handle by calling CloseHandle. These functions can be called in any order.

In practice, we can leverage this by:
CreateFileMapping in process A. (We get a handle to it)
MapViewOfFile in process A. (The shared memory becomes usable and we get a pointer to it)
OpenFileMapping in process B. (We get a handle to it)
MapViewOfFile in process B. (The shared memory becomes usable and we get a pointer to it)
CloseHandle in both processes. (Since all handles to this shared memory have been closed it is now impossible to connect a new process to it, OpenFileMapping would fail, however, the shared memory is still mapped and usable in process A and B).

Okay, now that we have a way to send info back and forth without handles, let's solve the problem of synchronisation.
Previously I used semaphores for synchronisation, but this doesn't comply - at all - with our stealth objectives: Semaphores require handles and they require to call semaphores functions that LSASS shouldn't be calling at all.
I decided to use a system of spinlock for synchronisation.
For those of you who haven't used spinlocks, this is pretty straightforward, it's a simple infinite loop that checks something over and over again until the desired condition is satisfied to break out of the loop.
In our case, we will use a byte at a specific address in the shared memory to lock and unlock the spinlock.
Our spinlock will read the value of a byte at a specific address in the shared memory and wait for it to be equal to a specific value to break out and continue with the next instructions.




