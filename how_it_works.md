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

##What is this bypass?##
This bypass use handle hijacking techniques allowing to read and write a target process memory.
It is designed with external cheats in mind.
The performance is, I think, as good as it can get in a handle hijacking bypass (shared memory, minimalist IPC protocol, direct call to Zw functions, very little overhead).
It is written with stealth as a main objective, with a separate bypass installer binary and a minimalist bypass client class to integrate in your cheat for more safety.
However, we are unfortunately bound to the limits of what user-mode allow us to do with this bypass, and with anti-cheats operating at kernel level, we have a disadvantage, and with this bypass being release publicly they will know what to look for, so be creative and sneaky if you consider using it.

##Compatibility##
Tested working on Windows 10 x64 and Windows 7 x64 (the only thing that changes between the 2 versions for these 2 OS is the function to get the handle ID, it needs a little adjustment for Windows 7)
It probably works on Windows 8 x64, but non tested.
I wrote this bypass for x64 OSes only (more specifically, for x64 abused processes), it can work for x86 but you'll have to adapt the shellcode and a few other things, otherwise I suggest that you join us in the x64 master race 
This bypass is compatible for both x86 and x64 games

Current detection status (14/02/2021)
Detection wise, I have used it actively to cheat on DayZ (BattlEye protected) for the last 2-3 months without problem, however please note that I am releasing it to the public and therefore it will certainly get the anti-cheat attention and they will set up some detection for it I presume.
I will discuss in this article the possible detection vectors with possible mitigation you can and should put into place for more safety.
Following this release, it is likely that the shellcode gets sigged, that is why I organised the generation and assembly of my shellcode with modularity, so you can easily tweak all this (and most likely write better shellcode than I did, I am not very experienced in assembly).
Keep in mind that this is a cat and mouse game, and as any other bypass, this comes without any guarantee.
Need background?
To understand this article and the source of the bypass you need to be familiar with the Windows API and the handle hijacking technique.
If all that is unclear, start by reading this article: [PoC] Remote memory operations using an existing handle
And if you want to see implementation examples, there are a few on the forum including these ones:
NoBastian - UNIVERSAL IPC/RPC based BattlEye/EAC/FaceIt/ESEA/MRAC bypass
lsass.exe Bypass [Battleye, EAC, Vac....]
And certainly others that I missed.

Evolution of handle hijacking
My very first bypass was a handle hijacking bypass, I would compile it as a DLL and inject it in a process that had a valid handle and then I would send through an interprocess communication method my order to make the process having the handle do the memory operation and send me the result.
Handle hijacking techniques have attracted the attention of anti-cheats and they deployed security measures.
For example, the Program compatibility assistant service (PcaSvc) normally has a full access handle, but the anti-cheats now modify its permissions to make it unusable for cheating purposes.
For LSASS and CSRSS, it's a bit trickier, it seems that modifying or getting rid of these handles create instability, therefore the same security mechanism cannot safely be applied.
The next solution that AC had is then to monitor processes having a high potential for abuse looking for suspicious activity (e.g. injected DLLs, including trying to detect manually mapped ones, looking for additional executable memory pages, looking for handles that shouldn't be there, etc...)
This is certainly what they did, because my attempt at using my DLL led me to a ban a few months ago.
I investigated which detection vectors I had and I was astonished by how noisy the DLL injection alone was, even with reputable injectors and their so-called "stealth" option enabled.
In addition to this the bypass I wrote made use of named pipes or shared memory, semaphores and other objects that leave traces such as handles in the handle list of the process, so I wanted to re-write that from the ground up.

Stealth objectives
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

Getting a synchronised inter-process communication system without handles

First, I wanted to have an inter-process communication that is as fast as possible (I did not sacrifice performance at all in this bypass) and that complies with our stealth objectives stated above.
Both the named pipes and the shared memory generate a new handle (from CreateNamedPipe and CreateFile for named pipes, and from CreateFileMapping and OpenFileMapping for shared memory) and we want to avoid that.
There is a way to get shared memory without keeping a handle, read this extract from MSDN's remark section of CreateFileMapping:

Quote:
Mapped views of a file mapping object maintain internal references to the object, and a file mapping object does not close until all references to it are released. Therefore, to fully close a file mapping object, an application must unmap all mapped views of the file mapping object by calling UnmapViewOfFile and close the file mapping object handle by calling CloseHandle. These functions can be called in any order.

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

This is my spinlock function prototype:
![ouia ca arrive](https://user-images.githubusercontent.com/65464469/116490425-a5325780-a897-11eb-8c1e-70960a008ab1.jpg)

And this is its assembly code:
![ghghg](https://user-images.githubusercontent.com/65464469/116490811-9dbf7e00-a898-11eb-9308-ba5b55a3c9d0.jpg)

If you are not familiar with assembly or struggle to understand, imagine it this way in pseudo code:
![jgjgjjg](https://user-images.githubusercontent.com/65464469/116490861-c2b3f100-a898-11eb-9434-b6473adac5b3.jpg)

Where 0x12345678 is the address of the byte that locks and unlocks the spinlock in shared memory and 1 is the value the byte at that address should have to break out of the loop.

Okay, now we have a synchronised IPC system, however, to connect the LSASS and our cheat we'll need LSASS to map the handle-free shared memory and that means executing instructions from it.
DLL injection being rejected for stealth reasons, this leaves us with shellcode execution.
To execute shellcode, we need to first write our shellcode in an executable section of memory.
As we have for objective to avoid creating new executable memory, we will have to use what's already there.

Finding usable executable memory
Memory is allocated by page (a fixed size of memory that is generally 4096 bytes on modern Windows OSes), which explains why you end up with a 4kB page even if you call VirtualAlloc requesting only 100 bytes.
The consequence of that is that there is often enough unused executable memory at the end of an executable page to allow us to execute some shellcode.
The following picture shows you the readable and executable (RX) memory page in which is the image of lsass.exe in its virtual memory as well as the unused bytes after lsass.exe's image at the end of the page.

![gg](https://user-images.githubusercontent.com/65464469/116490923-ec6d1800-a898-11eb-9218-6565d5756268.png)

In this example we are left with 1488 usable executable bytes, which is much more than enough.
You can also use the unused bytes in the executable memory page of loaded modules, and more generally any executable memory that will not be used/executed, even if it is non-zeroed.
If you want to experiment a little and find unused executable memory yourself manually, you can do that simply with Process Hacker: Double click the process you intent to abuse, go in "Memory" tab, find executable sections (there should be an "X" in the column protection), expand the section of memory if there are subsections then double click the executable memory section which will open the memory explorer with which you can go at the bottom, the end of the table and see directly the unused bytes equal to zero.
Please note that having custom shellcode that shouldn't be there is a detection vector. Therefore further hiding and obfuscating your shellcode is advised.
Instead of using the unused bytes at the end of the executable pages, we could can also make the choice to overwrite some code that won't be called.
For example, let's admit that LSASS (and all its modules loaded) do not make use of a specific function, let's say CreateNamedPipe (from kernel32.dll).
We could then freely overwrite the bytes of this function in the memory page of LSASS's kernel32.dll without causing disturbance.
However, note that we only trade a detection vector for another, we don't write additional shellcode at the end of the page, but we modify kernel32.dll's bytes and therefore a comparative check of LSASS's kernel32.dll against the version on disk (or loaded in another process) would fail and reveal the modification.
With this second solution however, we could split our shellcode in separate few instructions with absolute jumps, scattering our shellcode in multiple places, which would prevent having one big portion of shellcode directly siggable.
In this bypass release I simply make use of unused memory at the end of the page.

We can automate the search for available unused executable memory with VirtualQueryEx to list the memory pages with their properties and ReadProcessMemory (or NtReadVirtualMemory) to find the start address of unused bytes and the size available.
There's not much else to say, the function is quite self explanatory, you can check it out in the source it's FindExecutableMemory().

Okay, now that we can get usable executable memory we can execute instructions to start setting up the bypass in LSASS.

Connecting LSASS to our IPC system
Our objective is now to map a shared memory section in LSASS.
To map a memory section, a process has to call CreateFileMapping then MapViewOfFile, and the other has to call OpenFileMapping then MapViewOfFile, then both should call CloseHandle to get rid of the handle.
In our case it does matter who creates the file mapping and who joins.
Since LSASS is a system process with very specific parameters like running with higher privileges, being in session 0, etc... if we create the file mapping from LSASS we won't be able to join it from our installer or our cheat without also creating a DACL and other tedious tasks of the kind (and remember: we would have to do all that crap in shellcode!)
So instead, our installer running with lower privileges will create the file mapping and LSASS will join.
In our installer we therefore simply CreateFileMapping, then MapViewOfFile, and now, time to shellcode to make LSASS join.

In summary, we make LSASS execute OpenFileMapping storing the returned handle in a register, the file mapping name will be included at the end of the shellcode in a small buffer, we map the shared memory section with MapViewOfFile and we write the returned pointer to the shared memory in LSASS's virtual address space at the beginning of the shared memory (we will need the address of the shared memory in LSASS's virtual address space in further shellcode) and finally we get rid of the unwanted handle with CloseHandle.
Little heads up: My shellcode ends by a small infinite loop (JMP REL8 -2, opcodes: 0xEB, 0xFE); this minimalist infinite loop has the specificity to maintain the instruction pointer at a fixed address (the address of this infinite loop). I use this to acknowledge completion of the thread hijacking execution. Some people set a byte in memory to a value at a specific address and do a loop with ReadProcessMemory in the hijacking process, which require in addition to the thread handle a process handle to read the memory. Instead of that my method allow to acknowledge completion of execution with nothing more than what is needed to hijack the thread in the first place: Only a thread handle with GetContext permission. In summary we suspend the thread, GetThreadContext to save what it was doing, SetThreadContext with the instruction pointer at the beginning our our shellcode, ResumeThread, then infinite loop doing GetThreadContext until the instruction pointer is equal to the address where it should be after complete execution: the infinite loop at the end.
Microsoft warns us in GetThreadContext documentation:

Quote:
You cannot get a valid context for a running thread. Use the SuspendThread function to suspend the thread before calling GetThreadContext.

t's not really that you cannot, it is simply that if you do you'll have garbage data since the registers will change while you are trying to retrieve them.
However, since we are only interested in the instruction pointer and we know that with our infinite loop its value will not be changing, we can just give the finger to the docs and GetThreadContext our running thread.

Keeping the bypass connectable
Now there's a little problem with the way we get rid of the shared memory file mapping handle.
You remember that we can map the shared memory in both processes, close the handles to the file mapping and still have the shared memory usable but then impossible to join from another process since all handles have been closed?
Well, at that point we are in a situation where our installer has mapped and has a handle to the shared memory, and LSASS had mapped it and closed the handle.
This means the handle in our installer is the only one remaining, and if we close it, or if we terminate its process, there won't be any more handles and the shared memory will become impossible to join from other processes, including our bypass client integrated to our cheat.
I found a simple way around, that in addition solves something that bothered me: I wanted to be able to restart my cheat several times without problem (because DayZ crashes a lot), and if we close all handles, I would have had to code some functions to detect if the bypass is already installed, uninstall it, reinstall it, etc... in short it was messy.
Instead of that we are simply going to DuplicateHandle into another process, just to keep one handle somewhere in the system to keep the shared memory joinable, it will be our "Gate Keeper".
This is in accordance with our stealth objectives: Neither LSASS or our bypass client in the cheat won't have handles, they'll only have the memory mapped, whereas our gate keeper will have only the handle without having the memory mapped.
I decided to keep the handle in explorer.exe, since it's not a process that has potential for abuse and that it already has handle of the same type.
You can check out the code in the source, don't be shocked by the crap with the wstring at the beginning it's just a temporary shitty way to obfuscate strings in the binary.

That's pretty much it, now we have a connectable shared memory that LSASS has mapped without having a handle.
With all this we can now write the actual bypass code.

Writing the bypass and our minimalist IPC protocol
The objective is now to be able in our cheat process to send orders such as:
"Hey LSASS, read/write X bytes at that memory address using your handle ID # (and send me the results for reads - and here is what you should write for writes)"
To do this we will use some shellcode and our shared section of memory.
I created a small structure that we will write at the end of the shared memory page to send our order and have it executed.

code:
![opeopeoe](https://user-images.githubusercontent.com/65464469/116491043-3950ee80-a899-11eb-9379-1611614843b1.jpg)

In short:
exec is what lock/unlock our spinlocks and synchronises the 2 processes. LSASS will wait for it to be equal to 0 to unlock, then it will load our parameters from this struct placed in the shared memory and use these parameters to execute the read/write instruction.
order define if we want to read or write.
status is supposed to be the returned NTSTATUS of NtReadVirtualMemory or NtWriteVirtualMemory but I decided not to retrieve the return after thinking about it, I don't need it and it does unnecessary unwanted operations.
hProcess is the HANDLE ID that LSASS should use for the request
lpBaseAddress is the address to read or write in the target process. If we read we will write the bytes read at the beginning of the shared memory section, and if we write, the bytes to write will be previously written at the beginning of the shared memory section.
nSize is the size to read or write
nBytesReadOrWritten is a pointer to SIZE_T that should have received the number of bytes read/written from the function call, but I decided not to use it either.

Since this control struct is placed at a fixed address (at the very end of the shared memory), we can include in our shellcode a way to retrieve the parameters for the read and write calls from fixed addresses in the shared memory.
Our shellcode will start by the spinlock waiting for the least significant bit of exec to be equal to 0 to trigger execution.
NtReadVirtualMemory and NtWriteVirtualMemory (like ReadProcessMemory and WriteProcessMemory) both have almost identical parameters, therefore we'll then get the parameters in our shellcode and we will simply jump to the instructions to either fire up the read or write function.
Finally, the shellcode will reset the least significant byte of exec to 1 letting know the cheat process that the execution has completed (therefore unlocking the cheat's spinlock for synchronisation) before jumping back at the beginning, back to the initial spinlock.
To do the jumps correctly, we need to know the shared memory address in LSASS's virtual address space, that's okay since we pushed that address into the shared memory in the connection shellcode.
Little heads up: In this shellcode I don't actually call the usermode functions (RPM, WPM, NtRVM, NtWVM), instead I directly syscall to the Zw functions as I describe in my other thread: Calling directly ZwReadVirtualMemory (e.g. to avoid user-mode hooks based detection)
You can check out all this in the source, in the Start() function.

With that system in place, we can now send our orders by overwriting the SJORDER struct placed at the end of the shared memory and when written, we overwrite the least significant byte of exec to 0 to trigger execution in LSASS.
However there is one subtlety in this code: As you can see it is executed with my function ExecWithThreadHiJacking() without any parameters, which means a permanent thread hijacking, not waiting for completion, and not sending back the thread where it was initially.
This is not doable with any thread and can lead to system instability/crash if not done correctly.

Finding a permanently hijackable thread in LSASS
Since we refuse for stealth reason to create an additional thread with CreateRemoteThread (or with CreateThread executed with shellcode and thread hijacking), we are going to take a thread for our own use, permanently.
That is tricky, especially in a system critical process such as LSASS, if you pick the wrong thread you can either create instability or crash (BSOD on Windows 7, and "Your system has encountered a problem and will restart in 1 minute" on Windows 10)
Fortunately, a very basic test can show us what thread we can and cannot use: Suspending one thread at a time in LSASS and see what's happening.
Here's the list of the handles my LSASS had when I was writing this article:
![hyhy](https://user-images.githubusercontent.com/65464469/116491066-4a016480-a899-11eb-8fe5-da8c62b9b716.png)

In addition to these threads, you might have a thread with a start address in crypt32.dll
You will most likely not have the thread starting in samsrv.dll, this thread is only present in LSASS for about a minute after you reboot or login your user, I manually suspended it, that's why it's grey in the picture.

In short:
- All threads starting in ntdll.dll are system critical. You can suspend them without insta crashing, but after a few minutes, things are going to go haywire with unresponsive windows and other oddities until your system because almost unusable.
- The thread starting in lsasrv.dll is system critical
- The thread starting in lsass.exe would certainly be usable, unfortunately this thread is dormant (waiting for single object) and never wakes up, if you attempt thread hijacking with it you'll just wait for execution forever.
- The thread starting in msvcrt.dll is not system critical and can be permanently hijacked safely without noticeable consequences. Note that this thread is goes in waiting state and gets restarted periodically, therefore using it for thread hijacking mean that you sometime have to wait a little for the execution to start. Doing various things in the system, like starting apps seems to trigger sometimes its awaking. It can take between a few seconds and 5 minutes in the worst cases.
- The thread starting in crypt32.dll is also non critical, periodically waiting, and permanently hijackable without noticeable consequences.
- The thread starting in samsrv.dll (only present during about a minute after reboot or user login) is not critical, can be safely permanently hijacked, and is readily usable. (It doesn't enter any long waiting state)

So in our installer we'll check is samsrv.dll's thread is there to be used, and if it's not we'll just use either msvcrt.dll's or crypt32.dll's.
Time to code and automate all that now.
We're going to need:
- A function that gets the thread IDs of a process ID
- A function that gets the start address of a thread
- A function that gets the name and base address of loaded module of a process ID
- A function that wraps all that to give us the module in which a specific thread ID has started
You can check out these functions in the source, I hope you'll also find them useful for future projects of yours.

That's pretty much it, with this we can now execute our shellcode that waits for orders send through the shared memory, the installer can terminate, the bypass is installed.
I also write at the end of the shared memory (before the SJORDER control struct) a small SJCONFIG struct with some information that I check when the client connect to check for configuration mismatches, but that's not interesting or really needed anyway, you can check out that in the source.

Writing the bypass client to be integrated in the cheats
The client is very straightforward, with the description of the installer you probably have an idea of its general organisation.
We start by connecting the shared memory with OpenFileMapping, map the shared memory with MapViewOfFile, then close the handle for extra safety with CloseHandle.
We then have a set of functions to read and write that create a SJORDER struct, write it to shared memory, then overwrite the exec least significant byte to trigger execution and get the result.
In terms of stealth this bypass client is rather good, it doesn't import much functions and none of them is hack-related.
Having the installer and the client separated allow us to integrate in our cheat the bare minimum.

I also included:
- A function to retrieve LSASS's handle to the target game
- A set of functions to do your reads and writes
- A NOBYPASS define that you can set to make this bypass use the classic OpenProcess and NtRVM/NtWVM so you can switch your cheat from bypassed to non bypassed version easily
- 2 functions to dereference pointers and pointer chains in a vector
- A benchmark system so you can make the bypass count how many reads and writes it does per cycle and per second
I let you check that out in the source.

Release

Bypass installer (standalone binary) and also downloadable when i'll post it on realease tab.

SilentJack2-Setup.hpp:

code:
[SilentJack2-setupe.txt](https://github.com/whitecatOwO/handle-hijacking-user-mode-multi-AC-bypass-EAC-BE-tested-/files/6395757/SilentJack2-setupe.txt)

main.cpp:

code:
[main.cpp.txt](https://github.com/whitecatOwO/handle-hijacking-user-mode-multi-AC-bypass-EAC-BE-tested-/files/6395760/main.cpp.txt)

Usage:

Only execute when no anti-cheat is active. The installer does operations that AC won't like, therefore I STRONGLY advise you to add at the beginning of the Setup() function some additional checks to make sure the AC you are trying to bypass is not active (I left a comment telling you where to write that code). Without this additional security you can essentially pwn your sorry face by executing the bypass installer at the wrong time.
For instant setup, execute within 1 minute after reboot (the bypass will permanently hijack a thread that is active but only present for a short period, otherwise you will have to wait for one of the dormant threads to wake up, which can take a few minutes sometimes)
You only need to execute the installer once per reboot. If you execute it more than once, no sweat, the installer will detect that it's already installed and just exit successfully.
To auto install the bypass at every reboot, you can find a way to execute it automatically (I wouldn't advise that though)
I recommend deleting permanently the installer after each installation. If you want to keep a binary ready to run, consider keeping it on a USB stick that you unplug after installation, keeping the risky installer binary out of touch.

Bypass client (C++ class, use in your cheats)

SilentJack2-Client.hpp:
[SilentJack2-Client.hpp.txt](https://github.com/whitecatOwO/handle-hijacking-user-mode-multi-AC-bypass-EAC-BE-tested-/files/6395764/SilentJack2-Client.hpp.txt)


GetHandle.hpp:
[GetHandle.hpp.txt](https://github.com/whitecatOwO/handle-hijacking-user-mode-multi-AC-bypass-EAC-BE-tested-/files/6395768/GetHandle.hpp.txt)

spinlock.asm:
To add and include an assembly file for compiling, right click your project in Visual Studio, then go on Build Dependencies and click Build Customizations. Tick the checkbox "masm(.targets, .props) and click OK. Right click Source Files in your project, Add, New Item. Select C++ File and name it "spinlock.asm" and click Add. Right click spinlock.asm in the Source Files, click Properties. Set "Excluded from Build" to No, and set "Item Type" to "Microsoft Macro Assembler

Code:
[spinlock.asm.txt](https://github.com/whitecatOwO/handle-hijacking-user-mode-multi-AC-bypass-EAC-BE-tested-/files/6395772/spinlock.asm.txt)


Usage:

Integrate it in your cheat to do the read and write operations.
Initialise the bypass with the Init and GetHandle functions.
The following code is an example that connects the installed bypass, gets a handle to the game process "DayZ_x64.exe" then reads the value of the pointer to world:

example with DAYZ:
//
#include "SilentJack2-Client.hpp"
#include <iostream>
 
int main() {
	SilentJack sj;
	sj.Init();
	sj.GetHandle(L"DayZ_x64.exe");
 
	DWORD64 world = 0;
	sj.qRVM(0x121C5F0, &world, sizeof(DWORD64));
 
	cout << "World @ 0x" << hex << world << endl;
 
	system("pause");
    return EXIT_SUCCESS;
}
//



