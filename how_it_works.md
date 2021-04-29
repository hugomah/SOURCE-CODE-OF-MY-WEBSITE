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

This is my spinlock function prototype:
```C++
extern "C" void SpinLockByte(volatile void* byteAddr, volatile BYTE valueExit);
```
And this is its assembly code:
```C++
.code
 
SpinLockByte proc
SpinLock:
	pause ; tells the CPU we're spinning
	cmp dl, [rcx]
	jnz SpinLock
	ret
SpinLockByte endp
 
end
```

If you are not familiar with assembly or struggle to understand, imagine it this way in pseudo code:
```C++
while (true)
		if (*(BYTE*)0x12345678 == 1)
			break;
```

Where 0x12345678 is the address of the byte that locks and unlocks the spinlock in shared memory and 1 is the value the byte at that address should have to break out of the loop.

Okay, now we have a synchronised IPC system, however, to connect the LSASS and our cheat we'll need LSASS to map the handle-free shared memory and that means executing instructions from it.
DLL injection being rejected for stealth reasons, this leaves us with shellcode execution.
To execute shellcode, we need to first write our shellcode in an executable section of memory.
As we have for objective to avoid creating new executable memory, we will have to use what's already there.

## Finding usable executable memory

Memory is allocated by page (a fixed size of memory that is generally 4096 bytes on modern Windows OSes), which explains why you end up with a 4kB page even if you call VirtualAlloc requesting only 100 bytes.
The consequence of that is that there is often enough unused executable memory at the end of an executable page to allow us to execute some shellcode.
The following picture shows you the readable and executable (RX) memory page in which is the image of lsass.exe in its virtual memory as well as the unused bytes after lsass.exe's image at the end of the page.

![gg](https://user-images.githubusercontent.com/65464469/116492790-761ee480-a89d-11eb-9c8d-5dae02e421c7.png)

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

## Connecting LSASS to our IPC system
Our objective is now to map a shared memory section in LSASS.
To map a memory section, a process has to call CreateFileMapping then MapViewOfFile, and the other has to call OpenFileMapping then MapViewOfFile, then both should call CloseHandle to get rid of the handle.
In our case it does matter who creates the file mapping and who joins.
Since LSASS is a system process with very specific parameters like running with higher privileges, being in session 0, etc... if we create the file mapping from LSASS we won't be able to join it from our installer or our cheat without also creating a DACL and other tedious tasks of the kind (and remember: we would have to do all that crap in shellcode!)
So instead, our installer running with lower privileges will create the file mapping and LSASS will join.
In our installer we therefore simply CreateFileMapping, then MapViewOfFile, and now, time to shellcode to make LSASS join.

In summary, we make LSASS execute OpenFileMapping storing the returned handle in a register, the file mapping name will be included at the end of the shellcode in a small buffer, we map the shared memory section with MapViewOfFile and we write the returned pointer to the shared memory in LSASS's virtual address space at the beginning of the shared memory (we will need the address of the shared memory in LSASS's virtual address space in further shellcode) and finally we get rid of the unwanted handle with CloseHandle.
Little heads up: My shellcode ends by a small infinite loop (JMP REL8 -2, opcodes: 0xEB, 0xFE); this minimalist infinite loop has the specificity to maintain the instruction pointer at a fixed address (the address of this infinite loop). I use this to acknowledge completion of the thread hijacking execution. Some people set a byte in memory to a value at a specific address and do a loop with ReadProcessMemory in the hijacking process, which require in addition to the thread handle a process handle to read the memory. Instead of that my method allow to acknowledge completion of execution with nothing more than what is needed to hijack the thread in the first place: Only a thread handle with GetContext permission. In summary we suspend the thread, GetThreadContext to save what it was doing, SetThreadContext with the instruction pointer at the beginning our our shellcode, ResumeThread, then infinite loop doing GetThreadContext until the instruction pointer is equal to the address where it should be after complete execution: the infinite loop at the end.
Microsoft warns us in GetThreadContext documentation:

>You cannot get a valid context for a running thread. Use the SuspendThread function to suspend the thread before calling GetThreadContext.>

It's not really that you cannot, it is simply that if you do you'll have garbage data since the registers will change while you are trying to retrieve them.
However, since we are only interested in the instruction pointer and we know that with our infinite loop its value will not be changing, we can just give the finger to the docs and GetThreadContext our running thread.

## Keeping the bypass connectable

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

## Writing the bypass and our minimalist IPC protocol

The objective is now to be able in our cheat process to send orders such as:
"Hey LSASS, read/write X bytes at that memory address using your handle ID # (and send me the results for reads - and here is what you should write for writes)"
To do this we will use some shellcode and our shared section of memory.
I created a small structure that we will write at the end of the shared memory page to send our order and have it executed.

Code:
```C++
struct SJORDER {
	DWORD64 exec = 1; // Least significant byte used to release the spinlock, 0 release spinlock in abused process overwritten to 1 after execution
	DWORD order = 0; // 0: Read, 1: Write
	NTSTATUS status = 0xFFFFFFFF; // TODO: Remove, finally I don't want to get the return
	HANDLE hProcess = NULL;
	DWORD64 lpBaseAddress = NULL;
	SIZE_T nSize = 0;
	SIZE_T* nBytesReadOrWritten = 0; // TODO: Remove, finally I don't want the number of bytes read/written
}; // Important: Must be 8 bytes aligned, otherwise garbage data is added in the structure
```

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

## Finding a permanently hijackable thread in LSASS

Since we refuse for stealth reason to create an additional thread with CreateRemoteThread (or with CreateThread executed with shellcode and thread hijacking), we are going to take a thread for our own use, permanently.
That is tricky, especially in a system critical process such as LSASS, if you pick the wrong thread you can either create instability or crash (BSOD on Windows 7, and "Your system has encountered a problem and will restart in 1 minute" on Windows 10)
Fortunately, a very basic test can show us what thread we can and cannot use: Suspending one thread at a time in LSASS and see what's happening.
Here's the list of the handles my LSASS had when I was writing this article:
![hyhy](https://user-images.githubusercontent.com/65464469/116493016-170d9f80-a89e-11eb-896e-9e393205af25.png)

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

## Writing the bypass client to be integrated in the cheats

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

# RELEASE (written and copyable, i'll release the Microsoft VS buildable file later)
# Bypass installer (standalone binary)

SilentJack2-Setup.hpp:
```C++
#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
 
#pragma comment (lib, "ntdll.lib")
 
#define ThreadQuerySetWin32StartAddress 9
 
#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif
 
#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif
 
#define SHARED_MEM_SIZE 4096
#define PADDING_IN_XMEM 8
//#define SMNAME "Global\\SJ2Mem" // Obfuscated further in code
//#define MUTEXNAME "Global\\SJ2Mtx" // Obfuscated further in code
 
using namespace std;
 
struct UNUSED_XMEM {
	MEMORY_BASIC_INFORMATION regionInfo;
	void* start = nullptr;
	SIZE_T size = NULL;
};
 
struct SJORDER {
	DWORD64 exec = 1; // Least significant byte used to release the spinlock
	DWORD order = 0; // 0: Read, 1: Write
	NTSTATUS status = 0xFFFFFFFF; // TODO: Remove, finally I don't want to get the return
	HANDLE hProcess = NULL;
	DWORD64 lpBaseAddress = NULL;
	SIZE_T nSize = 0;
	SIZE_T* nBytesReadOrWritten = 0; // TODO: Remove, finally I don't want the number of bytes read/written
}; // Important: Must be 8 bytes aligned, otherwise garbage data is added in the structure
 
struct SJCFG {
	SIZE_T remoteExecMemSize = NULL;
	void* remoteExecMem = nullptr;
	SIZE_T sharedMemSize = NULL;
	void* ptrRemoteSharedMem = nullptr;
};
 
// Prototypes
vector<DWORD> GetTIDChronologically(DWORD pid);
vector<DWORD> GetThreadsOfPID(DWORD dwOwnerPID);
vector<DWORD> GetPIDs(wstring targetProcessName);
vector<UNUSED_XMEM> FindExecutableMemory(const HANDLE hProcess, bool onlyInBase = false);
void* GetBaseAddress(const HANDLE hProcess);
DWORD GetSyscallId(string strModule, string strProcName);
map<DWORD, DWORD64> GetThreadsStartAddresses(vector<DWORD> tids);
map<wstring, DWORD64> GetModulesNamesAndBaseAddresses(DWORD pid);
map<DWORD, wstring> GetTIDsModuleStartAddr(DWORD pid);
bool Start();
bool ConnectSharedMem();
bool PushShellcode(void* shellcode, SIZE_T size);
bool ExecWithThreadHiJacking(SIZE_T shellcodeSize = NULL, bool thenRestore = true);
void CleanUp();
bool Setup();
bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege = TRUE);
 
// Globals
string sharedMemName = ""; // Obfuscated further in code
DWORD pivotPID = NULL;
HANDLE hSharedMem = NULL;
HANDLE hProcess = NULL;
void* remoteExecMem = nullptr;
SIZE_T remoteExecMemSize = 0;
DWORD targetTID = NULL;
HANDLE hThread = NULL;
SIZE_T sharedMemSize = SHARED_MEM_SIZE;
SIZE_T usableSharedMemSize = NULL;
void* ptrRemoteSharedMem = nullptr;
void* ptrLocalSharedMem = nullptr;
HANDLE hLocalSharedMem = NULL;
HANDLE hGateKeeperProcess = NULL;
 
bool Setup() {
	string e = ""; // TODO: Randomise names instead of this bad obfuscation (need to be unique per each system reboot)
	string mutexNoStr = e+'G'+'l'+'o'+'b'+'a'+'l'+'\\'+'S'+'J'+'2'+'M'+'t'+'x';
	HANDLE hMutex = CreateMutexA(NULL, TRUE, mutexNoStr.c_str());
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		exit(EXIT_FAILURE); // Security: An instance of either the installer or the client is already running, terminate now
 
	// ADVICE: Add here checks to make sure all anti-cheats are turned off, otherwise you might fire up the installer that does shady stuff while being watched!
 
	if (!SetPrivilege(SE_DEBUG_NAME)) // Getting permissions
		return false;
 
	// Getting LSASS's PID
	wstring we = L"";
	wstring lsassNoStr = we+L'l'+L's'+L'a'+L's'+L's'+L'.'+L'e'+L'x'+L'e';
	vector<DWORD> pidsLsass = GetPIDs(lsassNoStr);
	if (pidsLsass.empty())
		return false;
	sort(pidsLsass.begin(), pidsLsass.end()); // In case there is several lsass.exe running (?) take the first one (based on PID)
	pivotPID = pidsLsass[0];
	if (!pivotPID)
		return false;
	
	// Check for already existing installations
	sharedMemName = e+'G'+'l'+'o'+'b'+'a'+'l'+'\\'+'S'+'J'+'2'+'M'+'e'+'m';
	hSharedMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, sharedMemName.c_str());
	if (hSharedMem)
		return true; // Already installed
 
	// Attachment to process: Get PID and OpenProcess
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pivotPID);
	if (!hProcess)
		return false;
 
	// Getting executable memory
	vector<UNUSED_XMEM> availableXMem = FindExecutableMemory(hProcess);
	if (availableXMem.empty() || availableXMem[0].start == nullptr || availableXMem[0].size == NULL)
		return false; // No executable memory
	if (availableXMem[0].size <= PADDING_IN_XMEM)
		return false; // Executable memory smaller or equal to demanded padding
	remoteExecMem = (void*)((DWORD64)availableXMem[0].start + PADDING_IN_XMEM);
	remoteExecMemSize = availableXMem[0].size - PADDING_IN_XMEM;
 
	// Attaching to thread for thread hijacking, auto finds usable thread
	map<DWORD, wstring> tidsStartModules = GetTIDsModuleStartAddr(pivotPID);
	vector<wstring> preferedTIDsModules;
	wstring dllNoStr = we+L'.'+L'd'+L'l'+L'l';
	wstring samsrvNoStr = we+L's'+L'a'+L'm'+L's'+L'r'+L'v'+dllNoStr;
	wstring msvcrtNoStr = we+L'm'+L's'+L'v'+L'c'+L'r'+L't'+dllNoStr;
	wstring crypt32NoStr = we+L'c'+L'r'+L'y'+L'p'+L't'+L'3'+L'2'+dllNoStr;
	preferedTIDsModules.push_back(samsrvNoStr);
	preferedTIDsModules.push_back(msvcrtNoStr);
	preferedTIDsModules.push_back(crypt32NoStr);
	wstring modName = L"";
	for (int i(0); i < preferedTIDsModules.size(); ++i) {
		for (auto const& thisTid : tidsStartModules) {
			DWORD tid = thisTid.first;
			modName = thisTid.second;
			if (modName == preferedTIDsModules[i]) {
				targetTID = tid;
				break;
			}
		}
		if (targetTID)
			break;
	}
	if (!targetTID)
		return false; // Could not find any of the threads starting in one of the target modules
	
	/*
	// If the thread used is not the one started in samsrv.dll, we'll have to wait for the thread to wake up...
	wcout << "Using thread " << dec << targetTID << " (started in " << modName << ")" << endl;
	if (modName != samsrvNoStr)
		cout << "This thread is most of the time dormant, it may take 1-10 minutes..." << endl;
	*/
 
	hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, targetTID);
	if (!hThread)
		return false; // Couldn't open thread
 
	// Creating shared memory
	hLocalSharedMem = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT | SEC_NOCACHE, 0, sharedMemSize, sharedMemName.c_str());
	if (!hLocalSharedMem)
		return false;
	ptrLocalSharedMem = MapViewOfFile(hLocalSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, sharedMemSize);
	if (!ptrLocalSharedMem)
		return false;
	usableSharedMemSize = sharedMemSize - sizeof(SJCFG);
 
	// Duplicate the handle to shared memory in explorer.exe so a handle keep existing which allows easy reconnection (using OpenFileMapping)
	wstring exeNoStr = we+L'.'+L'e'+L'x'+L'e';
	wstring explorerNoStr = we+L'e'+L'x'+L'p'+L'l'+L'o'+L'r'+L'e'+L'r'+exeNoStr;
	vector<DWORD> explorerPIDs = GetPIDs(explorerNoStr);
	if (explorerPIDs.empty())
		return false;
	hGateKeeperProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, explorerPIDs[0]);
	if (!hGateKeeperProcess)
		return false;
	HANDLE hGateKeeper = NULL;
	if (!DuplicateHandle(GetCurrentProcess(), hLocalSharedMem, hGateKeeperProcess, &hGateKeeper, NULL, FALSE, DUPLICATE_SAME_ACCESS))
		return false;
	CloseHandle(hGateKeeperProcess);
 
	// Connecting shared memory in pivot process
	if (!ConnectSharedMem())
		return false;
	CloseHandle(hLocalSharedMem); // Close handle to shared memory
 
	// Starting bypass
	if (!Start())
		return false;
 
	// Clean-up, closing now unnecessary handles and other potential detection vectors
	CloseHandle(hProcess);
	CloseHandle(hThread);
 
	// Pushes useful information into shared memory, in case the bypass has to reconnect
	CONTEXT contextEmpty;
	SecureZeroMemory(&contextEmpty, sizeof(contextEmpty));
	SJCFG cfgBackup;
	cfgBackup.ptrRemoteSharedMem = ptrRemoteSharedMem;
	cfgBackup.sharedMemSize = sharedMemSize;
	cfgBackup.remoteExecMem = remoteExecMem;
	cfgBackup.remoteExecMemSize = remoteExecMemSize;
	void* endOfUsableLocalSharedMem = (void*)((DWORD64)ptrLocalSharedMem + sharedMemSize - sizeof(SJORDER));
	void* backupAddrInSharedMem = (void*)((DWORD64)endOfUsableLocalSharedMem - sizeof(SJCFG));
	CopyMemory(backupAddrInSharedMem, &cfgBackup, sizeof(cfgBackup));
 
	CleanUp();
	return true;
}
 
vector<DWORD> GetPIDs(wstring targetProcessName) {
	vector<DWORD> pids;
	if (targetProcessName == L"")
		return pids;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof entry;
	if (!Process32FirstW(snap, &entry))
		return pids;
	do {
		if (wstring(entry.szExeFile) == targetProcessName) {
			pids.emplace_back(entry.th32ProcessID);
		}
	} while (Process32NextW(snap, &entry));
	return pids;
}
 
vector<UNUSED_XMEM> FindExecutableMemory(const HANDLE hProcess, bool onlyInBase) {
	MEMORY_BASIC_INFORMATION memInfo;
	vector<MEMORY_BASIC_INFORMATION> memInfos;
	vector<MEMORY_BASIC_INFORMATION> execMemInfos;
	vector<UNUSED_XMEM> freeXMems;
	void* baseAddr = nullptr;
 
	if (onlyInBase)
		baseAddr = GetBaseAddress(hProcess);
 
	// Getting all MEMORY_BASIC_INFORMATION of the target process
	unsigned char* addr = NULL;
	for (addr = NULL; VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo); addr += memInfo.RegionSize)
		if (!onlyInBase || (onlyInBase && memInfo.AllocationBase == baseAddr))
			memInfos.push_back(memInfo);
	if (memInfos.empty())
		return freeXMems;
 
	// Filtering only executable memory regions
	for (int i(0); i < memInfos.size(); ++i) {
		DWORD prot = memInfos[i].Protect;
		if (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY)
			execMemInfos.push_back(memInfos[i]);
	}
	if (execMemInfos.empty())
		return freeXMems;
 
	// Duplicating memory locally for analysis, finding unused memory at the end of executable regions
	for (int i(0); i < execMemInfos.size(); ++i) {
		// Getting local buffer
		void* localMemCopy = VirtualAlloc(NULL, execMemInfos[i].RegionSize, MEM_COMMIT, PAGE_READWRITE);
		if (localMemCopy == NULL)
			continue; // Error, no local buffer
 
		// Copying executable memory content locally
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProcess, execMemInfos[i].BaseAddress, localMemCopy, execMemInfos[i].RegionSize, &bytesRead)) {
			// Error while copying the executable memory content to local process for analysis
			VirtualFree(localMemCopy, execMemInfos[i].RegionSize, MEM_RELEASE);
			continue;
		}
 
		// Analysing unused executable memory size and location locally
		BYTE currentByte = 0;
		SIZE_T unusedSize = 0;
		DWORD64 analysingByteAddr = (DWORD64)localMemCopy + execMemInfos[i].RegionSize - 1;
		while (analysingByteAddr >= (DWORD64)localMemCopy) {
			CopyMemory(&currentByte, (void*)analysingByteAddr, sizeof(BYTE));
			if (currentByte != 0)
				break;
			++unusedSize;
			--analysingByteAddr; // Next byte
		}
		if (unusedSize == 0) {
			// No unused bytes
			VirtualFree(localMemCopy, execMemInfos[i].RegionSize, MEM_RELEASE);
			continue;
		}
 
		// Found unused executable memory, pushing it into the result vector
		UNUSED_XMEM unusedXMem;
		unusedXMem.regionInfo = execMemInfos[i];
		unusedXMem.size = unusedSize;
		unusedXMem.start = (void*)((DWORD64)execMemInfos[i].BaseAddress + execMemInfos[i].RegionSize - unusedSize);
		freeXMems.push_back(unusedXMem);
 
		// Clean-up
		VirtualFree(localMemCopy, execMemInfos[i].RegionSize, MEM_RELEASE);
	}
 
	return freeXMems;
}
 
void* GetBaseAddress(const HANDLE hProcess) {
	if (hProcess == NULL)
		return NULL;
	HMODULE lphModule[1024];
	DWORD lpcbNeeded(NULL);
	if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded))
		return NULL; // Impossible to read modules (hProcess requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
	return lphModule[0]; // Module 0 is the EXE itself, returning its address
}
 
bool ConnectSharedMem() {
	// Getting function addresses
	FARPROC addrOpenFileMappingA = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "OpenFileMappingA");
	FARPROC addrMapViewOfFile = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "MapViewOfFile");
	FARPROC addrCloseHandle = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "CloseHandle");
	if (!addrOpenFileMappingA || !addrMapViewOfFile || !addrCloseHandle)
		return false;
 
	// Get RW memory to assemble full shellcode from parts
	void* rwMemory = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (rwMemory == nullptr)
		return false;
	DWORD64 addrEndOfShellCode = (DWORD64)rwMemory;
 
	UCHAR x64OpenFileMappingA[] = {
		0x48, 0xc7, 0xc1, 0x1f, 0, 0x0f, 0,	// mov rcx, dwDesiredAccess			+0 (FILE_MAP_ALL_ACCESS = 0xf001f @ +3)
		0x48, 0x31, 0xd2,					// xor rdx, rdx						+7 (bInheritHandle = FALSE)
		0x49, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,	// mov r8, &lpName					+10 (&lpName +12)
		0x4d, 0x31, 0xc9,					// xor r9, r9						+20
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, addrOpenFileMappingA	+23 (addrOpenFileMappingA +25)
		0x48, 0x83, 0xec, 0x20,				// sub rsp, 0x20					+33
		0xff, 0xd0,							// call rax							+37
		0x48, 0x83, 0xc4, 0x20,				// add rsp, 0x20					+39
		0x49, 0x89, 0xc7					// mov r15, rax						+43
	};
	*(DWORD64*)((PUCHAR)x64OpenFileMappingA + 25) = (DWORD64)(ULONG_PTR)addrOpenFileMappingA;
	CopyMemory((void*)addrEndOfShellCode, x64OpenFileMappingA, sizeof(x64OpenFileMappingA));
	addrEndOfShellCode += sizeof(x64OpenFileMappingA);
 
	UCHAR x64MapViewOfFile[] = {
		0x48, 0x89, 0xc1,					// mov rcx, rax						+0
		0x48, 0xc7, 0xc2, 0x1f, 0, 0x0f, 0,	// mov rdx, dwDesiredAccess			+3 (FILE_MAP_ALL_ACCESS = 0xf001f @ +6)
		0x4d, 0x31, 0xc0,					// xor r8, r8						+10
		0x4d, 0x31, 0xc9,					// xor r9, r9						+13
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, dwNumberOfBytesToMap	+16 (dwNumberOfBytesToMap +18)
		0x50,								// push rax							+26
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, addrMapViewOfFile		+27 (addrMapViewOfFile +29)
		0x48, 0x83, 0xec, 0x20,				// sub rsp, 0x20					+37
		0xff, 0xd0,							// call rax							+41
		0x48, 0x83, 0xc4, 0x28,				// add rsp, 0x28					+43
		0x49, 0x89, 0xc6,					// mov r14, rax						+47
		// Writing to shared memory the virtual address in pivot process
		0x4d, 0x89, 0x36					// mov [r14], r14					+50
	};
	*(SIZE_T*)((PUCHAR)x64MapViewOfFile + 18) = (SIZE_T)(ULONG_PTR)sharedMemSize;
	*(DWORD64*)((PUCHAR)x64MapViewOfFile + 29) = (DWORD64)(ULONG_PTR)addrMapViewOfFile;
	CopyMemory((void*)addrEndOfShellCode, x64MapViewOfFile, sizeof(x64MapViewOfFile));
	addrEndOfShellCode += sizeof(x64MapViewOfFile);
 
	UCHAR x64CloseHandle[] = {
		0x4C, 0x89, 0xF9,					// mov rcx, r15						+0
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, addrCloseHandle			+3 (addrCloseHandle +5)
		0x48, 0x83, 0xec, 0x20,				// sub rsp, 0x20					+13
		0xff, 0xd0,							// call rax							+17
		0x48, 0x83, 0xc4, 0x20				// add rsp, 0x20					+19
	};
	*(DWORD64*)((PUCHAR)x64CloseHandle + 5) = (DWORD64)(ULONG_PTR)addrCloseHandle;
	CopyMemory((void*)addrEndOfShellCode, x64CloseHandle, sizeof(x64CloseHandle));
	addrEndOfShellCode += sizeof(x64CloseHandle);
 
	UCHAR x64InfiniteLoop[] = { 0xEB, 0xFE }; // nop + jmp rel8 -2
	CopyMemory((void*)addrEndOfShellCode, x64InfiniteLoop, sizeof(x64InfiniteLoop));
	addrEndOfShellCode += sizeof(x64InfiniteLoop);
 
	UCHAR lpNameBuffer[30];
	SecureZeroMemory(lpNameBuffer, sizeof(lpNameBuffer));
	CopyMemory(lpNameBuffer, sharedMemName.c_str(), sharedMemName.size());
	CopyMemory((void*)addrEndOfShellCode, lpNameBuffer, sizeof(lpNameBuffer));
	addrEndOfShellCode += sizeof(lpNameBuffer);
 
	// Calculating full size of shellcode
	SIZE_T fullShellcodeSize = addrEndOfShellCode - (DWORD64)rwMemory;
 
	// Placing pointer to the buffer integrated with the shellcode containing the name
	DWORD64 lpNameInRemoteExecMemory = (DWORD64)remoteExecMem + fullShellcodeSize - sizeof(lpNameBuffer);
	CopyMemory((void*)((DWORD64)rwMemory + 12), &lpNameInRemoteExecMemory, sizeof(lpNameInRemoteExecMemory));
 
	bool pushShellcodeStatus = PushShellcode(rwMemory, fullShellcodeSize);
	VirtualFree(rwMemory, 0, MEM_RELEASE);
	if (!pushShellcodeStatus)
		return false;
 
	if (!ExecWithThreadHiJacking(fullShellcodeSize - sizeof(lpNameBuffer), false)) // The shellcode ends before since the end is just memory
		return false;
 
	CopyMemory(&ptrRemoteSharedMem, ptrLocalSharedMem, sizeof(void*));
	if (ptrRemoteSharedMem == nullptr)
		return false;
	else
		return true;
}
 
bool Start() {
	// Pushing control structure into shared memory
	SJORDER controlStruct;
	void* controlLocalAddr = (void*)((DWORD64)ptrLocalSharedMem + sharedMemSize - sizeof(controlStruct));
	CopyMemory(controlLocalAddr, &controlStruct, sizeof(controlStruct));
	void* controlRemoteAddr = (void*)((DWORD64)ptrRemoteSharedMem + sharedMemSize - sizeof(controlStruct));
 
	// Getting function addresses
	string e = "";
	string ntrvmNoStr = e+'N'+'t'+'R'+'e'+'a'+'d'+'V'+'i'+'r'+'t'+'u'+'a'+'l'+'M'+'e'+'m'+'o'+'r'+'y';
	string ntwvmNoStr = e+'N'+'t'+'W'+'r'+'i'+'t'+'e'+'V'+'i'+'r'+'t'+'u'+'a'+'l'+'M'+'e'+'m'+'o'+'r'+'y';
	DWORD syscallIndexZwRVM = GetSyscallId("ntdll.dll", ntrvmNoStr);
	DWORD syscallIndexZwWVM = GetSyscallId("ntdll.dll", ntwvmNoStr);
	if (!syscallIndexZwRVM || !syscallIndexZwWVM)
		return false;
 
	// Get RW memory to assemble full shellcode from parts
	void* rwMemory = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (rwMemory == nullptr)
		return false;
	DWORD64 addrEndOfShellCode = (DWORD64)rwMemory;
 
	UCHAR x64Spinlock[] = {
		0xA0, 0, 0, 0, 0, 0, 0, 0, 0,	// mov al, [&exec]
		0x3c, 0,						// cmp al, 0
		0xF3, 0x90,						// pause (signals the CPU that we are in a spinlock)
		0x75, 0xF1						// jnz -14
	};
	*(DWORD64*)((PUCHAR)x64Spinlock + 1) = (DWORD64)(ULONG_PTR)controlRemoteAddr;
	CopyMemory((void*)addrEndOfShellCode, x64Spinlock, sizeof(x64Spinlock));
	addrEndOfShellCode += sizeof(x64Spinlock);
 
	// Do not retrieve nbr of bytes read/written (otherwise mov rax, ptr)
	UCHAR x64ZeroRax[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
	CopyMemory((void*)addrEndOfShellCode, x64ZeroRax, sizeof(x64ZeroRax));
	addrEndOfShellCode += sizeof(x64ZeroRax);
 
	UCHAR x64ZwRWVM[] = {
		// Preparing argument passing to NtRVM/NtWVM
		0x50,								// push rax						+0 (NumberOfBytesRead, optional)
		0x48, 0x83, 0xec, 0x28,				// sub rsp, 0x28				+1 (+8 normally the return address pushed by NtRVM call)
		0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, [&hProcess]			+5 (&hProcess +7)
		0x48, 0x89, 0xc1,					// mov rcx, rax					+15
		0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, [&lpBaseAddress]	+18 (&lpBaseAddress +20)
		0x48, 0x89, 0xc2,					// mov rdx, rax					+28
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, [&lpBuffer]			+31 (&lpBuffer +33)
		0x49, 0x89, 0xc0,					// mov r8, rax					+41
		0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, [&nSize]			+44 (&nSize +46)
		0x49, 0x89, 0xc1,					// mov r9, rax					+54
		// Loading function pointer accordingly to current order
		0xa0, 0, 0, 0, 0, 0, 0, 0, 0,		// mov al, [&order]				+57 (&order +58)
		0x3c, 0x0,							// cmp al, 0x0					+66
		0x49, 0x89, 0xCA,					// mov r10, rcx					+68
		0x75, 0x9,							// jne +9						+71
		0xb8, 0, 0, 0, 0,					// mov eax, WZWVM_SYSCALLID		+73 (WZWVM_SYSCALLID +74)
		0x0f, 0x05,							// syscall						+78
		0xeb, 0x7,							// jmp +7						+80
		0xb8, 0, 0, 0, 0,					// mov eax, WZRVM_SYSCALLID		+82 (WZRVM_SYSCALLID +83)
		0x0f, 0x05,							// syscall						+87
		0x48, 0x83, 0xC4, 0x30				// add rsp, 0x30				+89
	};
	*(DWORD64*)((PUCHAR)x64ZwRWVM + 7) = (DWORD64)(ULONG_PTR)((DWORD64)controlRemoteAddr + 16);
	*(DWORD64*)((PUCHAR)x64ZwRWVM + 20) = (DWORD64)(ULONG_PTR)((DWORD64)controlRemoteAddr + 24);
	*(DWORD64*)((PUCHAR)x64ZwRWVM + 33) = (DWORD64)(ULONG_PTR)ptrRemoteSharedMem;
	*(DWORD64*)((PUCHAR)x64ZwRWVM + 46) = (DWORD64)(ULONG_PTR)((DWORD64)controlRemoteAddr + 32);
	*(DWORD64*)((PUCHAR)x64ZwRWVM + 58) = (DWORD64)(ULONG_PTR)((DWORD64)controlRemoteAddr + 8);
	*(DWORD*)((PUCHAR)x64ZwRWVM + 74) = (DWORD)(ULONG_PTR)syscallIndexZwRVM;
	*(DWORD*)((PUCHAR)x64ZwRWVM + 83) = (DWORD)(ULONG_PTR)syscallIndexZwWVM;
	CopyMemory((void*)addrEndOfShellCode, x64ZwRWVM, sizeof(x64ZwRWVM));
	addrEndOfShellCode += sizeof(x64ZwRWVM);
 
	UCHAR x64ToggleSpinlock[] = {
		0xB0, 1,												// mov al, 1
		0xA2, 0, 0, 0, 0, 0, 0, 0, 0							// mov [&exec], al
	};
	*(DWORD64*)((PUCHAR)x64ToggleSpinlock + 3) = (DWORD64)(ULONG_PTR)controlRemoteAddr;
	CopyMemory((void*)addrEndOfShellCode, x64ToggleSpinlock, sizeof(x64ToggleSpinlock));
	addrEndOfShellCode += sizeof(x64ToggleSpinlock);
 
	// End of cycle, jump back to start
	UCHAR x64AbsoluteJump[] = {
		0x48, 0xb8,	0, 0, 0, 0, 0, 0, 0, 0,	// mov rax, m_remoteExecMem		+0 (m_remoteExecMem +2)
		0xff, 0xe0							// jmp rax						+10
	};
	*(DWORD64*)((PUCHAR)x64AbsoluteJump + 2) = (DWORD64)(ULONG_PTR)remoteExecMem;
	CopyMemory((void*)addrEndOfShellCode, x64AbsoluteJump, sizeof(x64AbsoluteJump));
	addrEndOfShellCode += sizeof(x64AbsoluteJump);
	
	SIZE_T fullShellcodeSize = addrEndOfShellCode - (DWORD64)rwMemory;
	bool pushShellcodeStatus = PushShellcode(rwMemory, fullShellcodeSize);
	VirtualFree(rwMemory, 0, MEM_RELEASE);
	if (!pushShellcodeStatus)
		return false;
 
	if (!ExecWithThreadHiJacking())
		return false;
	else
		return true;
}
 
bool PushShellcode(void* shellcode, SIZE_T size) {
	if (size > remoteExecMemSize)
		return false; // Not enough executable memory available
	SIZE_T bytesWritten = 0;
	BOOL wpmStatus = WriteProcessMemory(hProcess, remoteExecMem, shellcode, size, &bytesWritten);
	if (wpmStatus = FALSE)
		return false;
	else
		return true;
}
 
bool ExecWithThreadHiJacking(SIZE_T shellcodeSize, bool thenRestore) {
	// Preparing for thread hijacking
	CONTEXT tcInitial;
	CONTEXT tcHiJack;
	CONTEXT tcCurrent;
	SecureZeroMemory(&tcInitial, sizeof(CONTEXT));
	tcInitial.ContextFlags = CONTEXT_ALL;
 
	// Suspend thread and send it executing our shellcode
	DWORD suspendCount = SuspendThread(hThread);
	if (suspendCount > 0) // The thread was already suspended
		for (int i(0); i < suspendCount; ++i)
			ResumeThread(hThread);
	GetThreadContext(hThread, &tcInitial);
	CopyMemory(&tcHiJack, &tcInitial, sizeof(CONTEXT)); // Faster than another call to GetThreadContext
	CopyMemory(&tcCurrent, &tcInitial, sizeof(CONTEXT));
	tcHiJack.Rip = (DWORD64)remoteExecMem;
	SetThreadContext(hThread, &tcHiJack);
	ResumeThread(hThread);
 
	if (shellcodeSize == NULL)
		return true; // Permanent thread hijack, do not wait for any execution completion
 
	// Check the thread context to know when done executing (RIP should be at memory address + size of shellcode - 2 in the infinite loop jmp rel8 -2)
	DWORD64 addrEndOfExec = (DWORD64)remoteExecMem + shellcodeSize - 2;
	do {
		GetThreadContext(hThread, &tcCurrent);
	} while (tcCurrent.Rip != addrEndOfExec);
 
	if (thenRestore) {
		// Execution finished, resuming previous operations
		SuspendThread(hThread);
		SetThreadContext(hThread, &tcInitial);
		ResumeThread(hThread);
	}
 
	return true;
}
 
vector<DWORD> GetTIDChronologically(DWORD pid) {
	map<ULONGLONG, DWORD> tidsWithStartTimes;
	vector<DWORD> tids;
 
	if (pid == NULL)
		return tids;
 
	DWORD dwMainThreadID = NULL;
	ULONGLONG ullMinCreateTime = MAXULONGLONG;
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 th32;
		th32.dwSize = sizeof(THREADENTRY32);
		BOOL bOK = TRUE;
		for (bOK = Thread32First(hThreadSnap, &th32); bOK; bOK = Thread32Next(hThreadSnap, &th32)) {
			if (th32.th32OwnerProcessID == pid) {
				HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, th32.th32ThreadID);
				if (hThread) {
					FILETIME afTimes[4] = { 0 };
					if (GetThreadTimes(hThread, &afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
						ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime, afTimes[0].dwHighDateTime);
						tidsWithStartTimes[ullTest] = th32.th32ThreadID;
					}
					CloseHandle(hThread);
				}
			}
		}
		CloseHandle(hThreadSnap);
	}
 
	for (auto const& thread : tidsWithStartTimes) // maps are natively ordered by key
		tids.push_back(thread.second);
 
	return tids;
}
 
vector<DWORD> GetThreadsOfPID(DWORD dwOwnerPID) {
	vector<DWORD> threadIDs;
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
 
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return threadIDs;
	te32.dwSize = sizeof(THREADENTRY32);
 
	if (!Thread32First(hThreadSnap, &te32)) {
		CloseHandle(hThreadSnap);
		return threadIDs;
	}
 
	do {
		if (te32.th32OwnerProcessID == dwOwnerPID)
			threadIDs.push_back(te32.th32ThreadID);
	} while (Thread32Next(hThreadSnap, &te32));
	return threadIDs;
}
 
DWORD GetSyscallId(string strModule, string strProcName) {
	FARPROC pFunction = GetProcAddress(GetModuleHandleA(strModule.c_str()), strProcName.c_str());
	
	BYTE x64PreSyscallOpcodes[] = {
		0x4C, 0x8B, 0xD1,	// mov r10, rcx;
		0xB8				// mov eax, XXh ; Syscall ID
	};
 
	for (int i = 0; i < 4; ++i)
		if (*(BYTE*)((DWORD64)pFunction + i) != x64PreSyscallOpcodes[i])
			return 0; // The function has been tampered with already...
 
	DWORD sysCallIndex = *(DWORD*)((DWORD64)pFunction + 4);
	return sysCallIndex;
}
 
map<DWORD, DWORD64> GetThreadsStartAddresses(vector<DWORD> tids) {
	map<DWORD, DWORD64> tidsStartAddresses;
 
	if (tids.empty())
		return tidsStartAddresses;
 
	for (int i(0); i < tids.size(); ++i) {
		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tids[i]);
		PVOID startAddress = NULL;
		ULONG returnLength = NULL;
		NTSTATUS NtQIT = NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), &returnLength);
		CloseHandle(hThread);
		if (tids[i] && startAddress)
			tidsStartAddresses[tids[i]] = (DWORD64)startAddress;
	}
 
	return tidsStartAddresses;
}
 
map<wstring, DWORD64> GetModulesNamesAndBaseAddresses(DWORD pid) {
	map<wstring, DWORD64> modsStartAddrs;
 
	if (!pid)
		return modsStartAddrs;
 
	HMODULE hMods[1024];
	DWORD cbNeeded;
	unsigned int i;
 
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (!hProcess)
		return modsStartAddrs;
 
	// Get a list of all the modules in this process
	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		CloseHandle(hProcess);
		return modsStartAddrs;
	}
 
	// Get each module's infos
	for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		TCHAR szModName[MAX_PATH];
		if (!GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(TCHAR))) // Get the full path to the module's file
			continue;
		wstring modName = szModName;
		int pos = modName.find_last_of(L"\\");
		modName = modName.substr(pos + 1, modName.length());
 
		MODULEINFO modInfo;
		if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
			continue;
 
		DWORD64 baseAddr = (DWORD64)modInfo.lpBaseOfDll;
		modsStartAddrsName] = baseAddr;
	}
 
	// Release the handle to the process
	CloseHandle(hProcess);
	return modsStartAddrs;
}
 
map<DWORD, wstring> GetTIDsModuleStartAddr(DWORD pid) {
	map<DWORD, wstring> tidsStartModule;
 
	map<wstring, DWORD64> modsStartAddrs = GetModulesNamesAndBaseAddresses(pid);
	if (modsStartAddrs.empty())
		return tidsStartModule;
 
	vector<DWORD> tids = GetTIDChronologically(pid);
	if (tids.empty())
		return tidsStartModule;
 
	map<DWORD, DWORD64> tidsStartAddresses = GetThreadsStartAddresses(tids);
	if (tidsStartAddresses.empty())
		return tidsStartModule;
 
	for (auto const& thisTid : tidsStartAddresses) {
		DWORD tid = thisTid.first;
		DWORD64 startAddress = thisTid.second;
		DWORD64 nearestModuleAtLowerAddrBase = 0;
		wstring nearestModuleAtLowerAddrName = L"";
		for (auto const& thisModule : modsStartAddrs) {
			wstring moduleName = thisModule.first;
			DWORD64 moduleBase = thisModule.second;
			if (moduleBase > startAddress)
				continue;
			if (moduleBase > nearestModuleAtLowerAddrBase) {
				nearestModuleAtLowerAddrBase = moduleBase;
				nearestModuleAtLowerAddrName = moduleName;
			}
		}
		if (nearestModuleAtLowerAddrBase > 0 && nearestModuleAtLowerAddrName != L"")
			tidsStartModule[tid] = nearestModuleAtLowerAddrName;
	}
 
	return tidsStartModule;
}
 
void CleanUp() {
	if (hSharedMem)
		CloseHandle(hSharedMem);
	if (hProcess)
		CloseHandle(hProcess);
	if (hThread)
		CloseHandle(hThread);
	if (hLocalSharedMem)
		CloseHandle(hLocalSharedMem);
	if (ptrLocalSharedMem)
		UnmapViewOfFile(ptrLocalSharedMem);
	if (hGateKeeperProcess)
		CloseHandle(hGateKeeperProcess);
}
 
bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (!LookupPrivilegeValueW(0, lpszPrivilege, &luid)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)) {
		if (hToken)
			CloseHandle(hToken);
		return false;
	}
	if (hToken)
		CloseHandle(hToken);
	return true;
}
```

main.cpp:
```C++
#include "SilentJack2-Setup.hpp"
#include <iostream>
 
int main() {
	cout << "Installing ... ";
 
	bool installed = Setup();
	CleanUp();
 
	if (installed)
		cout << "OK ";
	else
		cout << "FAILED ";
 
	for (int i(0); i < 4; ++i) {
		Sleep(1000);
		cout << ".";
	}
 
	if (installed)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
```

## Usage:

Only execute when no anti-cheat is active. The installer does operations that AC won't like, therefore I STRONGLY advise you to add at the beginning of the Setup() function some additional checks to make sure the AC you are trying to bypass is not active (I left a comment telling you where to write that code). Without this additional security you can essentially pwn your sorry face by executing the bypass installer at the wrong time.
For instant setup, execute within 1 minute after reboot (the bypass will permanently hijack a thread that is active but only present for a short period, otherwise you will have to wait for one of the dormant threads to wake up, which can take a few minutes sometimes)
You only need to execute the installer once per reboot. If you execute it more than once, no sweat, the installer will detect that it's already installed and just exit successfully.
To auto install the bypass at every reboot, you can find a way to execute it automatically (I wouldn't advise that though)
I recommend deleting permanently the installer after each installation. If you want to keep a binary ready to run, consider keeping it on a USB stick that you unplug after installation, keeping the risky installer binary out of touch.

# Bypass client (C++ class, use in your cheats)

SilentJack2-Client.hpp:
```C++
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <map>
#include <algorithm>
#include <string>
#include "GetHandle.hpp"
 
//#define NOBYPASS
#ifdef NOBYPASS
#pragma comment (lib, "ntdll.lib")
#endif
 
#define WITHBENCHMARK
 
#define SHARED_MEM_SIZE 4096
//#define SMNAME "Global\\SJ2Mem" // Obfuscated
//#define MUTEXNAME "Global\\SJ2Mtx" // Obfuscated
 
using namespace std;
 
extern "C" void SpinLockByte(volatile void* byteAddr, volatile BYTE valueExit);
 
#ifdef NOBYPASS
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
#endif
 
struct SJORDER {
	DWORD64 exec = 1; // Least significant byte used to release the spinlock, 0 release spinlock in abused process overwritten to 1 after execution
	DWORD order = 0; // 0: Read, 1: Write
	NTSTATUS status = 0xFFFFFFFF; // TODO: Remove
	HANDLE hProcess = NULL;
	DWORD64 lpBaseAddress = NULL;
	SIZE_T nSize = 0;
	SIZE_T* nBytesReadOrWritten = 0; // TODO: Remove
}; // Important: Must be 8 bytes aligned, otherwise garbage data is added in the structure
 
struct SJCFG {
	SIZE_T remoteExecMemSize = NULL;
	void* remoteExecMem = nullptr;
	SIZE_T sharedMemSize = NULL;
	void* ptrRemoteSharedMem = nullptr;
};
 
class SilentJack {
public:
	SilentJack();
	~SilentJack();
 
	// Function to call before use
	bool Init();
 
	// Functions of interest
	HANDLE GetHandle(wstring gameProcessName = L"", bool setAsDefault = true);
	void UseHandle(HANDLE handleID);
	NTSTATUS qRVM(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead = NULL);
	NTSTATUS qWVM(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten = NULL);
	NTSTATUS RVM(HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead = NULL);
	NTSTATUS WVM(HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten = NULL);
	uintptr_t Deref(uintptr_t addr, HANDLE hProcess = NULL);
	uintptr_t DerefChain(vector<uintptr_t> ptrChain, bool derefLast = false);
	// Benchmark
	unsigned int countingRVMs = 0, countingWVMs = 0, RVMs = 0, WVMs = 0;
	unsigned int countingRVMc = 0, countingWVMc = 0, RVMc = 0, WVMc = 0;
	void ResetSecond();
	void ResetCycle();
 
	// Static functions
	static vector<DWORD> GetPIDs(wstring targetProcessName);
 
protected:
	// Install
	bool Reconnect(HANDLE hLocalSharedMem = NULL);
	bool Disconnect();
	NTSTATUS RWVM(HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* nBytesReadOrWritten, bool read = true);
 
	// Configuration
	HANDLE m_hMutex = NULL;
	DWORD m_pivotPID = NULL;
	HANDLE m_hHiJack = NULL;
	// Shared memory
	SIZE_T m_usableSharedMemSize = NULL;
	void* m_ptrLocalSharedMem = nullptr;
};
 
SilentJack::SilentJack() {
 
}
 
SilentJack::~SilentJack() {
	Disconnect();
}
 
bool SilentJack::Disconnect() {
	if (m_ptrLocalSharedMem)
		UnmapViewOfFile(m_ptrLocalSharedMem);
#ifdef NOBYPASS
	if (m_hHiJack)
		CloseHandle(m_hHiJack);
#endif
	return true;
}
 
bool SilentJack::Init() {
#ifdef NOBYPASS
	m_usableSharedMemSize = INFINITE;
	return true;
#endif
 
	string e = ""; // TODO Overoptimisation: Randomise names instead of offuscation (need to be unique per each system reboot)
	string mutexNoStr = e+'G'+'l'+'o'+'b'+'a'+'l'+'\\'+'S'+'J'+'2'+'M'+'t'+'x';
	m_hMutex = CreateMutexA(NULL, TRUE, mutexNoStr.c_str());
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		exit(EXIT_FAILURE); // Security: An instance is already running, terminate now
 
	wstring we = L"";
	wstring lsassNoStr = we + L'l' + L's' + L'a' + L's' + L's' + L'.' + L'e' + L'x' + L'e';
	vector<DWORD> pidsLsass = GetPIDs(lsassNoStr);
	if (pidsLsass.empty())
		return false;
	sort(pidsLsass.begin(), pidsLsass.end()); // In case there is several lsass.exe running (?) take the first one (based on PID)
	m_pivotPID = pidsLsass[0];
	if (!m_pivotPID)
		return false;
 
	// Test if bypass is installed with gatekeeper
	string sharedMemNameNoStr = e+'G'+'l'+'o'+'b'+'a'+'l'+'\\'+'S'+'J'+'2'+'M'+'e'+'m';
	HANDLE hLocalSharedMem = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, sharedMemNameNoStr.c_str());
	if (!hLocalSharedMem)
		return false; // Not installed
	return Reconnect(hLocalSharedMem);
}
 
bool SilentJack::Reconnect(HANDLE hLocalSharedMem) {
	if (!hLocalSharedMem)
		return false;
	// Remapping shared memory
	m_ptrLocalSharedMem = MapViewOfFile(hLocalSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, SHARED_MEM_SIZE);
	CloseHandle(hLocalSharedMem);
	if (!m_ptrLocalSharedMem)
		return false;
 
	// Restoring variables from backup in shared memory
	SJCFG cfgBackup;
	void* endOfUsableLocalSharedMem = (void*)((DWORD64)m_ptrLocalSharedMem + SHARED_MEM_SIZE - sizeof(SJORDER));
	void* backupAddrInSharedMem = (void*)((DWORD64)endOfUsableLocalSharedMem - sizeof(SJCFG));
	CopyMemory(&cfgBackup, backupAddrInSharedMem, sizeof(cfgBackup));
 
	// Quick and dirty consistency check
	if (!cfgBackup.ptrRemoteSharedMem || !cfgBackup.sharedMemSize || !cfgBackup.remoteExecMem || !cfgBackup.remoteExecMemSize || cfgBackup.sharedMemSize != SHARED_MEM_SIZE)
		return false;
	m_usableSharedMemSize = cfgBackup.sharedMemSize - sizeof(SJCFG);
 
	return true;
}
 
vector<DWORD> SilentJack::GetPIDs(wstring targetProcessName) {
	vector<DWORD> pids;
	if (targetProcessName == L"")
		return pids;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry;
	entry.dwSize = sizeof entry;
	if (!Process32FirstW(snap, &entry))
		return pids;
	do {
		if (wstring(entry.szExeFile) == targetProcessName) {
			pids.emplace_back(entry.th32ProcessID);
		}
	} while (Process32NextW(snap, &entry));
	return pids;
}
 
NTSTATUS SilentJack::RWVM(HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* nBytesReadOrWritten, bool read) {
	if (!lpBuffer || !lpBaseAddress || !nSize || nSize >= m_usableSharedMemSize || !hProcess)
		return (NTSTATUS)0xFFFFFFFF;
	
#ifdef NOBYPASS
		if (read)
			return NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, (PULONG)nBytesReadOrWritten);
		else
			return NtWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, (PULONG)nBytesReadOrWritten);
#endif
 
	// Preparing order structure
	SJORDER rpmOrder;
	rpmOrder.hProcess = hProcess;
	rpmOrder.lpBaseAddress = (DWORD64)lpBaseAddress;
	rpmOrder.nSize = nSize;
	rpmOrder.nBytesReadOrWritten = nBytesReadOrWritten;
 
	// For write operations, changing order and placing data to write in shared memory
	if (!read) {
		rpmOrder.order = 1;
		CopyMemory(m_ptrLocalSharedMem, lpBuffer, nSize);
	}
 
	// Pushing parameters
	void* controlLocalAddr = (void*)((DWORD64)m_ptrLocalSharedMem + SHARED_MEM_SIZE - sizeof(rpmOrder));
	CopyMemory(controlLocalAddr, &rpmOrder, sizeof(rpmOrder));
 
	// Triggering execution and waiting for completion with the configured synchronisation method
	BYTE exec = 0;
	CopyMemory(controlLocalAddr, &exec, sizeof(exec));
	SpinLockByte(controlLocalAddr, 1);
 
	// Moving from shared memory to lpBuffer and returning
	if (read)
		CopyMemory(lpBuffer, m_ptrLocalSharedMem, nSize);
 
#ifdef WITHBENCHMARK
	if (read) {
		++countingRVMs;
		++countingRVMc;
	} else {
		++countingWVMs;
		++countingWVMc;
	}
#endif
 
	return rpmOrder.status;
}
 
NTSTATUS SilentJack::RVM(HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
	return RWVM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, true);
}
 
NTSTATUS SilentJack::WVM(HANDLE hProcess, void* lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
	return RWVM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, false);
}
 
uintptr_t SilentJack::Deref(uintptr_t addr, HANDLE hProcess) {
	uintptr_t addrPointed = NULL;
	if (!addr) // Invalid memory address given.
		return addrPointed;
	
	if (hProcess)
		RVM(hProcess, (void*)addr, &addrPointed, sizeof(void*));
	else
		RVM(m_hHiJack, (void*)addr, &addrPointed, sizeof(void*));
		
	return addrPointed;
}
 
uintptr_t SilentJack::DerefChain(vector<uintptr_t> ptrChain, bool derefLast) {
	uintptr_t addr(0);
 
	for (int i(0); i < ptrChain.size(); ++i) {
		addr += ptrChain[i];
		if ((i + 1) < ptrChain.size() || ((i + 1) == ptrChain.size() && derefLast)) { // If we are asked to also dereference the last offset
			addr = Deref(addr);
		}
	}
	return addr;
}
 
// Quick mode
void SilentJack::UseHandle(HANDLE handleID) { m_hHiJack = handleID; }
NTSTATUS SilentJack::qRVM(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
	return RWVM(m_hHiJack, (void*)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead, true);
}
NTSTATUS SilentJack::qWVM(uintptr_t lpBaseAddress, void* lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
	return RWVM(m_hHiJack, (void*)lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten, false);
}
 
HANDLE SilentJack::GetHandle(wstring gameProcessName, bool setAsDefault) {
	HANDLE hGame = NULL;
 
#ifdef NOBYPASS
		vector<DWORD> pids = SilentJack::GetPIDs(gameProcessName);
		if (pids.empty())
			return (HANDLE)0x0;
		 hGame = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pids[0]);
#else
		hGame = GetHandleIdTo(gameProcessName, m_pivotPID);
#endif
 
	if (setAsDefault)
		UseHandle(hGame);
 
	return hGame;
}
 
void SilentJack::ResetSecond() {
	RVMs = countingRVMs;
	WVMs = countingWVMs;
	countingRVMs = 0;
	countingWVMs = 0;
}
 
void SilentJack::ResetCycle() {
	RVMc = countingRVMc;
	WVMc = countingWVMc;
	countingRVMc = 0;
	countingWVMc = 0;
}
```

GetHandle.hpp:
```C++
#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <ntstatus.h>
#include <Psapi.h>
#include <string>
#define SYSTEMHANDLEINFORMATION 16
#pragma comment (lib, "ntdll.lib")
 
typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;
 
typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount; // Or NumberOfHandles if you prefer
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;
 
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	DWORD UniqueProcessId;
	WORD HandleType;
	USHORT HandleValue;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
 
typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;
 
EXTERN_C NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG);
 
bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege = TRUE);
 
/* This function finds a handle to a process from its name.
It can also find handles to a process belonging to other processes.
Important: Does NOT return a valid HANDLE, it only returns the Handle ID */
HANDLE GetHandleIdTo(std::wstring targetProcessName, DWORD pidOwner = NULL) {
	if (targetProcessName == L"")
		return (HANDLE)0x0; // Trying to get a handle to an empty process name
 
	SetPrivilege(SE_DEBUG_NAME); // Getting required privileges
 
	if (pidOwner == NULL) // No owner PID for the handle specified, assuming we are looking for a handle belonging to this program
		pidOwner = GetCurrentProcessId();
 
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID buffer = NULL;
	ULONG buffersize = 0;
	while (true) {
		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SYSTEMHANDLEINFORMATION, buffer, buffersize, &buffersize);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				if (buffer != NULL)
					VirtualFree(buffer, 0, MEM_RELEASE);
				buffer = VirtualAlloc(NULL, buffersize, MEM_COMMIT, PAGE_READWRITE);
			}
			continue;
		}
		else
			break;
	}
 
	// Enumerate all handles on system
	PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
 
	PVOID buffer2 = NULL;
	ULONG buffersize2 = 0;
	for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO Handle = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleInfo->Handles[i];
		if (!Handle)
			continue; // Error, no handle
		if (!Handle->HandleValue)
			continue; // Error, empty handle value
		if (Handle->UniqueProcessId != pidOwner)
			continue; // The handle doesn't belong to the owner we target
 
		HANDLE localHandle = (HANDLE)Handle->HandleValue;
		if (pidOwner != GetCurrentProcessId()) { // Only if trying to get handle from another process (OpenProcess + DuplicateHandle)
			HANDLE hProcessHandleOwner = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pidOwner);
			//BOOL dupStatus = DuplicateHandle(hProcessHandleOwner, HANDLE(Handle->HandleValue), GetCurrentProcess(), &localHandle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0); // Can do with normal method instead of using native function
			NTSTATUS dupStatus = NtDuplicateObject(hProcessHandleOwner, HANDLE(Handle->HandleValue), GetCurrentProcess(), &localHandle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0);
			CloseHandle(hProcessHandleOwner);
			if (dupStatus != 0)
				continue; // Couldn't get a handle to get info, will not be able to define if it is a handle to our process, exiting
		}
 
		int trys = 0;
		while (true) {
			if (trys == 20)
				break;
			trys += 1;
 
			/* In rare cases, when a handle has been closed between the snapshot and this NtQueryObject, the handle is not valid at that line.
			This is problematic in system processes with a strict handle policy and can result in process termination, forcing a reboot (Windows 8+) or a BSOD (Windows 7)
			Note that this is not problematic in classic processes. */
			status = NtQueryObject(localHandle, ObjectTypeInformation, buffer2, buffersize2, &buffersize2); // Return objecttypeinfo into buffer
			if (!NT_SUCCESS(status)) {
				if (buffer2 != NULL)
					VirtualFree(buffer2, 0, MEM_RELEASE); // If buffer filled with anything, but call didnt succeed, assume its bullshit, so clear it
				buffer2 = VirtualAlloc(NULL, buffersize2, MEM_COMMIT, PAGE_READWRITE); // Allocate with new mem
			}
			else {
				if (wcsncmp(((POBJECT_TYPE_INFORMATION)buffer2)->TypeName.Buffer, L"Process", ((POBJECT_TYPE_INFORMATION)buffer2)->TypeName.Length + 1) == 0) {
					wchar_t process[MAX_PATH];
					if (GetModuleFileNameExW(localHandle, NULL, process, MAX_PATH)) {
						std::wstring processname = process;
						int pos = processname.find_last_of(L"\\");
						processname = processname.substr(pos + 1, processname.length());
						if (processname == targetProcessName) {
							HANDLE handleFound = (HANDLE)Handle->HandleValue;
							VirtualFree(buffer, 0, MEM_RELEASE); // Cleanup to avoid leaks
							VirtualFree(buffer2, 0, MEM_RELEASE);
							if (pidOwner != GetCurrentProcessId())
								CloseHandle(localHandle);
							SetPrivilege(SE_DEBUG_NAME, FALSE); // Removing special privileges to avoid detection vectors
							return handleFound; // TODO: Improve by returning a vector of handles, there might be several with different access rights
						}
						else
							break;
					}
				}
				else
					break;
			}
		}
		if (Handle->UniqueProcessId != GetCurrentProcessId())
			CloseHandle(localHandle); // Cleanup
		continue;
	}
	VirtualFree(buffer, 0, MEM_RELEASE); // Empties buffers to avoid memory leaks
	VirtualFree(buffer2, 0, MEM_RELEASE); // Empties buffers to avoid memory leaks
	SetPrivilege(SE_DEBUG_NAME, FALSE);
	return (HANDLE)0x0;
}
 
// Function provided by  @etc thanks for finding the solution and providing the source !!
bool SetPrivilege(LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	BOOL Status = true;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		Status = false;
		goto EXIT;
	}
	if (!LookupPrivilegeValueW(0, lpszPrivilege, &luid)) {
		Status = false;
		goto EXIT;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Luid = luid;
	priv.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if (!AdjustTokenPrivileges(hToken, false, &priv, 0, 0, 0)) {
		Status = false;
		goto EXIT;
	}
EXIT:
	if (hToken)
		CloseHandle(hToken);
	return Status;
}
```


spinlock.asm:

>To add and include an assembly file for compiling, right click your project in Visual Studio, then go on Build Dependencies and click Build Customizations. Tick the checkbox "masm(.targets, .props) and click OK. Right click Source Files in your project, Add, New Item. Select C++ File and name it "spinlock.asm" and click Add. Right click spinlock.asm in the Source Files, click Properties. Set "Excluded from Build" to No, and set "Item Type" to "Microsoft Macro Assembler

Code:
```C++
.code
 
SpinLockByte proc
SpinLock:
	pause ; tells the CPU we're spinning
	cmp dl, [rcx]
	jnz SpinLock
	ret
SpinLockByte endp
 
end
```
# Usage:

Integrate it in your cheat to do the read and write operations.
Initialise the bypass with the Init and GetHandle functions.
The following code is an example that connects the installed bypass, gets a handle to the game process "DayZ_x64.exe" then reads the value of the pointer to world:

code:
```C++
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
```
THANKS for being still here to read this, it was a really tough project that forced me to learn  alot of things but it has great use and sharing it to everyone and trying to
simplify it was very fun. Use those technique wisely. I must warn you i do not support any kind of cheating and my bypass wil be exposed in a few week and then will probably don't work anymore, don't cheat guys it's not worth it.
