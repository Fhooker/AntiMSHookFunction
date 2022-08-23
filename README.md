# AntiMSHookFunction


AntiMSHookFunction is an AntiHook library for MSHookFunction at runtime (make MSHookFunction doesn't work)    
include `AntiMSHookFunctionARM64.h`

[Swift-Version](https://github.com/TannerJin/IOSSecuritySuite/blob/master/IOSSecuritySuite/MSHookFunctionChecker.swift)(latest version)

## Usage 

```c

#if defined(__arm64__) || defined(__arm64e__)
#include "AntiMSHookFunction/AntiMSHookFunctionARM64.h"

void antiDebug(void) {
    extern int ptrace(int, pid_t, int, int);
    
    void* real_ptrace = antiMSHook((void *)ptrace);
    typedef int Ptrace(int, pid_t, int, int);
    Ptrace *_ptrace = (Ptrace *)real_ptrace;
    _ptrace(31, 0, 0, 0);
}
#endif

```

## TODO

 Add support for "DobbyInstructment()" and frida