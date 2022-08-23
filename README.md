# AntiInlineHook

用于对抗常见的inline hook，使其失效

测试了substitute，libhooker，DobbyHook

  
 include `AntiInlineHook_arm64.h`


## Usage 

```c

#if defined(__arm64__) || defined(__arm64e__)
#include "AntiInlineHook/AntiInlineHook_arm64.h"

void antiDebug(void) {
    extern int ptrace(int, pid_t, int, int);
    
    void* real_ptrace = antiInlineHook((void *)ptrace);
    typedef int Ptrace(int, pid_t, int, int);
    Ptrace *_ptrace = (Ptrace *)real_ptrace;
    _ptrace(31, 0, 0, 0);
}
#endif

```

## TODO

- Add armv7 support
- Add support for "DobbyInstructment()" and frida
 
 ## Credits

- TannerJin - [AntiMSHookFunction](https://github.com/TannerJin/AntiMSHookFunction)
- iOSSecuritySuite - [MSHookFunctionChecker.swift](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/MSHookFunctionChecker.swift)

