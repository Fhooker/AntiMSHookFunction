//
//  AntiMSHook.h
//  AntiMSHook
//
//  Created by jintao on 2019/9/17.
//  Copyright © 2019 jintao. All rights reserved.
//

#ifndef AntiMSHookFunctionARM_h
#define AntiMSHookFunctionARM_h

#include <stdio.h>

_Bool MSHookARMCheck(void *symbol_addr);
void* antiMSHook(void *orig_addr);

#endif /* AntiMSHook_h */
