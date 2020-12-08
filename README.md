# Shh0yaKernelHook
Shh0ya Kernel Hook Driver

## Hook Method

메모리 설명자 목록(Memory Descriptor List), MDL을 이용한 Kernel inline hooking 드라이버입니다.
당연히 PG(PatchGuard, KPP) 우회가 필요합니다.
서명의 경우 [Code Integrity](https://shhoya.github.io/antikernel_codeintegrity.html) 를 읽어보시면 간단한 코드로 우회할 수 있습니다.

1. `InitializeKHook`

   ```c++
   BOOLEAN InitializeKHook(
       PCWCHAR TargetName,
       PVOID   HookingFunction,
       ULONG   Size
   )
   /*
   TargetName : Routine Name. Ex) L"ExAllocatePoolWithTag"
   HookingFunction : Hook Function. Ex) ExAllocatePoolWithTag_Hook
   Size : Original instruction size
   
   48 89 5C 24 08                          mov     [rsp+arg_0], rbx
   48 89 6C 24 10                          mov     [rsp+arg_8], rbp
   48 89 74 24 18                          mov     [rsp+arg_10], rsi	//After 14 bytes of hook patch, the command is executed up to here and it is executed normally, So I need 15 bytes of the original data.
   
   57                                      push    rdi	// After Hooking function call
   41 56                                   push    r14
   41 57                                   push    r15
   48 83 EC 30                             sub     rsp, 30h
   */
   ```

2. `InitializeKHookEx`

   ```c++
   BOOLEAN InitializeKHookEx(
       PSTR BytePattern, 
       PVOID HookingFunction, 
       ULONG Size, 
       ULONG RelSize
   )
   /*
   BytePattern : Target function byte identification pattern
   
   1409B1030 48 89 5C 24 08                          mov     [rsp+arg_0], rbx
   1409B1035 48 89 6C 24 10                          mov     [rsp+arg_8], rbp
   1409B103A 48 89 74 24 18                          mov     [rsp+arg_10], rsi
   1409B103F 57                                      push    rdi
   1409B1040 41 56                                   push    r14
   1409B1042 41 57                                   push    r15
   1409B1044 48 83 EC 30                             sub     rsp, 30h
   1409B1048 65 48 8B 04 25 20 00 00+                mov     rax, gs:20h
   1409B1051 45 8B F0                                mov     r14d, r8d
   
   1409B1054 44 0F B7 3D A4 9F 34 00                 movzx   r15d, cs:KeNumberNodes <= Byte pattern that exists only in ExallocatePoolWithTag
   
   HookingFunction : Hook Function
   Size : Same as InitializeKHook
   RelSize : Size from pattern to first of target function
   
   Pattern : 1409B1054 44 0F B7 3D A4 9F 34 00
   RelSize : 1409B1054 - 1409B1030 = 0x24
   
   */
   ```

   

