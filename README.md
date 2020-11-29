# Shh0yaKernelHook
Shh0ya Kernel Hook Driver

19041 이상의 경우 PDE에 Write 가 없습니다.
그래서 MiGetPdeAddress를 이용하여 후킹하고자 하는 함수의 PDE를 찾고, 이를 수정합니다.
DebugMode+DSE 에서는 동작하지만 일반 모드에서는 후킹이 되지 않습니다.
연구 중입니다.
일반 모드에서도 PDE의 권한은 잘 바뀌는데 왜 안될까...

현재 진행 된 연구 사항으로는,

DebugMode + DSE 모드에서도 inline hooking 코드를 실행 시, `page_fault_in_nonpaged_area` 가 발생한다.
이 때, PDE의 Write 비트 플래그를 Set 해주면 후킹이 가능하다.
하지만 일반 모드에서는 같은 작업을 해도 `page_fault_in_nonpaged_area` 가 발생한다.

왜죠?
