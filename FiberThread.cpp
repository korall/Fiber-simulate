// Fiber thread.cpp 
//
// rulary

#include <conio.h>
#include <Windows.h>
#include <iostream>


//一些常数

#define MAX_FIBER_NUM           10
#define MAX_FIBER_STACK_SIZE    0x4000

//纤程例程的原型
typedef DWORD(*LPFFIBER_ROUTING)(LPVOID);

//#region 纤程控制结构定义
#pragma pack(1)
//函数的栈帧
struct _EBPFram{
    DWORD   dwEBP;					//ebp 栈帧指针(一般指向下一个栈帧)
    LPVOID  lpReAddress;           //函数返回地址
    LPVOID  lpArg1;                  //以下是函数参数(这里仅仅是演示，所以硬编码了四个参数,一般函数有四个参数也够用了)
    LPVOID  lpArg2;
    LPVOID  lpArg3;
    LPVOID  lpArg4;
};

//纤程的栈帧，在建立纤程的时候使用
struct _FiberStackFram{
    DWORD  dwFlagReg;

    DWORD  dwEDI;
    DWORD  dwESI;
    DWORD  dwEBP;
    DWORD  dwEBX;
    DWORD  dwEDX;
    DWORD  dwECX;
    DWORD  dwEAX;

    DWORD  dwEBPFram;

    union{
        LPVOID lpReAddr;
        LPVOID lpFiberStartAddr;
    };

    LPVOID lplpParam[2];
};

// 双向链表
struct _DLink{
    _DLink *lpLast;
    _DLink *lpNext;
};

//纤程的上下文结构，切换纤程的时候使用
struct _FiberContext{
    union{
        _DLink link;
        struct{
            _FiberContext *lpLast;
            _FiberContext *lpNext;
        };
    };
    DWORD  dwFiberId;
    LPVOID lpStackTop;
    union{
        DWORD  dwESP;
        LPVOID lpStackMem;
        _FiberStackFram *lpStackFram;
    };
    LPVOID lpStackMemBase;
    LPVOID lpSEHStack;
    DWORD  dwExitCode;
    DWORD  dwFiberState;

    LPVOID lpNextHandler;
    LPVOID lpFiberExceptionTopHandler;
};


// WinNT 的TCB 结构，用于支持 SEH 。(关于TCP结构和SEH 可参考罗云彬的Win32编程)
struct _TCB{
    LPVOID lpSEHLinkHead;
    LPVOID lpThreadStackTop;
    LPVOID lpThreadStackBottom;

    // others ...
};

//#endregion

//一些函数的前置声明

// dwId ：要切换过去的纤程ID,如果其最高位置位，则让表示让SwitchToFiber自动寻找
// 一个合适的纤程来切换，默认-1即高位置位
DWORD RiSwitchToFiber(DWORD dwId = -1);


DWORD RiCreateFiber(LPFFIBER_ROUTING lpfNewFiberProc, LPVOID lpFiberParam);
VOID  RiExitFiber(DWORD dwExitCode);

DWORD RiGetCurrentFiberId();

//双向链表的成员函数，C式的
void Dlink_InsertHead(_DLink &target, _DLink &obj){
    obj.lpLast = &target;
    obj.lpNext = target.lpNext;
    target.lpNext->lpLast = &obj;
    target.lpNext = &obj;
}

void Dlink_InsertTail(_DLink &target, _DLink &obj){
    obj.lpNext = &target;
    obj.lpLast = target.lpLast;
    target.lpLast->lpNext = &obj;
    target.lpLast = &obj;
}

void Dlink_Remove(_DLink &obj){
    if (obj.lpNext == &obj && obj.lpLast == obj.lpNext)
        return;

    obj.lpLast->lpNext = obj.lpNext;
    obj.lpNext->lpLast = obj.lpLast;

    obj.lpLast = obj.lpNext = &obj;
}


/*
*全局变量,其实这些变量应该放在线程的本地存储之中，
*即是线程相关的，但是对属于该线程的所有纤程来说，
*这些变量是共用的。这里简单起见，置于全局变量之中
**/
BOOL g_bIsFiberMode = FALSE;
_FiberContext g_FiberData[MAX_FIBER_NUM] = { 0 };
_FiberContext *g_lpLiveList = NULL;		//当前可调度纤程链表
_FiberContext *g_lpDieList = NULL;		//已经不可调度的纤程列表，仅用于缓冲

DWORD g_dwCurrentFiberId = 0;


DWORD __stdcall RiFiberException(){
    return EXCEPTION_EXECUTE_HANDLER;
}

//为纤程布置一个顶层异常处理
void  __stdcall RiFiberWrap(LPFFIBER_ROUTING lpfFiberProc, LPVOID lpParam){
    DWORD dwReVal = -1;

    //std::cout<<"start Fiber !"<< std::endl;
    __try{
        dwReVal = lpfFiberProc(lpParam);
    }
    __except (RiFiberException()/*EXCEPTION_EXECUTE_HANDLER*/){
        std::cout << "Fiber stop in exception!" << std::endl;
    }
    //std::cout<<"Fiber stop:["<<dwReVal<<"]!"<< std::endl;

    //这个函数将不再返回
    RiExitFiber(dwReVal);
}

//此函数仅仅只是在纤程栈中压入一个返回值，平衡栈帧,所以没有压入参数的 call RiFiberWrap 显得有点怪
//为什么需要压入一个返回地址呢？因为RiFiberStartThunk 是在RiSwapContext返回时开始执行的，所以纤程
//栈上的返回地址其实已经被RiSwapContext函数吃掉了，必须补回去
void  _declspec (naked)RiFiberStartThunk(){
    __asm{
        call RiFiberWrap
    }
}

DWORD RiCreateFiber(LPFFIBER_ROUTING lpfNewFiberProc, LPVOID lpFiberParam){
    if (!g_bIsFiberMode)
        return -1;

    DWORD dwFiberId = -1;

    //首先分配一个纤程上下文结构，这里是从 g_lpDieList 链表里摘一个出来，如果有的话；
    _FiberContext *lpListWalk = g_lpDieList;
    if (lpListWalk){
        do{
            if (lpListWalk->lpStackMemBase){
                dwFiberId = lpListWalk->dwFiberId;
                Dlink_Remove(lpListWalk->link);
                break;
            }
            lpListWalk = lpListWalk->lpNext;
        } while (lpListWalk != g_lpDieList);
    }

    // 如果g_lpDieList 链表里没有资源，则从 g_FiberData 中查找分配
    if (-1 == dwFiberId){
        for (int i = 1; i<MAX_FIBER_NUM; i++){
            if (!g_FiberData[i].lpStackMemBase){
                dwFiberId = i;
                break;
            }
        }

        if (-1 == dwFiberId)
            return dwFiberId;		//没有找到资源

        //下面初始化纤程上下文结构
        //首先是为纤程栈向系统申请内存资源
        if (!g_FiberData[dwFiberId].lpStackMemBase)
            g_FiberData[dwFiberId].lpStackMemBase = VirtualAlloc(NULL, MAX_FIBER_STACK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (g_FiberData[dwFiberId].lpStackMemBase){
            g_FiberData[dwFiberId].lpStackMem = &((BYTE*)g_FiberData[dwFiberId].lpStackMemBase)[MAX_FIBER_STACK_SIZE - sizeof(_FiberStackFram)-8];
            g_FiberData[dwFiberId].lpStackTop = &((BYTE*)g_FiberData[dwFiberId].lpStackMemBase)[MAX_FIBER_STACK_SIZE];
        }
        else{
            dwFiberId = -1;
        }
    }

    if (-1 == dwFiberId)
        return dwFiberId;

    g_FiberData[dwFiberId].dwFiberState = 1;			//纤程调度状态
    g_FiberData[dwFiberId].dwFiberId = dwFiberId;		//纤程ID
    g_FiberData[dwFiberId].lpSEHStack = &g_FiberData[dwFiberId].lpNextHandler;		//SEH
    g_FiberData[dwFiberId].lpNextHandler = (LPVOID)-1;
    g_FiberData[dwFiberId].lpFiberExceptionTopHandler = &RiFiberException;

    //初始化纤程栈
    _FiberStackFram *lpStackFram = g_FiberData[dwFiberId].lpStackFram;

    lpStackFram->dwEBP = (DWORD)&lpStackFram->dwEBPFram;
    lpStackFram->lpFiberStartAddr = &RiFiberStartThunk;
    lpStackFram->lplpParam[0] = lpfNewFiberProc;
    lpStackFram->lplpParam[1] = lpFiberParam;

    //插入调度链表，等待调度
    Dlink_InsertTail(g_lpLiveList->link, g_FiberData[dwFiberId].link);

    return dwFiberId;
}

VOID  RiExitFiber(DWORD dwExitCode){

    if (0 == g_dwCurrentFiberId)
        return;

    std::cout << "Fiber [" << RiGetCurrentFiberId() << "] exit!!" << std::endl;
    g_FiberData[g_dwCurrentFiberId].dwExitCode = dwExitCode;
    g_FiberData[g_dwCurrentFiberId].dwFiberState = -1;

    if (g_lpLiveList == &g_FiberData[g_dwCurrentFiberId]){
        g_lpLiveList = g_FiberData[g_dwCurrentFiberId].lpNext;
    }

    Dlink_Remove(g_FiberData[g_dwCurrentFiberId].link);

    if (!g_lpDieList){
        g_lpDieList = &g_FiberData[g_dwCurrentFiberId];
        g_lpDieList->lpLast = g_lpDieList->lpNext = g_lpDieList;
    }
    else{
        Dlink_InsertTail(g_lpDieList->link, g_FiberData[g_dwCurrentFiberId].link);
    }

    RiSwitchToFiber();
}

DWORD RiGetCurrentFiberId(){
    return g_dwCurrentFiberId;
}

//在CPU平台上的切换实现函数，核心中的核心
// lpNewContext : 要切换过去的纤程上下文
// lpCurrContext : 当前纤程上下文
void _declspec (naked)RiSwapContext(_FiberContext *lpNewContext, _FiberContext *lpCurrContext){
    __asm{
        push ebp
            mov  ebp, esp

            pushad
            pushfd

            mov  eax, dword ptr[ebp]_EBPFram.lpArg2       //lpCurrContext
            push esp
            pop[eax]_FiberContext.dwESP
            xor  ebx, ebx
            push dword ptr fs : [ebx]_TCB.lpSEHLinkHead
            pop[eax]_FiberContext.lpSEHStack
            push dword ptr fs : [ebx]_TCB.lpThreadStackTop
            pop[eax]_FiberContext.lpStackTop
            push dword ptr fs : [ebx]_TCB.lpThreadStackBottom
            pop[eax]_FiberContext.lpStackMemBase


            mov  eax, dword ptr[ebp]_EBPFram.lpArg1       //lpNewContext
            push[eax]_FiberContext.dwESP
            pop  esp
            push[eax]_FiberContext.lpSEHStack
            pop  dword ptr fs : [ebx]_TCB.lpSEHLinkHead
            push[eax]_FiberContext.lpStackTop
            pop  dword ptr fs : [ebx]_TCB.lpThreadStackTop
            push[eax]_FiberContext.lpStackMemBase
            pop  dword ptr fs : [ebx]_TCB.lpThreadStackBottom

            popfd
            popad

            leave
            retn
    }
}

//纤程调度切换函数，实现纤程机制的核心
DWORD RiSwitchToFiber(DWORD dwId/* = -1*/){
    //::Sleep(20);

    if (!g_bIsFiberMode)
        return -1;

    if (dwId == g_dwCurrentFiberId)
        return 0;

    if (dwId > 0x10000000){		//寻找一个合适的纤程

        bool bIsFound = false;
        DWORD dwNextFiber = 0;

        _FiberContext *lpListWalk = g_lpLiveList;
        do{
            if (lpListWalk->dwFiberId != g_dwCurrentFiberId
                && lpListWalk->dwFiberState < 0x10000000){
                dwNextFiber = lpListWalk->dwFiberId;
                bIsFound = true;
                break;
            }
            lpListWalk = lpListWalk->lpNext;

        } while (lpListWalk != g_lpLiveList);

        if (bIsFound){
            DWORD dwTemp = g_dwCurrentFiberId;
            g_dwCurrentFiberId = dwNextFiber;
            g_lpLiveList = &g_FiberData[dwNextFiber];
            RiSwapContext(&g_FiberData[dwNextFiber], &g_FiberData[dwTemp]);
        }
    }
    else if (dwId < MAX_FIBER_NUM &&
        g_FiberData[dwId].lpStackMem != NULL  &&
        g_FiberData[dwId].dwFiberState < 0x10000000){

        DWORD dwTemp = g_dwCurrentFiberId;
        g_dwCurrentFiberId = dwId;
        RiSwapContext(&g_FiberData[dwId], &g_FiberData[dwTemp]);
    }
    else{
        return -1;
    }

    return 0;
}

BOOL RiConvertToFiber(){
    if (!g_bIsFiberMode){
        g_lpLiveList = &g_FiberData[0];		//g_FiberData[]第一个值总是"主纤程"
        g_lpLiveList->lpLast = g_lpLiveList->lpNext = g_lpLiveList;
        g_lpLiveList->dwFiberId = 0;
        g_lpLiveList->dwFiberState = 1;
        g_lpLiveList->lpSEHStack = &g_lpLiveList->lpNextHandler;		//SEH异常栈
        g_lpLiveList->lpNextHandler = (LPVOID)-1;
        g_lpLiveList->lpFiberExceptionTopHandler = &RiFiberException;		//没什么用
        g_bIsFiberMode = TRUE;

        //这里没有为主纤程申请栈内存和初始化栈，是因为主纤程将重用线程的栈。
        //在第一次真正切换上下文的时候，线程栈将被保存到纤程的上下文中
    }
    return g_bIsFiberMode;
}

void TryCppExceptionInFiberPro()
{
    try
    {
        throw RiGetCurrentFiberId();
    }
    catch (...)
    {
        std::cout << "C++ exception catch in FiberProc[" << RiGetCurrentFiberId() << "]!" << std::endl;
    }
}

// 一个纤程例程，纤程使用的演示
DWORD FiberProc1(LPVOID lpParam){
    std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] running!! lpParam = " << lpParam << std::endl;

    float fTemp = 1.0f;

    int iCount = 50;
    while (true){
        fTemp += iCount * 1.0f;

        std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] yield!! fTemp = " << fTemp << std::endl;
        RiSwitchToFiber();

        if (iCount-- <= 0)
            break;
    }

    std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] end!!" << std::endl;
    return 0;
}


//另一个纤程例程
DWORD FiberProc2(LPVOID lpParam){
    std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] running!! lpParam = " << lpParam << std::endl;

    RiCreateFiber(FiberProc1, (LPVOID)4);
    RiCreateFiber(FiberProc1, (LPVOID)3);
    RiCreateFiber(FiberProc1, (LPVOID)2);
    RiCreateFiber(FiberProc1, (LPVOID)5);

    float fTemp = 1.0f;

    int iCount = 50;
    while (iCount-- > 0){
        fTemp += iCount * 1.0f;

        std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] yield!! fTemp = " << fTemp << std::endl;
        RiSwitchToFiber(); //纤程的调度，当然，是手动的
    }

    //测试SEH异常能否使用
    __try{
        int i = 0;
        i = i / i;
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
        std::cout << "SEH exception catch in FiberProc[" << RiGetCurrentFiberId() << "]!" << std::endl;
    }

    std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] end!!" << std::endl;

    //测试C++异常
    TryCppExceptionInFiberPro();
    RiExitFiber(0);
    return 0;
}


// test 
int _tmain(int argc, _TCHAR* argv[])
{
    // 必须的第一步
    // 将本线程转换为纤程，如果成功，那么ConvertToFiber返回时，本线程
    // 就已经进入到了纤程模式之中，并且是主纤程。
    // 不过当前只有一个纤程在运行
    if (!RiConvertToFiber()){
        std::cout << "ConverToFiber failed!" << std::endl;
        _getch();
        return 0;
    }

    //因为只有一个纤程，所以SwitchToFiber其实什么也不干
    RiSwitchToFiber();

    // 测试C++异常处理是否正常
    try{
        throw 0;
    }
    catch (...){
        std::cout << "C++ exception catch!" << std::endl;
    }

    //建立一个纤程
    DWORD dwFiberId = RiCreateFiber(FiberProc2, (LPVOID)1);

    _getch();
    //.....
    RiSwitchToFiber();

    int iCount = 60;
    while (true){
        std::cout << "Fiber:[00000000] yield!" << std::endl;
        RiSwitchToFiber();
        if (iCount-- <= 0)
            break;
    }

    std::cout << "Fiber:[00000000] end!" << std::endl;

    RiSwitchToFiber();

    // 测试C++异常处理是否还正常
    try{
        throw 0;
    }
    catch (...){
        std::cout << "C++ exception catch2!" << std::endl;
    }

    _getch();
    return 0;
}