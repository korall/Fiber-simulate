// Fiber thread.cpp 
//
// rulary

#include <conio.h>
#include <Windows.h>
#include <iostream>


//һЩ����

#define MAX_FIBER_NUM           10
#define MAX_FIBER_STACK_SIZE    0x4000

//�˳����̵�ԭ��
typedef DWORD(*LPFFIBER_ROUTING)(LPVOID);

//#region �˳̿��ƽṹ����
#pragma pack(1)
//������ջ֡
struct _EBPFram{
    DWORD   dwEBP;					//ebp ջָ֡��(һ��ָ����һ��ջ֡)
    LPVOID  lpReAddress;           //�������ص�ַ
    LPVOID  lpArg1;                  //�����Ǻ�������(�����������ʾ������Ӳ�������ĸ�����,һ�㺯�����ĸ�����Ҳ������)
    LPVOID  lpArg2;
    LPVOID  lpArg3;
    LPVOID  lpArg4;
};

//�˳̵�ջ֡���ڽ����˳̵�ʱ��ʹ��
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

// ˫������
struct _DLink{
    _DLink *lpLast;
    _DLink *lpNext;
};

//�˳̵������Ľṹ���л��˳̵�ʱ��ʹ��
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


// WinNT ��TCB �ṹ������֧�� SEH ��(����TCP�ṹ��SEH �ɲο����Ʊ��Win32���)
struct _TCB{
    LPVOID lpSEHLinkHead;
    LPVOID lpThreadStackTop;
    LPVOID lpThreadStackBottom;

    // others ...
};

//#endregion

//һЩ������ǰ������

// dwId ��Ҫ�л���ȥ���˳�ID,��������λ��λ�����ñ�ʾ��SwitchToFiber�Զ�Ѱ��
// һ�����ʵ��˳����л���Ĭ��-1����λ��λ
DWORD RiSwitchToFiber(DWORD dwId = -1);


DWORD RiCreateFiber(LPFFIBER_ROUTING lpfNewFiberProc, LPVOID lpFiberParam);
VOID  RiExitFiber(DWORD dwExitCode);

DWORD RiGetCurrentFiberId();

//˫������ĳ�Ա������Cʽ��
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
*ȫ�ֱ���,��ʵ��Щ����Ӧ�÷����̵߳ı��ش洢֮�У�
*�����߳���صģ����Ƕ����ڸ��̵߳������˳���˵��
*��Щ�����ǹ��õġ���������������ȫ�ֱ���֮��
**/
BOOL g_bIsFiberMode = FALSE;
_FiberContext g_FiberData[MAX_FIBER_NUM] = { 0 };
_FiberContext *g_lpLiveList = NULL;		//��ǰ�ɵ����˳�����
_FiberContext *g_lpDieList = NULL;		//�Ѿ����ɵ��ȵ��˳��б������ڻ���

DWORD g_dwCurrentFiberId = 0;


DWORD __stdcall RiFiberException(){
    return EXCEPTION_EXECUTE_HANDLER;
}

//Ϊ�˳̲���һ�������쳣����
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

    //������������ٷ���
    RiExitFiber(dwReVal);
}

//�˺�������ֻ�����˳�ջ��ѹ��һ������ֵ��ƽ��ջ֡,����û��ѹ������� call RiFiberWrap �Ե��е��
//Ϊʲô��Ҫѹ��һ�����ص�ַ�أ���ΪRiFiberStartThunk ����RiSwapContext����ʱ��ʼִ�еģ������˳�
//ջ�ϵķ��ص�ַ��ʵ�Ѿ���RiSwapContext�����Ե��ˣ����벹��ȥ
void  _declspec (naked)RiFiberStartThunk(){
    __asm{
        call RiFiberWrap
    }
}

DWORD RiCreateFiber(LPFFIBER_ROUTING lpfNewFiberProc, LPVOID lpFiberParam){
    if (!g_bIsFiberMode)
        return -1;

    DWORD dwFiberId = -1;

    //���ȷ���һ���˳������Ľṹ�������Ǵ� g_lpDieList ������ժһ������������еĻ���
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

    // ���g_lpDieList ������û����Դ����� g_FiberData �в��ҷ���
    if (-1 == dwFiberId){
        for (int i = 1; i<MAX_FIBER_NUM; i++){
            if (!g_FiberData[i].lpStackMemBase){
                dwFiberId = i;
                break;
            }
        }

        if (-1 == dwFiberId)
            return dwFiberId;		//û���ҵ���Դ

        //�����ʼ���˳������Ľṹ
        //������Ϊ�˳�ջ��ϵͳ�����ڴ���Դ
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

    g_FiberData[dwFiberId].dwFiberState = 1;			//�˳̵���״̬
    g_FiberData[dwFiberId].dwFiberId = dwFiberId;		//�˳�ID
    g_FiberData[dwFiberId].lpSEHStack = &g_FiberData[dwFiberId].lpNextHandler;		//SEH
    g_FiberData[dwFiberId].lpNextHandler = (LPVOID)-1;
    g_FiberData[dwFiberId].lpFiberExceptionTopHandler = &RiFiberException;

    //��ʼ���˳�ջ
    _FiberStackFram *lpStackFram = g_FiberData[dwFiberId].lpStackFram;

    lpStackFram->dwEBP = (DWORD)&lpStackFram->dwEBPFram;
    lpStackFram->lpFiberStartAddr = &RiFiberStartThunk;
    lpStackFram->lplpParam[0] = lpfNewFiberProc;
    lpStackFram->lplpParam[1] = lpFiberParam;

    //������������ȴ�����
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

//��CPUƽ̨�ϵ��л�ʵ�ֺ����������еĺ���
// lpNewContext : Ҫ�л���ȥ���˳�������
// lpCurrContext : ��ǰ�˳�������
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

//�˳̵����л�������ʵ���˳̻��Ƶĺ���
DWORD RiSwitchToFiber(DWORD dwId/* = -1*/){
    //::Sleep(20);

    if (!g_bIsFiberMode)
        return -1;

    if (dwId == g_dwCurrentFiberId)
        return 0;

    if (dwId > 0x10000000){		//Ѱ��һ�����ʵ��˳�

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
        g_lpLiveList = &g_FiberData[0];		//g_FiberData[]��һ��ֵ����"���˳�"
        g_lpLiveList->lpLast = g_lpLiveList->lpNext = g_lpLiveList;
        g_lpLiveList->dwFiberId = 0;
        g_lpLiveList->dwFiberState = 1;
        g_lpLiveList->lpSEHStack = &g_lpLiveList->lpNextHandler;		//SEH�쳣ջ
        g_lpLiveList->lpNextHandler = (LPVOID)-1;
        g_lpLiveList->lpFiberExceptionTopHandler = &RiFiberException;		//ûʲô��
        g_bIsFiberMode = TRUE;

        //����û��Ϊ���˳�����ջ�ڴ�ͳ�ʼ��ջ������Ϊ���˳̽������̵߳�ջ��
        //�ڵ�һ�������л������ĵ�ʱ���߳�ջ�������浽�˳̵���������
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

// һ���˳����̣��˳�ʹ�õ���ʾ
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


//��һ���˳�����
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
        RiSwitchToFiber(); //�˳̵ĵ��ȣ���Ȼ�����ֶ���
    }

    //����SEH�쳣�ܷ�ʹ��
    __try{
        int i = 0;
        i = i / i;
    }
    __except (EXCEPTION_EXECUTE_HANDLER){
        std::cout << "SEH exception catch in FiberProc[" << RiGetCurrentFiberId() << "]!" << std::endl;
    }

    std::cout << "Fiber:[" << RiGetCurrentFiberId() << "] end!!" << std::endl;

    //����C++�쳣
    TryCppExceptionInFiberPro();
    RiExitFiber(0);
    return 0;
}


// test 
int _tmain(int argc, _TCHAR* argv[])
{
    // ����ĵ�һ��
    // �����߳�ת��Ϊ�˳̣�����ɹ�����ôConvertToFiber����ʱ�����߳�
    // ���Ѿ����뵽���˳�ģʽ֮�У����������˳̡�
    // ������ǰֻ��һ���˳�������
    if (!RiConvertToFiber()){
        std::cout << "ConverToFiber failed!" << std::endl;
        _getch();
        return 0;
    }

    //��Ϊֻ��һ���˳̣�����SwitchToFiber��ʵʲôҲ����
    RiSwitchToFiber();

    // ����C++�쳣�����Ƿ�����
    try{
        throw 0;
    }
    catch (...){
        std::cout << "C++ exception catch!" << std::endl;
    }

    //����һ���˳�
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

    // ����C++�쳣�����Ƿ�����
    try{
        throw 0;
    }
    catch (...){
        std::cout << "C++ exception catch2!" << std::endl;
    }

    _getch();
    return 0;
}