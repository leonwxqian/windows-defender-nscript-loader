// wLoadMpEngine.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include "DETOUR/detours.h"

#include "engineboot.h"
#include "openscan.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "rsignal.h"


#include <windows.h>
#include <windns.h>
#include <iostream>
#include <iosfwd>
#include <streambuf>
#include <fstream>
#include <string>
#include <Tlhelp32.h>

BYTE x86_strtod[] = {0x8b, 0xff, 0x55, 0x8b, 0xec, 0x6a, 0x00, 0xff, 0x75, 0x0c, 0xff, 0x75, 0x08, 0xe8, 0xc2, 0xf8, 0xff, 0xff, 0x83, 0xc4, 0x0c, 0x5d, 0xc3};
DWORD dwStrTodLen = 23; //x86_strtod length
/*
	@modified based on:  
	@original author  : Tavis Ormandy
						https://github.com/taviso/loadlibrary  (GPLv2)

	@writtenby    :   Wenxiang Qian (aka `blastxiang`)
	@email        :   leonwxqian@gmail.com
	@website      :   http ://nul.pw
	@licence      :   GPLv2

*/

//1. GetModuleHandle()
//2. specify starting address and ending address.
//3. find x86_strtod
//4. calc jump diff
//5. jump it into the very first byte of our logging func.


const char header[] =
"function log(msg) { parseFloat('__log: ' + msg); }\n"
"function dump(obj) { for (i in obj) { log(i); log('\\t' + obj[i]); }; }\n";

//javascript that triggers scanning
//const char footer[] = { 0x00
 //read javascript.txt now...
//};

typedef DWORD (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);
typedef double (* __rlog)(const char *nptr, char **endptr);

PVOID FindBeginOfData(PVOID data1, DWORD dwSize)
{
    DWORD i = 0;
    PVOID data2 = x86_strtod;
    for(; i < dwSize; i++)
    {
        if (*((PBYTE)data1 + i) != 0x8b)
        {
            continue; //jumps over the nothing bytes.s
        }
        if (memcmp((PVOID)((PBYTE)data1 + i), data2, dwStrTodLen) != 0)
        {
            continue;
        }
        else
        {
            return (PVOID)((PBYTE)data1 + i);
        }
        
    }
    
    return NULL;
}


double __cdecl JavaScriptLog(const char *nptr, char **endptr)
{
    if (strncmp(nptr, "__log: ", 7) == 0) {
        std::cout << "evaluation result: ";
        std::cout << nptr + 7 << std::endl;
        return 0;
    }
    return strtod(nptr, endptr);
}

void PatchFunction(PVOID pAddr)
{
    PVOID pDestAddr = &JavaScriptLog;

    BYTE x86_replace[] = {0xe9, 0x00, 0x00, 0x00, 0x00};

    DWORD dwDelta = (DWORD)pDestAddr - (DWORD)pAddr - 5;

    memcpy(&x86_replace[1], &dwDelta, 4);



    DWORD dwOldProtect;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(pAddr, &mbi, sizeof(mbi));
    VirtualProtect(pAddr, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    ::WriteProcessMemory(::GetCurrentProcess(), 
        pAddr, &x86_replace, 5 /*sizeof long jump*/, NULL);

    //VirtualProtect(pAddr, 5, dwOldProtect, 0);

}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    return 0;
}

static DWORD ReadStream(PVOID t, QWORD Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    DWORD sl = strlen((PCHAR)t + Offset);
    *SizeRead = sl< Size ? sl : Size;

    memcpy(Buffer, (PCHAR)t + Offset, *SizeRead);
    return TRUE;
}

static DWORD GetStreamSize(PVOID t, PQWORD FileSize)
{
    *FileSize = strlen((PCHAR)t);
    return TRUE;
}


DWORD GetFileSizeC(CHAR* pFileName)
{
    if (!pFileName)
    {
        return 0;
    }

    FILE * pFile;
    DWORD size;

    pFile = fopen (pFileName,"rb");
    if (pFile == NULL)
    {
        return 0;
    }
    else
    {
        fseek (pFile, 0, SEEK_END);
        size=ftell (pFile);
        fclose (pFile);
    }
    return size;
}

int _tmain(int argc, _TCHAR* argv[])
{
    PVOID StrtodPtr;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    HANDLE KernelHandle;
    SCAN_REPLY ScanReply;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;

    PVOID p = (PVOID)strtod;
    
    TlsGetValue(1);




    //DetourTransactionBegin();


    HMODULE hModule = LoadLibrary(L"mpengine.dll");
    __rsignal rs = (__rsignal)GetProcAddress(hModule, "__rsignal");
    //__rlog stod = (__rlog)GetProcAddress(hModule, "_strtod"); //todo: hook _strtod



    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);

    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.Attributes    = BOOT_ATTR_NORMAL;
    BootParams.SignatureLocation = L"engine";
    BootParams.ProductName = L"Legitimate Antivirus";
    EngineConfig.QuarantineLocation = L"quarantine";
    EngineConfig.Inclusions = L"*.*";
    EngineConfig.EngineFlags = 1 << 1;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;

    if (rs(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof(BootParams)) != 0) 
    {
        return 1;
    }


    //now we can go
/*
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h != INVALID_HANDLE_VALUE) 
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(h, &te)) 
        {
            do 
            {
                if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                    sizeof(te.th32OwnerProcessID) &&
                    
                    te.th32OwnerProcessID == GetProcessId(GetCurrentProcess())) 
                {
                        printf("Process 0x%04x Thread 0x%04x\n",
                            te.th32OwnerProcessID, te.th32ThreadID);
                        static int entering = 0;
                        if(entering++)
                        {

                            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                            SuspendThread(hThread);

                            DetourUpdateThread(hThread);  

                            DetourAttach(&(PVOID&)p, JavaScriptLog);

                            DetourTransactionCommit();  

                            ResumeThread(hThread);

                            CloseHandle(hThread);
                        }
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(h, &te));
        }
        CloseHandle(h);
    }

   */



    PVOID pBaseAddress = (PVOID)GetModuleHandle(L"mpengine.dll");
    DWORD dwMaxSize = GetFileSizeC("../wLoadMpEngine/engine/mpengine.dll");
    PVOID pFuncAddress = FindBeginOfData((PBYTE)pBaseAddress + 0x1000, dwMaxSize - 0x1000); //now we got strtod here!!

    PatchFunction(pFuncAddress);

    ZeroMemory(&ScanParams, sizeof(ScanParams));
    ZeroMemory(&ScanDescriptor, sizeof(ScanDescriptor));
    ZeroMemory(&ScanReply, sizeof(ScanReply));

    ScanParams.Descriptor        = &ScanDescriptor;
    ScanParams.ScanReply         = &ScanReply;
    ScanReply.EngineScanCallback = EngineScanCallback;
    ScanReply.field_C            = 0x7fffffff;
    ScanDescriptor.Read          = ReadStream;
    ScanDescriptor.GetSize       = GetStreamSize;

    CHAR InputBuf[4000] = { 0 };
    while (true) {
        //CHAR *InputBuf = "var p='r';'\\x41\\x42\\x43'+p.toString();";//" readline("> ");";
        printf("\ninput:");
        gets_s(InputBuf);

        std::ifstream in("javascript.txt");
        std::string footer((std::istreambuf_iterator<char>(in)),
            std::istreambuf_iterator<char>());

        if (InputBuf) {
            CHAR *EscapeBuf = (CHAR*)calloc(strlen(InputBuf) + 1, 3);
            CHAR *p = EscapeBuf;

            if (!EscapeBuf)
                break;

            // This is probably not correct.
            for (size_t i = 0; InputBuf[i]; i++) {
                if (InputBuf[i] == '%') {
                    *p++ = '%'; *p++ = '2'; *p++ = '5';
                } else if (InputBuf[i] == '"') {
                    *p++ = '%'; *p++ = '2'; *p++ = '2';
                } else if (InputBuf[i] == '\\') {
                    *p++ = '%'; *p++ = '5'; *p++ = 'c';
                } else {
                    *p++ = InputBuf[i];
                }
            }


            //std::ifstream in("c:\\fuzzer.txt");
           // std::string fuzzer((std::istreambuf_iterator<char>(in)),
            //    std::istreambuf_iterator<char>());

            std::string miscStr = "%s\ntry{log(eval(unescape(\"%s\")))} catch(e) { log(e); }\n%s";
            ULONG ulHeaderLen = strlen(header) + 2;
            ULONG ulEscapeBuf = strlen(EscapeBuf) + 2;
            ULONG ulFooterLen = footer.length() + 2;
            ULONG ulMiscLen = miscStr.length();

            ULONG ulTotalLen = ulHeaderLen + ulEscapeBuf + ulFooterLen + ulMiscLen;
    
            ScanDescriptor.UserPtr = new (std::nothrow) CHAR[ulTotalLen];
            ZeroMemory(ScanDescriptor.UserPtr, ulTotalLen);

            if (sprintf((char*)ScanDescriptor.UserPtr,
                "%s\ntry{log(eval(unescape(\"%s\")))} catch(e) { log(e); }\n%s",
                header,
                EscapeBuf,
                footer.c_str()) == -1) {
                MessageBox(0, L"memAllocationFail!!", 0, 0);
            }

            free(EscapeBuf);
        } else {
            break;
        }

        if (rs(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof(ScanParams)) != 0) {
            //LogMessage("__rsignal(RSIG_SCAN_STREAMBUFFER) returned failure, file unreadable?");
            return 1;
        }

       // break;

       
       delete [] ScanDescriptor.UserPtr;
       ScanDescriptor.UserPtr = NULL;
    }

    return 0;
}

