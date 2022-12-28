// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdint>
#include <cstdlib>
#include <cstdio>

#include "../UnshadowedCloudmusic/monkey_bridge.h"

#define PACK(__decl__) __pragma(pack(push, 1)) __decl__; __pragma(pack(pop))

void* ptr_func_remaining;
int patched = 0;
int debug = FALSE;
const char* log_file_path = NULL;
FILE* fp = NULL;

#define LOG(__fmt__, ...) do { \
    SYSTEMTIME tm; \
    GetLocalTime(&tm); \
    fprintf(fp, "[%04d-%02d-%02d %02d:%02d:%02d, pid=%d] " __fmt__ "\n", \
        tm.wYear, tm.wMonth, tm.wDay, tm.wHour, tm.wMinute, tm.wSecond, \
        GetCurrentProcessId(), \
        __VA_ARGS__);\
    fflush(fp); \
} while(0)

PACK(struct s_jmp_rel32 {
    uint8_t opcode; // 0xe9
    uint32_t offset;
});
static_assert(sizeof(struct s_jmp_rel32) == 5, "invalid instruction length");

struct s_jmp_rel32 jmp_rel32(void* dst, void* src) {
    return { 0xe9, (uint32_t)dst - ((uint32_t)src + sizeof(struct s_jmp_rel32)) };
}

void* get_eip() {
    __asm {
        mov eax, [esp];
        ret;
    }
    return NULL;
}

const LPCWSTR nullable_str(LPCWSTR s) {
    if (s == NULL) return L"<empty>";
    return s;
}

DWORD get_pid() {
    HANDLE hProc = GetCurrentProcess();
    DWORD nPid = GetProcessId(hProc);
    return nPid;
}

// this function does not work in MSVC Debug complication mode
// may caused by stack smashing detector
HWND WINAPI proxy(
    DWORD     dwExStyle,
    LPCWSTR   lpClassName,
    LPCWSTR   lpWindowName,
    DWORD     dwStyle,
    int       X,
    int       Y,
    int       nWidth,
    int       nHeight,
    HWND      hWndParent,
    HMENU     hMenu,
    HINSTANCE hInstance,
    LPVOID    lpParam) {

    HWND ret;

    char msg[1024];
    //sprintf_s(msg, sizeof(msg), "CreateWindowExW dwExStyle=0x%X lpClassName=%ls lpWindowName=%ls dwStyle=%d X=%d Y=%d nWidth=%d nHeight=%d",
    //    dwExStyle, nullable_str(lpClassName), nullable_str(lpWindowName), dwStyle, X, Y, nWidth, nHeight);
    //MessageBoxA(0, msg, "MonkeyDLL", 0);

    //sprintf_s(msg, sizeof(msg), "CreateWindowExW dwExStyle=0x%X dwStyle=%d",
    //    dwExStyle, dwStyle);
    //MessageBoxA(0, msg, "MonkeyDLL", 0);
    if (fp) {
        LOG("CreateWindowExW dwExStyle=0x%X dwStyle=0x%X lpClassName=0x%X, "
            "lpWindowName=0x%X X=%d Y=%d nWidth=%d nHeight=%d",
            dwExStyle, dwStyle, (uint32_t)lpClassName, (uint32_t)lpWindowName, X, Y, nWidth, nHeight);
    }

    if (dwExStyle == 0x800A0 && dwStyle == 0x86880000) {
        // or make it invisible
        dwStyle &= ~WS_VISIBLE;
        if (fp) {
            LOG("hijack window creation dwExStyle=0x%X dwStyle=0x%X", dwExStyle, dwStyle);
        }
        return 0;
    }

    __asm {
        // 3*12=36 bytes
        push lpParam;
        push hInstance;
        push hMenu;
        push hWndParent;
        push nHeight;
        push nWidth;
        push Y;
        push X;
        push dwStyle;
        push lpWindowName;
        push lpClassName;
        push dwExStyle;

        call get_eip;
        add eax, 15; // 3 bytes

        push eax; // 1 byte

        /* copied from first 5 bytes of CreateWindowExW */
        mov edi, edi;
        push ebp;
        mov ebp, esp;
        /* end of copy */

        jmp ptr_func_remaining; // 6 bytes

        mov ret, eax;
    }

    return ret;
}

void patch() {
    const auto hMod = LoadLibraryW(L"user32.dll");
    if (hMod == 0) {
        MessageBoxA(0, "Failed to load user32.dll", "MonkeyDLL", 0);
        return;
    }

    const auto func = GetProcAddress(hMod, "CreateWindowExW");
    if (func == NULL) {
        MessageBoxA(0, "Failed to get Win32 API proc address", "MonkeyDLL", 0);
        return;
    }

    const auto hProc = GetCurrentProcess();

    auto patch = jmp_rel32((void*)&proxy, (void*)func);
    ptr_func_remaining = (void*)((uint32_t)func + sizeof(patch)); // we will jump back to the real impl if needed

    SIZE_T written{};
    if (!WriteProcessMemory(hProc, func, &patch, sizeof(patch), &written) || written != sizeof(patch)) {
        MessageBoxA(0, "Failed to write process memory.", "MonkeyDLL", 0);
        return;
    }

    if (debug) {
        char msg[1024];
        sprintf_s(msg, sizeof(msg), "Patched CreateWindowExW 0x%X\nproxy function: 0x%X", 
            (uint32_t)func, (uint32_t)&proxy);
        MessageBoxA(0, msg, "MonkeyDLL", 0);
    }

    if (fp) {
        LOG("CreateWindowExW patched successfully");
    }
}

__declspec(dllexport) void __cdecl DisplayVersion(void);

void __cdecl DisplayVersion(void) {
    // dummy export
    MessageBoxA(0, "MonkeyDLL version 1.0.0 (2022-12-28 23:05:14)\nHappy hacking!", "MonkeyDLL Info", MB_ICONASTERISK);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    static BOOL env_debug_loaded = FALSE;
    if (!env_debug_loaded) {
        env_debug_loaded = TRUE;
        char buf[2048];
        int nRead = GetEnvironmentVariableA(ENVIRON_DEBUG, buf, sizeof(buf));
        if (nRead >= sizeof(buf)) {
            buf[sizeof(buf) - 1] = '\0';
        }
        debug = (nRead > 0 && strcmp(buf, "0")) ? TRUE : FALSE;

        nRead = GetEnvironmentVariableA(ENVIRON_LOG_FILE, buf, sizeof(buf));
        if (nRead > 0 && nRead < sizeof(buf)) {
            log_file_path = _strdup(buf);
        }
        else {
            log_file_path = "R:\\monkey.log";
        }
    }

    if (debug && fp == NULL) {
        fp = fopen(log_file_path, "a");
    }

    if (!patched) {
        patch();
        patched = 1;
    }

    //switch (ul_reason_for_call)
    //{
    //case DLL_PROCESS_ATTACH:
    //case DLL_THREAD_ATTACH:
    //case DLL_THREAD_DETACH:
    //case DLL_PROCESS_DETACH:
    //    break;
    //}
    return TRUE;
}

