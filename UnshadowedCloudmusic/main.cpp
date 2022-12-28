#include <Windows.h>
#include <shlwapi.h>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <detours.h>

#include "monkey_bridge.h"

#define STRCMP_NC(__s1__, __s2__) CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, (__s1__), -1, (__s2__), -1)

struct s_args {
    BOOL debug;
    LPCWSTR exec_path;
    LPCWSTR custom_dll_path;
    LPCWSTR debug_log_file;
    BOOL wait_before_exit;
};

bool get_argv(struct s_args *ret) {
    *ret = s_args {};
    int nArgs;
    const auto argv = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    for (int i = 1; i < nArgs; ++i) {
        if (STRCMP_NC(argv[i], L"/Debug") == CSTR_EQUAL) {
            ret->debug = TRUE;
        }
        else if (STRCMP_NC(argv[i], L"/Wait") == CSTR_EQUAL) {
            ret->wait_before_exit = TRUE;
        }
        else if (STRCMP_NC(argv[i], L"/Dll") == CSTR_EQUAL) {
            if (i >= nArgs - 1) {
                return false;
            }
            ret->custom_dll_path = argv[++i];
        }
        else if (STRCMP_NC(argv[i], L"/DebugLog") == CSTR_EQUAL) {
            if (i >= nArgs - 1) {
                return false;
            }
            ret->debug_log_file = argv[++i];
        }
        else if(ret->exec_path == NULL) {
            ret->exec_path = argv[i];
        }
        else {
            // invalid argument
            return false;
        }
    }
    // exec_path must be set
    if (ret->exec_path == NULL) {
        if (PathFileExistsA("cloudmusic.exe")) {
            // use cloudmusic.exe found in current working directory
            ret->exec_path = L"cloudmusic.exe";
            return true;
        }
        return false;
    }
    return true;
}

std::string WStringToString(const std::wstring& s)
{
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

int APIENTRY WinMain(
    HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
    LPSTR     lpCmdLine,
	int       nCmdShow) {

    LPCSTR dll_path = "Monkey.dll";

    const struct s_args args {};
    if (!get_argv((struct s_args*) & args)) {
        WCHAR filePath[MAX_PATH];
        WCHAR buf[1024];
        GetModuleFileNameW(NULL, filePath, MAX_PATH);
        swprintf_s(buf, L"Usage: %ls [/Debug] [/Wait] [/Dll <monkey_dll>] [/DebugLog [<log_file>]] <cloudmusic.exe>", 
            PathFindFileNameW(filePath));
        MessageBoxW(0, buf, L"Invalid argments", 0);
        return 0;
	}

    if (args.custom_dll_path != NULL) {
        auto s = new std::string{};
        s->assign(WStringToString(args.custom_dll_path));
        dll_path = s->c_str();

        if (args.debug) {
            CHAR buf[1024];
            sprintf_s(buf, "Using custom DLL: %s", dll_path);
            MessageBoxA(0, buf, "Debug", 0);
        }
    }

    // pass debug flags to child process
    if (args.debug) {
        if (!SetEnvironmentVariableA(ENVIRON_DEBUG, "1")) {
            MessageBoxA(0, "Failed to set debug flag " ENVIRON_DEBUG, NULL, 0);
            return 1;
        }
        if (args.debug_log_file != NULL && !SetEnvironmentVariableW(TEXT(ENVIRON_LOG_FILE), args.debug_log_file)) {
            MessageBoxA(0, "Failed to set debug flag " ENVIRON_LOG_FILE, NULL, 0);
            return 1;
        }
    }

    STARTUPINFO si{};
    PROCESS_INFORMATION pi{};

    si.cb = sizeof(si);
    
    BOOL ok = DetourCreateProcessWithDllEx(
        args.exec_path,
        NULL,
        NULL,
        NULL,
        TRUE,
        CREATE_DEFAULT_ERROR_MODE | CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi,
        dll_path,
        NULL
    );

    if (!ok) {
        LPSTR messageBuffer{};
        int err = GetLastError();
        size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        char msg[1024];
        sprintf_s(msg, "DetourCreateProcessWithDllEx failed: %s", messageBuffer);
        MessageBoxA(0, msg, NULL, 0);
        LocalFree(messageBuffer);
        return 1;
    }

    auto t = ResumeThread(pi.hThread);
    if (t == 0) {
        MessageBoxA(0, "ResumeThread failed", NULL, 0);
        return 1;
    }

    if (args.debug) {
        MessageBoxA(0, "Target process main thread is resumed", "Debug", 0);
    }

    if (args.wait_before_exit) {
        auto o = WaitForSingleObject(pi.hProcess, INFINITE);
        if (o != 0) {
            MessageBoxA(0, "WaitForSingleObject failed", NULL, 0);
            return 1;
        }
    }

    return 0;
}