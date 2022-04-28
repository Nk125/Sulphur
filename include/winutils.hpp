#undef UNICODE
#include <windows.h>
#include "common.hpp"
#include <functional>
#include <locale>
#include <process.h>
#include <string>
#include <tchar.h>
#include <tlhelp32.h>
#include <vector>

namespace nk125 {
    std::string parse_win_error(int ret) {
        LPSTR buf = nullptr;
        std::string strbuf;

        int bufsz = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            static_cast<DWORD>(ret),
            NULL,
            (LPSTR)&buf,
            0,
            NULL
        );

        strbuf.assign(buf, bufsz);

        return strbuf;
    }

    void set_wallpaper(std::string wallpaper) {
        #pragma comment(lib, "user32")
        SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID) wallpaper.data(), SPIF_UPDATEINIFILE);
        return;
    }

    std::vector<char> listDrives() {
        DWORD drvlist = GetLogicalDrives();
        std::vector<char> ldisk_buffer;

        for (int i = 0; i < 26; i++) {
            if (drvlist & (1 << i)) {
                ldisk_buffer.push_back('a' + i);
            }
        }

        return ldisk_buffer;
    }

    bool killProcByPID(DWORD pid) {
        DWORD perms = PROCESS_TERMINATE;
        bool secinh = FALSE;
        HANDLE proc = OpenProcess(perms, secinh, pid);

        if (proc == NULL) {
            return false;
        }

        bool terminated = TerminateProcess(proc, 1);
        CloseHandle(proc);
        return terminated;
    }

    bool killProcByPID(int pid) {
        return killProcByPID(static_cast<DWORD>(pid));
    }

    int getProcPID(std::string name) {
        HANDLE aproc;
        PROCESSENTRY32 pe32;
        DWORD self_pid = GetCurrentProcessId();

        aproc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (aproc == INVALID_HANDLE_VALUE) {
            return -1;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(aproc, &pe32)) {
            CloseHandle(aproc);
            return -1;
        }

        name = str_to_lower(name);
        DWORD pid = -1;

        do {
            std::string procname(pe32.szExeFile);
            procname = str_to_lower(procname);

            if (procname == name) {
                pid = pe32.th32ProcessID;
            }
        } while (Process32Next(aproc, &pe32));

        CloseHandle(aproc);

        return pid;
    }

    void purge_process(std::string proc_w) {
        HANDLE aproc;
        PROCESSENTRY32 pe32;
        DWORD self_pid = GetCurrentProcessId();

        aproc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (aproc == INVALID_HANDLE_VALUE) {
            return;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(aproc, &pe32)) {
            CloseHandle(aproc);
            return;
        }

        std::string proc_wc = proc_w;
        proc_wc = str_to_lower(proc_wc);

        do {
            std::string procname(pe32.szExeFile);
            procname = str_to_lower(procname);

            DWORD pid = pe32.th32ProcessID;
            if (self_pid != pid && self_pid > 4 && (proc_wc.find(procname) == std::string::npos)) {
                killProcByPID(pid);
            }
        } while (Process32Next(aproc, &pe32));

        CloseHandle(aproc);
        return;
    }

    bool killProcByName(std::string name) {
        HANDLE aproc;
        PROCESSENTRY32 pe32;
        DWORD self_pid = GetCurrentProcessId();

        aproc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (aproc == INVALID_HANDLE_VALUE) {
            return false;
        }

        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(aproc, &pe32)) {
            CloseHandle(aproc);
            return false;
        }

        name = str_to_lower(name);

        do {
            std::string procname(pe32.szExeFile);
            procname = str_to_lower(procname);

            if (procname == name) {
                killProcByPID(pe32.th32ProcessID);
            }
        } while (Process32Next(aproc, &pe32));

        CloseHandle(aproc);
        return true;
    }

    // Invoke it as a normal function pointer:
    // auto duhh = getFuncFromDLL("Mysuperdll.dll", "?duh@@", void (*duh)());
    // if (duhh == NULL) ExitProcess(1);
    // duhh();
    auto getFuncFromDll = [](std::string obj_dll, std::string func_name, auto func_ptr) -> FARPROC {
        HMODULE Dll = LoadLibrary(TEXT(obj_dll.c_str()));
        func_ptr Func;

        if (Dll != NULL) {
            Func = (func_ptr) GetProcAddress(Dll, func_name.c_str());
        }
        else {
            Func = NULL;
        }

        FreeLibrary(Dll);
        return Func;
    };

    // Same as above but this searches in System32 for the DLL
    auto getFuncFromSysDll = [](std::string obj_dll, std::string func_name, auto func_ptr) -> FARPROC {
        HMODULE Dll = LoadLibraryExA(TEXT(obj_dll.c_str()), NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        func_ptr Func;

        if (Dll != NULL) {
            Func = (func_ptr) GetProcAddress(Dll, func_name.c_str());
        }
        else {
            Func = NULL;
        }

        FreeLibrary(Dll);
        return Func;
    };
}
