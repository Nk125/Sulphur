#pragma once
#include <chrono>
#include "plusaes.hpp"
#include <string>
#include <vector>
#include <iostream>

namespace nk125 {
    class plusaes_wrapper {
        private:
            unsigned char m_iv[16] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
            };

            unsigned char m_tw_iv[12] = {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0A, 0x0B
            };

            unsigned char m_tag[16] = {0};

            bool copy_str(std::vector<unsigned char>* v, std::string str) {
                std::vector<unsigned char> buffer;
                // I need a buffer if vector v is undefined/cleared/modified under execution
                if (str.size() == 0) return 0;
                buffer.assign(str.begin(), str.end());

                *v = buffer;
                return 1;
            }

            /*
            unsigned char* stouc(std::string content) {
                unsigned char* buffer;
                for (long long i = 0; i < content.size(); i++) {
                    buffer[i] = content[i];
                }
                return buffer;
            }
            */

            void make_seed() {
                std::chrono::time_point<std::chrono::high_resolution_clock> cptr = std::chrono::high_resolution_clock::now();
                srand(std::chrono::duration_cast<std::chrono::nanoseconds> (cptr.time_since_epoch()).count());
            }

            std::string select_next_char() {
                std::string dictionary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                int dict_sz = dictionary.size();
                std::string random_ch = std::string{dictionary[rand() % dict_sz]};
                return random_ch;
            }

        // End Of Private

        public:
            void set_iv(unsigned char* iv) {
                strcpy((char*) m_iv, (const char*) iv);
            }

            void set_tw_iv(unsigned char* iv) {
                strcpy((char*) m_tw_iv, (const char*) iv);
            }

            std::string get_tag() {
                std::string buf;

                for (int i = 0; i < sizeof(m_tag); i++) {
                    buf += m_tag[i];
                }

                return buf;
            }

            std::string gen_random(long long size) {
                if (size <= 0) return "";
                std::string random;

                make_seed();

                for (long long i = 0; i < size; i++) {
                    random.append(select_next_char());
                }

                return random;
            }

            std::string cbc_encrypt(std::string raw, std::string pass) {
                const unsigned long pass_sz = pass.size(), orig_raw_sz = raw.size();
                if (orig_raw_sz == 0 || (pass_sz != 16 && pass_sz != 24 && pass_sz != 32)) return "";

                std::string encrypted_buffer;
                const unsigned long raw_sz = plusaes::get_padded_encrypted_size(raw.size());
                const unsigned char* passkey = (unsigned char*)(pass.data());

                std::vector<unsigned char> e_raw_data(raw_sz);

                auto res = plusaes::encrypt_cbc((unsigned char*)(raw.data()), orig_raw_sz, passkey, pass_sz, &m_iv, &e_raw_data[0], e_raw_data.size(), true);
                if (res) {
                    return "";
                }

                encrypted_buffer.assign(e_raw_data.begin(), e_raw_data.end());

                return encrypted_buffer;
            }

            std::string cbc_decrypt(std::string raw, std::string pass) {
                const unsigned long pass_sz = pass.size(), orig_raw_sz = raw.size();
                if (orig_raw_sz == 0 || (pass_sz != 16 && pass_sz != 24 && pass_sz != 32)) return "";

                std::string decrypted_buffer;
                unsigned long raw_sz = plusaes::get_padded_encrypted_size(raw.size());
                const unsigned char* passkey = (unsigned char*)(pass.data());

                std::vector<unsigned char> e_raw_data;
                if (!copy_str(&e_raw_data, raw)) return "";
                std::vector<unsigned char> d_raw_data(raw_sz);

                auto res = plusaes::decrypt_cbc(&e_raw_data[0], orig_raw_sz, passkey, pass_sz, &m_iv, &d_raw_data[0], d_raw_data.size(), &raw_sz);
                if (res) {
                    return "";
                }

                decrypted_buffer.assign(d_raw_data.begin(), d_raw_data.end());

                return decrypted_buffer;
            }

            std::string ecb_encrypt(std::string raw, std::string pass) {
                const unsigned long pass_sz = pass.size(), orig_raw_sz = raw.size();
                if (orig_raw_sz == 0 || (pass_sz != 16 && pass_sz != 24 && pass_sz != 32)) return "";

                std::string encrypted_buffer;
                const unsigned long raw_sz = plusaes::get_padded_encrypted_size(raw.size());
                const unsigned char* passkey = (unsigned char*)(pass.data());

                std::vector<unsigned char> e_raw_data(raw_sz);

                auto res = plusaes::encrypt_ecb((unsigned char*)(raw.data()), orig_raw_sz, passkey, pass_sz, &e_raw_data[0], e_raw_data.size(), true);
                if (res) {
                    return "";
                }

                encrypted_buffer.assign(e_raw_data.begin(), e_raw_data.end());

                return encrypted_buffer;
            }

            std::string ecb_decrypt(std::string raw, std::string pass) {
                const unsigned long pass_sz = pass.size(), orig_raw_sz = raw.size();
                if (orig_raw_sz == 0 || (pass_sz != 16 && pass_sz != 24 && pass_sz != 32)) return "";

                std::string decrypted_buffer;
                unsigned long raw_sz = plusaes::get_padded_encrypted_size(raw.size());
                const unsigned char* passkey = (unsigned char*)(pass.data());

                std::vector<unsigned char> e_raw_data;
                if (!copy_str(&e_raw_data, raw)) return "";

                std::vector<unsigned char> d_raw_data(raw_sz);

                auto res = plusaes::decrypt_ecb(&e_raw_data[0], orig_raw_sz, passkey, pass_sz, &d_raw_data[0], d_raw_data.size(), &raw_sz);
                if (res) {
                    return "";
                }

                decrypted_buffer.assign(d_raw_data.begin(), d_raw_data.end());

                return decrypted_buffer;
            }

            std::string gcm_encrypt(std::string raw, std::string pass, std::string aad = "") {
                const unsigned long pass_sz = pass.size(), orig_raw_sz = raw.size();
                if (orig_raw_sz == 0 || (pass_sz != 16 && pass_sz != 24 && pass_sz != 32)) return "";

                std::string encrypted_buffer;
                const unsigned long raw_sz = plusaes::get_padded_encrypted_size(raw.size());
                const unsigned char* passkey = (unsigned char*)(pass.data());
                unsigned char* aadata = (unsigned char*)(aad.data());
                int aadata_sz = aad.size();

                //std::vector<unsigned char> vec_iv(std::begin(m_iv), std::end(m_iv));
                std::vector<unsigned char> e_raw_data(raw_sz);

                auto res = plusaes::encrypt_gcm((unsigned char*)(raw.data()), orig_raw_sz, aadata, aadata_sz, passkey, pass_sz, &m_tw_iv, &m_tag);
                if (res) {
                    return "";
                }

                encrypted_buffer.assign(e_raw_data.begin(), e_raw_data.end());

                return encrypted_buffer;
            }

            std::string gcm_decrypt(std::string raw, std::string pass, std::string tag, std::string aad = "") {
                const unsigned long pass_sz = pass.size(), orig_raw_sz = raw.size();
                if (orig_raw_sz == 0 || (pass_sz != 16 && pass_sz != 24 && pass_sz != 32)) return "";

                std::string decrypted_buffer;
                unsigned long raw_sz = plusaes::get_padded_encrypted_size(raw.size());
                const unsigned char* passkey = (unsigned char*)(pass.data());
                unsigned char* aadata = (unsigned char*)(aad.data());
                int aadata_sz = aad.size();

                // std::vector<unsigned char> vec_iv(std::begin(m_iv), std::end(m_iv));
                // GCM Mode doesn't out the decrypted data to another vector, instead, overwrite the encrypted data buffer
                // with the decrypted data there
                std::vector<unsigned char> ed_raw_data;
                if (!copy_str(&ed_raw_data, raw)) return "";
                for (int i = 0; i < sizeof(m_tag); i++) {
                    m_tag[i] = tag[i];
                }

                auto res = plusaes::decrypt_gcm(&ed_raw_data[0], orig_raw_sz, aadata, aadata_sz, passkey, pass_sz, &m_tw_iv, &m_tag);
                if (res) {
                    return "";
                }

                decrypted_buffer.assign(ed_raw_data.begin(), ed_raw_data.end());

                return decrypted_buffer;
            }
        // End Of Public
    };
}
