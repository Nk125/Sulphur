#pragma once
#include <chrono>
#include <string>
#pragma warning(disable: 4244)

namespace nk125 {
    class random {
    private:
        static void make_seed() {
            std::chrono::time_point<std::chrono::high_resolution_clock> cptr = std::chrono::high_resolution_clock::now();
            srand(std::chrono::duration_cast<std::chrono::nanoseconds> (cptr.time_since_epoch()).count());
        }

        static std::string select_next_char() {
            std::string dictionary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            int dict_sz = dictionary.size();
            std::string random_ch = std::string{ dictionary[rand() % dict_sz] };
            return random_ch;
        }

    public:
        static std::string gen_random(long long size) {
            if (size <= 0) return "";
            std::string randomstr;

            make_seed();

            for (long long i = 0; i < size; i++) {
                randomstr.append(select_next_char());
            }

            return randomstr;
        }
    };
}
