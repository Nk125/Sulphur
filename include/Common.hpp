#pragma once
#pragma warning(disable: 4244)
#include <algorithm>
#include <chrono>
#include <cctype>
#include <string>

namespace nk125 {
    std::string str_to_lower(std::string in_data) {
        std::string buffer = in_data;

        std::transform(buffer.begin(), buffer.end(), buffer.begin(),
        [](unsigned char c){
            return std::tolower(c);
        });
        
        return buffer;
    }

    const std::string WHITESPACE = " ";

    std::string ltrim(const std::string& s) {
        size_t start = s.find_first_not_of(WHITESPACE);
        return (start == std::string::npos) ? "" : s.substr(start);
    }

    std::string rtrim(const std::string& s) {
        size_t end = s.find_last_not_of(WHITESPACE);
        return (end == std::string::npos) ? "" : s.substr(0, end + 1);
    }

    std::string trim(const std::string& s) {
        return rtrim(ltrim(s));
    }

    class random {
    private:
        std::string dictionary = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        int dict_sz = dictionary.size();

        void make_seed() {
            std::chrono::time_point<std::chrono::high_resolution_clock> cptr = std::chrono::high_resolution_clock::now();
            srand(std::chrono::duration_cast<std::chrono::nanoseconds> (cptr.time_since_epoch()).count());
        }
    public:
        std::string gen_random(long long size) {
            if (size <= 0) return "";
            std::string randomstr;

            make_seed();

            for (long long i = 0; i < size; i++) {
                randomstr += dictionary.at(rand() % dict_sz);
            }

            return randomstr;
        }
    };
}
