#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace nk125 {
  class stringsplit {
    private:
        std::string separator = "";
      
        std::string delete_separator(std::string str) {
            int index = 0;
            std::string buffer = str;
            for (char c : buffer) {
                if (separator.find(c) != std::string::npos) {
                    buffer.erase(index, 1);
                }
                index++;
            }
            return buffer;
        }
        std::vector<std::string> splitted = {};

    public:
        std::vector<std::string> get_splitted_str() {
            return splitted;
        }
        
        int split(std::string& str, std::string del = " ") {
            std::string str_buffer;
            separator = del;
            auto cst_str = str.c_str(), delim = del.c_str();
            char* split_buffer;
            char* cst_str_t = const_cast<char*>(cst_str);
            // Due to some strange reason my compiler reject the const char* type in 
            // constant_string and delimiter
            split_buffer = strtok(cst_str_t, delim);
            while (split_buffer != nullptr) {
                str_buffer.assign(delete_separator(split_buffer));
                splitted.push_back(str_buffer);
                split_buffer = strtok(nullptr, delim);
            }
            return splitted.size();
        }
    };
}