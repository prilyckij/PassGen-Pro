// passgen_cpp.cpp — генератор паролей с настраиваемыми правилами на C++

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <random>
#include <getopt.h>
#include <cmath>
#include <fstream>
#include <json/json.h> // требуется библиотека jsoncpp

class PasswordGenerator {
private:
    std::string chars;
    int default_length;
    bool use_letters, use_digits, use_special;
    bool exclude_similar, exclude_ambiguous;
    std::random_device rd;
    std::mt19937 gen;

public:
    PasswordGenerator() : gen(rd()) {
        loadConfig();
    }

    void loadConfig() {
        std::ifstream file("passgen_config.json");
        if (file.is_open()) {
            Json::Value root;
            file >> root;
            default_length = root.get("default_length", 16).asInt();
            use_letters = root.get("use_letters", true).asBool();
            use_digits = root.get("use_digits", true).asBool();
            use_special = root.get("use_special", true).asBool();
            exclude_similar = root.get("exclude_similar", false).asBool();
            exclude_ambiguous = root.get("exclude_ambiguous", false).asBool();
            file.close();
        } else {
            default_length = 16;
            use_letters = true;
            use_digits = true;
            use_special = true;
            exclude_similar = false;
            exclude_ambiguous = false;
            saveConfig();
        }
    }

    void saveConfig() {
        Json::Value root;
        root["default_length"] = default_length;
        root["use_letters"] = use_letters;
        root["use_digits"] = use_digits;
        root["use_special"] = use_special;
        root["exclude_similar"] = exclude_similar;
        root["exclude_ambiguous"] = exclude_ambiguous;
        std::ofstream file("passgen_config.json");
        file << root;
        file.close();
    }

    std::string generate(int length, bool letters, bool digits, bool special,
                         bool excl_similar, bool excl_ambiguous) {
        std::string charSet;
        if (letters) charSet += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (digits) charSet += "0123456789";
        if (special) charSet += "!@#$%^&*()_+-=[]{}|;:,.<>?/~`";

        if (excl_similar) {
            for (char c : "O0Il1") {
                size_t pos = charSet.find(c);
                if (pos != std::string::npos) charSet.erase(pos, 1);
            }
        }
        if (excl_ambiguous) {
            for (char c : "{}[]()/\\\"'`~,;:.<>") {
                size_t pos = charSet.find(c);
                if (pos != std::string::npos) charSet.erase(pos, 1);
            }
        }
        if (charSet.empty()) throw std::runtime_error("Нет доступных символов");

        std::uniform_int_distribution<> dist(0, charSet.size()-1);
        std::string password;
        for (int i=0; i<length; ++i) {
            password += charSet[dist(gen)];
        }
        return password;
    }

    double entropy(const std::string& password) {
        // подсчёт уникальных символов
        std::string unique;
        for (char c : password) {
            if (unique.find(c) == std::string::npos) unique += c;
        }
        double per_char = log2(unique.size());
        return per_char * password.size();
    }

    double crackTime(double entropy) {
        return pow(2, entropy) / 1e9 / (60*60*24*365.25);
    }

    void interactive() {
        std::cout << "🔐 PassGen Pro — C++ Edition\n";
        std::cout << "Настройка параметров (можно оставить пустым для значений по умолчанию):\n";
        std::string input;
        std::cout << "Длина пароля (по умолчанию " << default_length << "): ";
        std::getline(std::cin, input);
        if (!input.empty()) default_length = std::stoi(input);
        std::cout << "Использовать буквы? (y/n, по умолчанию y): ";
        std::getline(std::cin, input);
        if (input == "n") use_letters = false;
        std::cout << "Использовать цифры? (y/n, по умолчанию y): ";
        std::getline(std::cin, input);
        if (input == "n") use_digits = false;
        std::cout << "Использовать спецсимволы? (y/n, по умолчанию y): ";
        std::getline(std::cin, input);
        if (input == "n") use_special = false;
        std::cout << "Исключить похожие? (y/n, по умолчанию n): ";
        std::getline(std::cin, input);
        exclude_similar = (input == "y");
        std::cout << "Исключить двусмысленные? (y/n, по умолчанию n): ";
        std::getline(std::cin, input);
        exclude_ambiguous = (input == "y");
        std::cout << "Количество паролей (по умолчанию 1): ";
        std::getline(std::cin, input);
        int count = input.empty() ? 1 : std::stoi(input);
        saveConfig();

        for (int i=0; i<count; ++i) {
            try {
                std::string pwd = generate(default_length, use_letters, use_digits,
                                           use_special, exclude_similar, exclude_ambiguous);
                double ent = entropy(pwd);
                double years = crackTime(ent);
                std::cout << i+1 << ") " << pwd << std::endl;
                std::cout << "   Энтропия: " << ent << " бит, время взлома: ~ " << years << " лет" << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Ошибка: " << e.what() << std::endl;
            }
        }
    }
};

int main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"length", required_argument, 0, 'l'},
        {"letters", no_argument, 0, 0},
        {"digits", no_argument, 0, 0},
        {"special", no_argument, 0, 0},
        {"all", no_argument, 0, 0},
        {"exclude-similar", no_argument, 0, 0},
        {"exclude-ambiguous", no_argument, 0, 0},
        {"count", required_argument, 0, 'c'},
        {"interactive", no_argument, 0, 'i'},
        {0, 0, 0, 0}
    };
    PasswordGenerator pg;
    bool interactive = false;
    int length = 0, count = 1;
    bool letters=false, digits=false, special=false, all=false;
    bool excl_similar=false, excl_ambiguous=false;

    int opt;
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "l:c:i", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'l': length = std::stoi(optarg); break;
            case 'c': count = std::stoi(optarg); break;
            case 'i': interactive = true; break;
            case 0:
                if (std::string(long_options[option_index].name) == "letters") letters = true;
                else if (std::string(long_options[option_index].name) == "digits") digits = true;
                else if (std::string(long_options[option_index].name) == "special") special = true;
                else if (std::string(long_options[option_index].name) == "all") all = true;
                else if (std::string(long_options[option_index].name) == "exclude-similar") excl_similar = true;
                else if (std::string(long_options[option_index].name) == "exclude-ambiguous") excl_ambiguous = true;
                break;
            default: break;
        }
    }

    if (interactive || argc == 1) {
        pg.interactive();
        return 0;
    }

    if (!letters && !digits && !special && !all) {
        // использовать сохранённые
        // загружены в объекте
    }
    bool use_letters = all || letters || pg.use_letters;
    bool use_digits = all || digits || pg.use_digits;
    bool use_special = all || special || pg.use_special;
    int gen_length = length > 0 ? length : pg.default_length;
    bool excl_sim = excl_similar || pg.exclude_similar;
    bool excl_amb = excl_ambiguous || pg.exclude_ambiguous;

    for (int i=0; i<count; ++i) {
        try {
            std::string pwd = pg.generate(gen_length, use_letters, use_digits, use_special,
                                          excl_sim, excl_amb);
            double ent = pg.entropy(pwd);
            double years = pg.crackTime(ent);
            std::cout << i+1 << ") " << pwd << std::endl;
            if (count == 1) {
                std::cout << "Энтропия: " << ent << " бит, время взлома: ~ " << years << " лет" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Ошибка: " << e.what() << std::endl;
        }
    }
    return 0;
}
