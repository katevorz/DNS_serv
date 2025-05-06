#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <ctime>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
#define SHUT_RDWR SD_BOTH
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// Структура для хранения DNS записи
struct DNSRecord {
    std::string data;
    time_t expiry_time;
    uint16_t type; // 1 = A, 28 = AAAA, 2 = NS, 12 = PTR
};

// Класс кэша DNS с двумя хэш-массивами
class DNSCache {
private:
    // Первый хэш-массив: доменное имя -> записи
    std::unordered_map<std::string, std::vector<DNSRecord>> domain_to_records;

    // Второй хэш-массив: IP адрес -> доменное имя
    std::unordered_map<std::string, std::vector<DNSRecord>> ip_to_records;

    std::mutex cache_mutex;
    std::string cache_file = "dns_cache.dat";

    void clean_expired() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        time_t now = time(nullptr);

        // Очистка первого хэш-массива
        for (auto it = domain_to_records.begin(); it != domain_to_records.end(); ) {
            auto& records = it->second;
            records.erase(
                std::remove_if(records.begin(), records.end(),
                    [now](const DNSRecord& r) { return r.expiry_time <= now; }),
                records.end());

            if (records.empty()) {
                it = domain_to_records.erase(it);
            }
            else {
                ++it;
            }
        }

        // Очистка второго хэш-массива
        for (auto it = ip_to_records.begin(); it != ip_to_records.end(); ) {
            auto& records = it->second;
            records.erase(
                std::remove_if(records.begin(), records.end(),
                    [now](const DNSRecord& r) { return r.expiry_time <= now; }),
                records.end());

            if (records.empty()) {
                it = ip_to_records.erase(it);
            }
            else {
                ++it;
            }
        }
    }

public:
    DNSCache() {
        load_cache();
    }

    ~DNSCache() {
        save_cache();
    }

    void add_record(const std::string& key, const std::string& data, uint32_t ttl, uint16_t type) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        DNSRecord record;
        record.data = data;
        record.expiry_time = time(nullptr) + ttl;
        record.type = type;

        if (type == 1 || type == 28) { // A или AAAA запись
            domain_to_records[key].push_back(record);
            ip_to_records[data].push_back({ key, record.expiry_time, 12 }); // PTR запись
        }
        else if (type == 12) { // PTR запись
            ip_to_records[key].push_back(record);
            domain_to_records[data].push_back({ key, record.expiry_time, 1 }); // A запись
        }
        else { // Другие типы (NS и т.д.)
            domain_to_records[key].push_back(record);
        }
    }

    std::vector<DNSRecord> find_records(const std::string& key, uint16_t type = 0) {
        std::lock_guard<std::mutex> lock(cache_mutex);
        clean_expired();

        std::vector<DNSRecord> result;

        // Поиск в первом хэш-массиве (домены)
        auto domain_it = domain_to_records.find(key);
        if (domain_it != domain_to_records.end()) {
            for (const auto& record : domain_it->second) {
                if (type == 0 || record.type == type) {
                    result.push_back(record);
                }
            }
        }

        // Если не нашли в доменах, ищем во втором хэш-массиве (IP)
        if (result.empty()) {
            auto ip_it = ip_to_records.find(key);
            if (ip_it != ip_to_records.end()) {
                for (const auto& record : ip_it->second) {
                    if (type == 0 || record.type == type) {
                        result.push_back(record);
                    }
                }
            }
        }

        return result;
    }

    void save_cache() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        clean_expired();

        std::ofstream out(cache_file);
        if (!out) return;

        // Сохраняем записи из первого хэш-массива
        for (const auto& pair : domain_to_records) {
            for (const auto& record : pair.second) {
                out << "DOMAIN\t" << pair.first << "\t"
                    << record.data << "\t"
                    << record.expiry_time << "\t"
                    << record.type << "\n";
            }
        }

        // Сохраняем записи из второго хэш-массива
        for (const auto& pair : ip_to_records) {
            for (const auto& record : pair.second) {
                out << "IP\t" << pair.first << "\t"
                    << record.data << "\t"
                    << record.expiry_time << "\t"
                    << record.type << "\n";
            }
        }
    }

    void load_cache() {
        std::lock_guard<std::mutex> lock(cache_mutex);
        std::ifstream in(cache_file);
        if (!in) return;

        std::string line;
        time_t now = time(nullptr);

        while (std::getline(in, line)) {
            std::istringstream iss(line);
            std::string type, key, data;
            time_t expiry;
            uint16_t record_type;

            if (iss >> type >> key >> data >> expiry >> record_type) {
                if (expiry > now) {
                    DNSRecord record;
                    record.data = data;
                    record.expiry_time = expiry;
                    record.type = record_type;

                    if (type == "DOMAIN") {
                        domain_to_records[key].push_back(record);
                    }
                    else if (type == "IP") {
                        ip_to_records[key].push_back(record);
                    }
                }
            }
        }
    }
};

// Класс DNS сервера
class DNSServer {
private:
    DNSCache cache;
    int sockfd;
    bool running;
    std::thread cleaner_thread;

    void start_cache_cleaner() {
        cleaner_thread = std::thread([this]() {
            while (running) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
                cache.save_cache();
            }
            });
    }

    // Упрощенный парсинг DNS запроса
    std::string parse_dns_query(const char* buf, size_t len) {
        if (len < 12) return "";

        // Получаем тип запроса 
        uint16_t qtype = (buf[len - 4] << 8) | buf[len - 3];

        size_t pos = 12;
        std::string domain;
        while (pos < len && buf[pos] != 0) {
            size_t label_len = static_cast<size_t>(buf[pos]);
            if (pos + label_len >= len) break;

            domain.append(&buf[pos + 1], label_len);
            domain += ".";
            pos += label_len + 1;
        }

        if (!domain.empty()) domain.pop_back();

        // Для PTR запросов преобразуем IP в специальный формат
        if (qtype == 12) { // PTR запрос
            if (domain.find("in-addr.arpa") != std::string::npos) {
                // Преобразуем из формата x.y.z.w.in-addr.arpa в w.z.y.x
                std::vector<std::string> parts = split(domain, '.');
                if (parts.size() >= 4) {
                    domain = parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0];
                }
            }
        }

        return domain;
    }

    // Создание DNS ответа
    std::string create_dns_response(const char* query, size_t query_len,
        const std::vector<DNSRecord>& records) {
        if (records.empty()) return "";

        // Копируем заголовок из запроса
        std::string response(query, query_len);

        // Модифицируем флаги в заголовке (устанавливаем QR=1, RA=1)
        response[2] = 0x80; // QR = 1, Opcode = 0
        response[3] = 0x00; // AA = 0, TC = 0, RD = 0, RA = 1

        // Устанавливаем количество ответов
        uint16_t ancount = htons(records.size());
        memcpy(&response[6], &ancount, 2);

        // Добавляем ответы
        for (const auto& record : records) {
            // Имя (ссылка на имя в вопросе)
            response += "\xc0\x0c";

            // Тип и класс
            uint16_t type = htons(record.type);
            uint16_t cls = htons(1); // IN
            response.append(reinterpret_cast<char*>(&type), 2);
            response.append(reinterpret_cast<char*>(&cls), 2);

            // TTL (60 секунд)
            uint32_t ttl = htonl(60);
            response.append(reinterpret_cast<char*>(&ttl), 4);

            // Данные
            if (record.type == 1) { // A запись
                struct in_addr addr;
                inet_pton(AF_INET, record.data.c_str(), &addr);
                uint16_t rdlength = htons(4);
                response.append(reinterpret_cast<char*>(&rdlength), 2);
                response.append(reinterpret_cast<char*>(&addr.s_addr), 4);
            }
            else if (record.type == 12) { // PTR запись
                std::string name;
                for (const auto& part : split(record.data, '.')) {
                    name += static_cast<char>(part.size());
                    name += part;
                }
                name += "\x00";

                uint16_t rdlength = htons(name.size());
                response.append(reinterpret_cast<char*>(&rdlength), 2);
                response += name;
            }
        }

        return response;
    }

    std::vector<std::string> split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(s);
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    // Рекурсивный DNS запрос к вышестоящему серверу
    std::vector<DNSRecord> recursive_query(const std::string& domain, uint16_t type) {
        std::vector<DNSRecord> result;
     // используем фиктивные данные

        if (type == 1) { // A запись
            if (domain == "example.com") {
                result.push_back({ "93.184.216.34", time(nullptr) + 3600, 1 });
            }
            else {
                // Случайный IP для демонстрации
                result.push_back({ "8.8.8.8", time(nullptr) + 3600, 1 });
            }
        }
        else if (type == 12) { // PTR запись
            if (domain == "8.8.8.8") {
                result.push_back({ "dns.google", time(nullptr) + 3600, 12 });
            }
            else {
                result.push_back({ "example.com", time(nullptr) + 3600, 12 });
            }
        }

        return result;
    }

public:
    DNSServer() : running(false), sockfd(-1) {}

    ~DNSServer() {
        stop();
    }

    void start() {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup failed\n";
            return;
        }
#endif

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("socket creation failed");
            return;
        }

        sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = INADDR_ANY;
        servaddr.sin_port = htons(53);

        if (bind(sockfd, (const sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
            perror("bind failed");
            close(sockfd);
            return;
        }

        running = true;
        start_cache_cleaner();

        std::cout << "DNS Server started on port 53\n";

        char buffer[1024];
        sockaddr_in cliaddr;
        socklen_t len = sizeof(cliaddr);

        while (running) {
            int n = recvfrom(sockfd, buffer, sizeof(buffer), 0,
                (sockaddr*)&cliaddr, &len);
            if (n < 0) {
                perror("recvfrom failed");
                continue;
            }

            // Парсим запрос
            std::string query(buffer, n);
            std::string domain = parse_dns_query(buffer, n);

            if (domain.empty()) {
                std::cerr << "Invalid DNS query\n";
                continue;
            }

            // Получаем тип запроса 
            uint16_t qtype = (buffer[n - 4] << 8) | buffer[n - 3];

            std::cout << "Query for: " << domain << " (type: " << qtype << ")\n";

            // Ищем в кэше
            auto records = cache.find_records(domain, qtype);

            if (records.empty()) {
                records = recursive_query(domain, qtype);

                for (const auto& record : records) {
                    if (qtype == 1 || qtype == 28) { 
                        cache.add_record(domain, record.data, 60, qtype);
                    }
                    else if (qtype == 12) { 
                        cache.add_record(domain, record.data, 60, qtype);
                    }
                }

                std::cout << "Cache miss, added to cache: " << domain << "\n";
            }
            else {
                std::cout << "Cache hit for: " << domain << "\n";
            }

            // Формируем и отправляем ответ
            std::string response = create_dns_response(buffer, n, records);
            if (!response.empty()) {
                sendto(sockfd, response.c_str(), response.size(), 0,
                    (const sockaddr*)&cliaddr, len);
            }
        }
    }

    void stop() {
        running = false;
        if (cleaner_thread.joinable()) {
            cleaner_thread.join();
        }
        if (sockfd >= 0) {
            shutdown(sockfd, SHUT_RDWR);
            close(sockfd);
        }
        cache.save_cache();
        std::cout << "DNS Server stopped\n";

#ifdef _WIN32
        WSACleanup();
#endif
    }
};

#endif // DNS_SERVER_H