#include "dns_server.h"
#include <cassert>
#include <thread>

void test_dns_cache() {
    DNSCache cache;

    // Тест добавления и поиска записи
    cache.add_record("example.com", "93.184.216.34", 60, 1);
    auto records = cache.find_records("example.com", 1);
    assert(!records.empty());
    assert(records[0].data == "93.184.216.34");

    // Тест TTL
    cache.add_record("temp.com", "1.2.3.4", 1, 1); // TTL = 1 сек
    std::this_thread::sleep_for(std::chrono::seconds(2));
    records = cache.find_records("temp.com", 1);
    assert(records.empty()); // Должна быть удалена

    // Тест сохранения и загрузки
    cache.add_record("save.com", "5.6.7.8", 3600, 1);
    cache.save_cache();

    DNSCache new_cache;
    records = new_cache.find_records("save.com", 1);
    assert(!records.empty());
    assert(records[0].data == "5.6.7.8");

    std::cout << "DNS Cache tests passed!\n";
}

void test_dns_server() {
    DNSServer server;

    // Запускаем сервер в отдельном потоке
    std::thread server_thread([&]() {
        server.start();
        });

    // Даем серверу время на запуск
    std::this_thread::sleep_for(std::chrono::seconds(1));

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    // Создаем тестовый DNS запрос (упрощенный)
    char query[] = {
        0x00, 0x01, // ID
        0x01, 0x00, // Флаги (Recursion desired)
        0x00, 0x01, // 1 вопрос
        0x00, 0x00, // Ответы
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00, // Конец имени
        0x00, 0x01, // Тип A
        0x00, 0x01  // Класс IN
    };

    // Отправляем запрос на сервер
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

    sendto(sock, query, sizeof(query), 0, (sockaddr*)&servaddr, sizeof(servaddr));

    // Получаем ответ
    char response[1024];
    socklen_t len = sizeof(servaddr);
    int n = recvfrom(sock, response, sizeof(response), 0, (sockaddr*)&servaddr, &len);
    assert(n > 0);

    // Проверяем, что ответ содержит IP (упрощенная проверка)
    assert(n > sizeof(query)); // Ответ должен быть больше запроса
    std::cout << "Received DNS response with size: " << n << "\n";

    close(sock);
    server.stop();
    server_thread.join();

#ifdef _WIN32
    WSACleanup();
#endif

    std::cout << "DNS Server tests passed!\n";
}

int main() {
    test_dns_cache();
    test_dns_server();
    return 0;
}