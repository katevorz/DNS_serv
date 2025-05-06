# DNS_serv
Назначение
Кэширующий DNS сервер, который:
Прослушивает 53 порт (UDP),
Обрабатывает рекурсивные запросы,
Кэширует все полученные записи (A, AAAA, NS, PTR),
Сохраняет кэш на диск между запусками.

Тесты
#ifdef DNS_SERVER_TESTING
#include <cassert>
#include <chrono>
void test_dns_cache() {
    DNSCache cache;
    
    // Тест добавления и поиска A записи
    cache.add_record("example.com", "93.184.216.34", 60, 1);
    auto records = cache.find_records("example.com", 1);
    assert(!records.empty());
    assert(records[0].data == "93.184.216.34");
    
    // Тест автоматического создания PTR записи
    auto ptr_records = cache.find_records("93.184.216.34", 12);
    assert(!ptr_records.empty());
    assert(ptr_records[0].data == "example.com");
    
    // Тест TTL
    cache.add_record("temp.com", "1.2.3.4", 1, 1);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    records = cache.find_records("temp.com", 1);
    assert(records.empty());
    
    std::cout << "DNS cache tests passed!\n";
}

void test_dns_server() {
    DNSServer server;
    std::thread server_thread([&]() { server.start(); });
    
    // Даем серверу время на запуск
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    // Тестовый DNS запрос (пример.com)
    const char query[] = {
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 
        'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 
        0x00, 0x00, 0x01, 0x00, 0x01
    };
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);
    
    // Отправляем запрос
    sendto(sock, query, sizeof(query), 0, 
          (sockaddr*)&servaddr, sizeof(servaddr));
    
    // Получаем ответ
    char response[1024];
    socklen_t len = sizeof(servaddr);
    recvfrom(sock, response, sizeof(response), 0, 
            (sockaddr*)&servaddr, &len);
    
    // Проверяем что ответ содержит данные
    assert(response[2] & 0x80); // Проверяем флаг QR=1
    assert(ntohs(*(uint16_t*)(response + 6)) > 0); // ANCOUNT > 0
    
    server.stop();
    server_thread.join();
    close(sock);
    
    std::cout << "DNS server tests passed!\n";
}
int main() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

    test_dns_cache();
    test_dns_server();

#ifdef _WIN32
    WSACleanup();
#endif
    
    return 0;
}
#endif // DNS_SERVER_TESTING
