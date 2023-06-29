#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip* ip_header = (struct ip*)(packet + 14); // Saltar la cabecera Ethernet
    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4); // Calcular la posición de la cabecera TCP

    // Filtra el tráfico HTTP
    if (ntohs(tcp_header->th_dport) == 80 || ntohs(tcp_header->th_sport) == 80) {
        const u_char* payload = packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4;

        // Imprime los detalles de la solicitud HTTP
        std::cout << "Fuente: " << inet_ntoa(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport)
                  << " --> Destino: " << inet_ntoa(ip_header->ip_dst) << ":" << ntohs(tcp_header->th_dport) << std::endl;
        std::cout.write(reinterpret_cast<const char*>(payload), pkthdr->len - (payload - packet));
        std::cout << "---------------------------------------------" << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Abre la interfaz de red en modo promiscuo
    pcap_t* handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error al abrir la interfaz de red: " << errbuf << std::endl;
        return 1;
    }

    // Filtra solo los paquetes con destino o origen puerto 80 (HTTP)
    struct bpf_program filter;
    std::string expression = "tcp port 80";
    if (pcap_compile(handle, &filter, expression.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error al compilar el filtro: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        std::cerr << "Error al aplicar el filtro: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // Captura los paquetes y los pasa al controlador de paquetes
    pcap_loop(handle, -1, packet_handler, nullptr);

    pcap_close(handle);
    return 0;
}
