#include <cstdint>
#include <iostream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fstream>

std::vector<std::string> dns_servers(10);

struct DNSHeader {
    /** identifier */
    uint16_t id;
    /** Check out for more info on flags: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1 */
    uint16_t flags;
    /** the number of entries in the question section */
    uint16_t qdcount;
    /** the number of resource records in the answer section */
    uint16_t ancount;
    /** the number of name server resource records in the authority records section */
    uint16_t nscount;
    /** the number of resource records in the additional records section */
    uint16_t arcount;
};

std::vector<uint8_t> encodeDomainName(const std::string& domain) {
    std::vector<uint8_t> encoded;
    size_t pos = 0, next;

    while((next = domain.find('.', pos)) != std::string::npos) {
        encoded.push_back(next - pos);
        // Can we change to domain.at(pos) & domain.at(next) ?
        encoded.insert(encoded.end(), domain.begin() + pos, domain.begin() + next);
        pos = next + 1;
    }
    encoded.push_back(domain.size() - pos);
    encoded.insert(encoded.end(), domain.begin() + pos, domain.end());
    encoded.push_back(0);
    return encoded;
}

std::vector<uint8_t> createQuestion(const std::string& domain) {
    std::vector<uint8_t> question = encodeDomainName(domain);
    // append the query type (ex: here A = 0x0001)
    question.push_back(0x00);
    question.push_back(0x01);

    // append the class (ex: here IN = 0x0001)
    question.push_back(0x00);
    question.push_back(0x01);
    return question;
}

std::vector<uint8_t> createDNSQuery(const std::string& domain) {
    // Creating a header using the DNSHeader struct
    DNSHeader header = {};
    // we need to convert the integer to Big-Endian as that is what networks use! htons does that for us
    header.id = htons(0x384);
    // Standard query with recursion
    header.flags = htons(0x0100);
    header.qdcount = htons(0x1);

    // Fancy copy value of header into the query! reinterpret_cast converts header to uint8_t* to treat its mem
    // as a sequence of bits and copies it into query
    std::vector<uint8_t> query(reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header) + sizeof(DNSHeader));

    std::vector<uint8_t> question = createQuestion(domain);
    query.insert(query.end(), question.begin(), question.end());

    return query;
}

int parseResponse(const uint8_t *response) {
    size_t offset = 0;

    // Copying two bytes into their respective variables from response
    uint16_t idHex = (response[offset] << 8) | response[offset + 1];
    offset += 2;
    uint16_t flags = (response[offset] << 8) | response[offset + 1];
    offset += 2;
    uint16_t qdCount = (response[offset] << 8) | response[offset + 1];
    offset += 2;
    uint16_t anCount = (response[offset] << 8) | response[offset + 1];
    offset += 2;
    uint16_t nsCount = (response[offset] << 8) | response[offset + 1];
    offset += 2;
    uint16_t arCount = (response[offset] << 8) | response[offset + 1];
    offset += 2;

    // Getting the value of ID in ascii
    char id[10];
    snprintf(id, sizeof(id), "%x", idHex);

    // We are getting the value of opcode here
    std::string opcode;
    uint8_t opcodeHex = (flags >> 11) & 0x3;
    if (opcodeHex == 0x0) {
        opcode = "QUERY";
    } else if (opcodeHex == 0x1) {
        opcode = "IQUERY";
    } else if (opcodeHex == 0x2) {
        opcode = "STATUS";
    }

    // Getting the status value and comparing it to the 
    std::string status;
    uint8_t statusHex = (flags & 0xF);
    switch (statusHex){
        case 0x0:
            status = "NOERROR";
            break;
        case 0x1:
            status = "FORMERR";
            break;
        case 0x2:
            status = "SERVFAIL";
            break;
        case 0x3:
            status = "NXDOMAIN";
            break;
        case 0x4:
            status = "NOTIMP";
            break;
        case 0x5:
            status = "REFUSED";
            break;
        case 0x6:
            status = "YXDOMAIN";
            break;
        case 0x7:
            status = "XRRSET";
            break;
        case 0x8:
            status = "NOTAUTH";
            break;
        case 0x9:
            status = "NOTZONE";
            break;
    }

    std::string flagStr;
    if ((flags >> 15) & 0x1) {
        flagStr.append("qr ");
    }
    if ((flags >> 10) & 0x1) {
        flagStr.append("aa ");
    }
    if ((flags >> 9) & 0x1) {
        flagStr.append("tc ");
    }
    if ((flags >> 8) & 0x1) {
        flagStr.append("rd ");
    }
    if ((flags >> 7) & 0x1) {
        flagStr.append("ra ");
    }
    if (flagStr.length() == 0) {
        flagStr = "none";
    } else {
        flagStr.erase(flagStr.length()-1);
    }
    std::cout << "Header:\n";
    std::cout << "  opcode: " << opcode << ", status: " << status << ", id: " << id << "\n";
    std::cout << "  flags: " << flagStr << "; QUERY: " << qdCount <<", ANSWER: " << anCount;
    std::cout << ", AUTHORITY: " << nsCount << ", ADDITIONAL: " << arCount << "\n";
    return 0;
}

int sendQuery(const std::vector<uint8_t>& query) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed.");
        return -1;
    }

    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(53);
    //inet_pton(AF_INET, &dns_servers[0][0], &server.sin_addr);
    server.sin_addr.s_addr = inet_addr(&dns_servers[0][0]);
    socklen_t serverLen = sizeof(server);

    if(sendto(sock, query.data(), query.size(), 0, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Send error.");
        close(sock);
        return -1;
    }

    uint8_t buffer[512];
    
    int recvLen = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&server, &serverLen);
    if(recvLen < 0) {
        perror("Receive failed.");
        close(sock);
        return -1;
    }

    std::cout<<"Response:   ";
    for(uint8_t byte: buffer) {
        printf("%02x ", byte);
    }
    std::cout<<std::endl;

    std::cout<<"Response received, of length: "<<recvLen<<std::endl;
    close(sock);
    parseResponse(buffer);
    return 0;
}

void getNameServers(int isGiven) {
    std::ifstream resolv("/etc/resolv.conf");
    std::string str;
    std::vector<std::string> nameservers;
    int i = 0;
    while (std::getline(resolv, str)) {
        if ((str[0] == '#') || (str == "")) {
            continue;
        }
        if (str.substr(0, 10) == "nameserver") {
            nameservers.push_back(str.substr(11, str.length() - 11));
        }
    }

    if (isGiven) {
        i = 1;
        for (std::string s: nameservers) {
            dns_servers[i] = s;
            i += 1;
        }
    } else {
        for (std::string s: nameservers) {
            dns_servers[i] = s;
            i += 1;
        }
    }
}

int main(int argc, char *argv[]) {
    unsigned char hostname[100];
    int serverGiven = 0;

    if (argc < 2) {
        std::cout<< "Invalid usage."<< std::endl;
        return 0;
    }
    if (argc > 2) {
        serverGiven = 1;
        dns_servers[0] = argv[2];
        getNameServers(serverGiven);
    } else if (argc == 2) {
        getNameServers(serverGiven);
    }

    // we want to create a DNS Query using the protocol described by IETF
    std::vector<uint8_t> query = createDNSQuery(argv[1]);

    sendQuery(query);
    return 0;
}