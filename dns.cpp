#include <cstdint>
#include <iostream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

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

int main() {
    // we want to create a DNS Query using the protocol described by IETF
    std::vector<uint8_t> query = createDNSQuery("sameepshah.com");
    
    // Just printing the query for review
    std::cout << "DNS Query (Hex): ";
    for(uint8_t byte: query) {
        printf("%02x ", byte);
    }
    std::cout<<std::endl;

    return 0;
}