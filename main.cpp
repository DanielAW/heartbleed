#include "apps.h"

#include <botan/tls_client.h>
#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <string>
#include <iostream>
#include <memory>
#include <iostream>
#include <fstream>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>

#include "credentials.h"

/**
 * Code based on TLS client example here:
 * http://botan.randombit.net/manual/tls.html#tls-clients
 */


using namespace Botan;

using namespace std::placeholders;

namespace {

/**
 * @brief Shows hexdump of returned payload
 * see: http://stahlworks.com/dev/index.php?tool=csc01
 * @param pAddressIn
 * @param lSize
 */
void hexdump(const void *pAddressIn, long  lSize) {
    char szBuf[100];
    long lIndent = 1;
    long lOutLen, lIndex, lIndex2, lOutLen2;
    long lRelPos;
    struct { 
        char *pData; 
        unsigned long lSize; 
    } buf;

    unsigned char *pTmp,ucTmp;
    unsigned char *pAddress = (unsigned char *)pAddressIn;

    buf.pData   = (char *)pAddress;
    buf.lSize   = lSize;

    while (buf.lSize > 0) {
        pTmp     = (unsigned char *)buf.pData;
        lOutLen  = (int)buf.lSize;
        if (lOutLen > 16)
            lOutLen = 16;

        // create a 64-character formatted output line:
        sprintf(szBuf, " >                            "
                "                      "
                "    %08lX", pTmp-pAddress);
        lOutLen2 = lOutLen;

        for(lIndex = 1+lIndent, lIndex2 = 53-15+lIndent, lRelPos = 0;
            lOutLen2;
            lOutLen2--, lIndex += 2, lIndex2++
            )
        {
            ucTmp = *pTmp++;

            sprintf(szBuf + lIndex, "%02X ", (unsigned short)ucTmp);
            if(!isprint(ucTmp))  ucTmp = '.'; // nonprintable char
            szBuf[lIndex2] = ucTmp;

            if (!(++lRelPos & 3))     // extra blank after 4 bytes
            {  lIndex++; szBuf[lIndex+2] = ' '; }
        }

        if (!(lRelPos & 3)) lIndex--;

        szBuf[lIndex  ]   = '<';
        szBuf[lIndex+1]   = ' ';

        printf("%s\n", szBuf);

        buf.pData   += lOutLen;
        buf.lSize   -= lOutLen;
    }
}

int connect_to_host(const std::string& host, u16bit port, const std::string& transport) {
    hostent* host_addr = ::gethostbyname(host.c_str());

    if(!host_addr)
        throw std::runtime_error("gethostbyname failed for " + host);

    if(host_addr->h_addrtype != AF_INET) // no ipv6 support
        throw std::runtime_error(host + " has IPv6 address, not supported");

    int type = (transport == "tcp") ? SOCK_STREAM : SOCK_DGRAM;

    int fd = ::socket(PF_INET, type, 0);
    if(fd == -1)
        throw std::runtime_error("Unable to acquire socket");

    sockaddr_in socket_info;
    ::memset(&socket_info, 0, sizeof(socket_info));
    socket_info.sin_family = AF_INET;
    socket_info.sin_port = htons(port);

    ::memcpy(&socket_info.sin_addr,
             host_addr->h_addr,
             host_addr->h_length);

    socket_info.sin_addr = *(struct in_addr*)host_addr->h_addr;

    if(::connect(fd, (sockaddr*)&socket_info, sizeof(struct sockaddr)) != 0) {
        ::close(fd);
        throw std::runtime_error("connect failed");
    }

    return fd;
}

bool handshake_complete(const TLS::Session& session) {
    std::cout << "Handshake complete, " << session.version().to_string()
              << " using " << session.ciphersuite().to_string() << "\n";

    if(!session.session_id().empty())
        std::cout << "Session ID " << hex_encode(session.session_id()) << "\n";

    if(!session.session_ticket().empty())
        std::cout << "Session ticket " << hex_encode(session.session_ticket()) << "\n";

    return true;
}

/**
 * @brief send data through Unix sockets
 * @param sockfd
 * @param buf
 * @param length
 */
void stream_socket_write(int sockfd, const byte buf[], size_t length) {
    size_t offset = 0;

    while(length) {
        std::cout << "stream_socket_write(): About to send: " << std::endl;
        hexdump(buf, length);
        ssize_t sent = ::send(sockfd, (const char*)buf + offset,
                              length, MSG_NOSIGNAL);

        if(sent == -1) {
            if(errno == EINTR)
                sent = 0;
            else
                throw std::runtime_error("Socket::write: Socket write failed");
        }

        offset += sent;
        length -= sent;
    }
}

//global status variables
bool got_alert = false;
int got_data = 0;

void alert_received(TLS::Alert alert, const byte data[], size_t data_len) {
    got_data = data_len;
    std::cout << "Alert: " << alert.type_string() << "\n";
    std::cout << "Alert data len: " << data_len << "\n";

    hexdump(data, data_len);

    got_alert = true;
}

void process_data(const byte buf[], size_t buf_size) {
    for(size_t i = 0; i != buf_size; ++i)
        std::cout << buf[i];
}

std::string protocol_chooser(const std::vector<std::string>& protocols) {
    for(size_t i = 0; i != protocols.size(); ++i)
        std::cout << "Protocol " << i << " = " << protocols[i] << "\n";
    return "http/1.1";
}

} //end namespace




int main(int argc, char* argv[]) {
    if(argc != 2 && argc != 3 && argc != 4) {
        std::cout << "Usage " << argv[0] << " host [port]\n";
        return 1;
    }

    try {
        AutoSeeded_RNG rng;
        TLS::Policy policy;

        TLS::Session_Manager_In_Memory session_manager(rng);

        Credentials_Manager_Simple creds(rng);

        std::string host = argv[1];
        u32bit port = argc >= 3 ? Botan::to_u32bit(argv[2]) : 443;

        int sockfd = connect_to_host(host, port, "tcp");

        auto socket_write = std::bind(stream_socket_write, sockfd, _1, _2);

        auto version = TLS::Protocol_Version::latest_tls_version();

        //initialize the client and set callback functions defined above
        TLS::Client client(socket_write,
                           process_data,
                           alert_received,
                           handshake_complete,
                           session_manager,
                           creds,
                           policy,
                           rng,
                           TLS::Server_Information(host, port),
                           version,
                           protocol_chooser);

        while(!client.is_closed()) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(sockfd, &readfds);

            byte buf[4*1024] = { 0 };

            ssize_t got = ::read(sockfd, buf, sizeof(buf));

            if(got == 0) {
                std::cout << "EOF on socket\n";
                break;
            }
            else if(got == -1) {
                std::cout << "Socket error: " << errno << " " << strerror(errno) << "\n";
                continue;
            }

            std::cout << "Socket - got " << got << " bytes\n";
            client.received_data(buf, got);


            //Stop if we received payload data from server
            if(got_data > 0) {
                client.close();
            }

            if(client.heartbeat_sending_allowed()) {
                std::cout << "Heartbeats allowed, sending some..." << std::endl;
                //we dont need any payload => nullptr
                //size of the hearbeat payload could go up to 64K
                client.heartbeat(nullptr, 1024);
            } else {
                std::cout << "Heardbeats NOT allowed..." << std::endl;
            }
        }

        ::close(sockfd);

    } catch(const std::exception& e) {
        std::cout << "Exception: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

