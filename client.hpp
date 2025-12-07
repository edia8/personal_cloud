#pragma once
#include <string>
#include <vector>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "protocol.hpp"

using namespace std;
class ScopedSocket {
    int sockfd;
public:
    ScopedSocket() : sockfd(-1) {}
    explicit ScopedSocket(int fd) : sockfd(fd) {}
    ~ScopedSocket() {
        if (sockfd >= 0) {
            close(sockfd);
            cout << "[Client] Connection closed.\n";
        }
    }
    // Disable copy, allow move pt evitarea erorilor
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;
    
    void reset(int fd) {
        if (sockfd >= 0) close(sockfd);
        sockfd = fd;
    }
    bool connect_to_server(const std::string& ip, int port) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            cerr << "Failed to create socket.\n";
            return false;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
            cerr << "Invalid address.\n";
            close(sockfd);
            return false;
        }

        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            cerr << "Connection Failed. Is the server running?\n";
            close(sockfd);
            return false;
        }
        cout << "Connected to " << ip << ":" << port << "\n";
        return true;
    }
    int get() const { return sockfd; }
    bool is_valid() const { return sockfd >= 0; }
};

class ClientBackend {
    ScopedSocket user_sock;
    ScopedSocket data_sock;
    bool is_logged_in = false;
    unsigned long token;

    bool send_full_packet(int fd, const void* data, unsigned long len);
    bool recv_full_packet(int fd, void* data, unsigned long len);
public:
    bool connect(string ip, int port);
    void send_link_packet(unsigned long token);
    bool register_user(const string &user, const string &pass);
    unsigned long login(const string &user, const string &pass);
    string upload(string filename);
    string download(string filename);
    string del(string filename);
    void close_client();
};
