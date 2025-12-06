#include    <iostream>
#include    <string>
#include    <vector>
#include    <cstring>
#include    <sys/socket.h>
#include    <arpa/inet.h>
#include    <unistd.h>
#include    <regex> 
#include "protocol.hpp"

using namespace std;
// --- RAII SOCKET WRAPPER ---
// Ensures the socket is always closed, even if we return early.
class ScopedSocket {
    int sockfd;
public:
    ScopedSocket() : sockfd(-1) {}
    explicit ScopedSocket(int fd) : sockfd(fd) {}
    ~ScopedSocket() {
        if (sockfd >= 0) {
            close(sockfd);
            std::cout << "[Client] Connection closed.\n";
        }
    }
    // Disable copy, allow move
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;
    
    void reset(int fd) {
        if (sockfd >= 0) close(sockfd);
        sockfd = fd;
    }
    bool connect_to_server(const std::string& ip, int port) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            std::cerr << "Failed to create socket.\n";
            return false;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
            std::cerr << "Invalid address.\n";
            close(sockfd);
            return false;
        }

        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            std::cerr << "Connection Failed. Is the server running?\n";
            close(sockfd);
            return false;
        }
        std::cout << "Connected to " << ip << ":" << port << "\n";
        return true;
    }
    int get() const { return sockfd; }
    bool is_valid() const { return sockfd >= 0; }
};

string trim(string &s) {
    unsigned long  start = s.find_first_not_of(" \t\n");
    unsigned long end = s.find_last_not_of(" \t\n");
    if(start == string::npos) {
        //numai spatii, returnam empty string si verificam in client
        return "";
    }
    s = s.substr(start,end-start+1);
    regex whitespaces("\\s+");
    return regex_replace(s,whitespaces," ");
}

class CloudClient {
    ScopedSocket user_sock;
    ScopedSocket data_sock;
    bool is_logged_in = false;
    unsigned long token;

    // Helper: Send exactly N bytes
    bool send_all(int fd, const void* data, size_t length) {
        const char* ptr = static_cast<const char*>(data);
        size_t total_sent = 0;
        while (total_sent < length) {
            ssize_t sent = send(fd, ptr + total_sent, length - total_sent, 0);
            if (sent <= 0) return false;
            total_sent += sent;
        }
        return true;
    }

    // Helper: Receive exactly N bytes
    bool recv_all(int fd, void* buffer, size_t length) {
        char* ptr = static_cast<char*>(buffer);
        size_t total_received = 0;
        while (total_received < length) {
            ssize_t r = recv(fd, ptr + total_received, length - total_received, 0);
            if (r <= 0) return false; // Server disconnected
            total_received += r;
        }
        return true;
    }

public:
    bool connect(string ip, int port) {
        return user_sock.connect_to_server(ip,port);
    }
    void send_link_packet(ScopedSocket &client, unsigned long token) {
        LinkData payload;
        payload.session_token = token;

        Header header;
        header.op_code = DATA_LINK;
        header.packet_identifier = PACKET_IDENTIFIER;
        header.data_len = htonl(sizeof(payload));

        std::vector<unsigned char> packet;
        packet.resize(sizeof(header) + sizeof(payload));
        
        memcpy(packet.data(), &header, sizeof(header));
        memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

        if (!send_all(client.get(), packet.data(), packet.size())) {
            cerr << "Failed to send Link packet.\n";
        }
    }
    bool register_user(const string &username, const string &password) {
        if (!user_sock.is_valid()) {
            cerr << "Not connected.\n";
            return 0;
        }
        LoginData payload;
        bzero(&payload,sizeof(payload));

        strncpy((char*)payload.username, username.c_str(), sizeof(payload.username) - 1);
        strncpy((char*)payload.password, password.c_str(), sizeof(payload.password) - 1);
    
        Header header;
        header.op_code = REGISTER;
        header.packet_identifier = PACKET_IDENTIFIER;
        header.data_len = htonl(sizeof(payload));

        vector<unsigned char> packet;
        packet.resize(sizeof(header) + sizeof(payload));
        
        memcpy(packet.data(), &header, sizeof(header));
        memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

        if (!send_all(user_sock.get(), packet.data(), packet.size())) {
            cerr << "Failed to send Register packet.\n";
            return 0;
        }

        cout << "Register request sent. Waiting for response...\n";
        Header resp_header;
        if (recv_all(user_sock.get(), &resp_header, sizeof(resp_header))) {
            if(resp_header.op_code == OK && resp_header.packet_identifier == PACKET_IDENTIFIER) {
                return 1;
            }else if(resp_header.op_code == ERROR && resp_header.packet_identifier == PACKET_IDENTIFIER) {
                return 0;
            }else if(resp_header.op_code == ERR_ALR_REG && resp_header.packet_identifier == PACKET_IDENTIFIER) {
                cout<<"Acest username este deja folosit\n";
                return 0;
            }
        }
    }
    unsigned long login(const std::string& username, const std::string& password) {
        if (!user_sock.is_valid()) {
            cerr << "Not connected.\n";
            return 0;
        }

        // 1. Prepare Payload
        LoginData payload;
        // Zero out memory to prevent leaking stack garbage
        bzero(&payload,sizeof(payload));
        
        // Safe copy (truncates if too long)
        strncpy((char*)payload.username, username.c_str(), sizeof(payload.username) - 1);
        strncpy((char*)payload.password, password.c_str(), sizeof(payload.password) - 1);

        // 2. Prepare Header
        Header header;
        header.op_code = LOGIN;
        header.packet_identifier = PACKET_IDENTIFIER;
        header.data_len = htonl(sizeof(payload));

        // 3. Send
        std::vector<unsigned char> packet;
        packet.resize(sizeof(header) + sizeof(payload));
        
        memcpy(packet.data(), &header, sizeof(header));
        memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

        if (!send_all(user_sock.get(), packet.data(), packet.size())) {
            cerr << "Failed to send Login packet.\n";
            return 0;
        }

        cout << "Login request sent. Waiting for response...\n";

        // 4. Wait for Response (Blocking)
        Header resp_header;
        if (recv_all(user_sock.get(), &resp_header, sizeof(resp_header))) {
            if (resp_header.op_code == OK && resp_header.packet_identifier == PACKET_IDENTIFIER) {
                std::cout << "Login Successful!\n";
                is_logged_in = true;
                
                // Read LoginResponse payload
                LoginResponse resp_payload;
                if (recv_all(user_sock.get(), &resp_payload, sizeof(resp_payload))) {
                    return resp_payload.session_token;
                } else {
                    cerr << "Failed to receive login response payload.\n";
                    return 0;
                }
            } else if(resp_header.op_code == ERROR && resp_header.packet_identifier == PACKET_IDENTIFIER) {
                cerr << "Login Failed. Server responded with OpCode: " << (int)resp_header.op_code << "\n";
                return 0;
            }
        } else {
            cerr << "Server disconnected during login.\n";
            return 0;
        }
    }

    void loop() {
        string line;
        while (true) {
            cout << "> ";
            if (!getline(cin, line)) break;
            if (line == "exit") break;

            // Simple command parser
            if (line.rfind("login", 0) == 0) {
                // Parse "login user pass"
                line = trim(line);
                if(line == "") {
                    cout<<"Nu prea am ce sa fac cu spatii, introdu si tu macar un caracter\n";
                    continue;
                }
                if(is_logged_in == false) {
                    unsigned long first_space = line.find(' ');
                    unsigned long second_space = line.find(' ', first_space + 1);
                    
                    if (first_space == string::npos || second_space == string::npos) {
                        cout << "Sintaxa: login <username> <password>\n";
                        continue;
                    }
    
                    std::string user = line.substr(first_space + 1, second_space - first_space - 1);
                    std::string pass = line.substr(second_space + 1);
                    this->token = login(user, pass);
                    if(this->token == 0) {
                        cout<<"Login falied\n";continue;
                    } else if(this->token != 0) {
                        data_sock.connect_to_server("127.0.0.1",PORT);
                        
                        send_link_packet(data_sock,this->token);
        
                        cout<<"Conexiune FPT facuta\n";
                    }
                }else {
                    cout<<"Esti deja logat\n";
                    continue;
                }
            } else if(line.rfind("register",0) == 0) {
                if(is_logged_in == false) {
                    unsigned long first_space = line.find(' ');
                    unsigned long second_space = line.find(' ', first_space + 1);
                        
                    if (first_space == string::npos || second_space == string::npos) {
                        cout << "Usage: register <username> <password>\n";
                        continue;
                        }
        
                    string user = line.substr(first_space + 1, second_space - first_space - 1);
                    string pass = line.substr(second_space + 1);
                    bool is_registered = register_user(user,pass);
                    if(is_registered) {
                        cout<<"Inregistrat cu succes. Acum te poti loga\n";
                        continue;
                    }else {
                        cout<<"Eroare la inregistrarea, incearca din nou\n";
                        continue;
                    }
                }
            } else if(line.rfind("upload") == 0){

            } else if (line == "help" && is_logged_in) {
                cout << "Commands: \n\tlogin <u> <p>\n\tupload <f>\n\tdownload <f>\n\tlist\n\tdelete <f>\n\texit\n";
            } else if(!is_logged_in){
                cout << "Unknown command. Try 'login' or 'exit'.\n";
            } else if(is_logged_in) {
                cout<<"Unknown command. Try 'upload', 'download', 'list', 'delete' or 'exit'\n";
            }
        }
    }
};

int main() {
    CloudClient client;
    
    // Connect to localhost by default
    if (!client.connect("127.0.0.1", PORT)) {
        return 1;
    }

    client.loop();
    return 0;
}