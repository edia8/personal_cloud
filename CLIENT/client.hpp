#pragma once
#include    <string>
#include    <vector>
#include    <iostream>
#include    <sys/socket.h>
#include    <arpa/inet.h>
#include    <unistd.h>
#include    <pthread.h>
#include    <queue>
#include    "protocol.hpp"

#define IP "127.0.0.1"
#define SV "10.100.0.30"


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
    pthread_mutex_t mutex_user = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_data = PTHREAD_MUTEX_INITIALIZER;
    bool is_logged_in = false;
    unsigned long token;
    int user_id = -1;

    // Upload Queue
    struct UploadTask {
        string filename;
        int current_folder_id;
        void (*callback)(int, void*);
        void* callback_arg;
    };
    queue<UploadTask> upload_queue;
    pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
    pthread_t worker_thread;
    bool stop_worker = false;
    bool worker_started = false;

    static void* worker_entry(void* arg);
    void worker_routine();

public:
    bool connect(string ip, int port);
    void send_link_packet(unsigned long token);
    int register_user(const string &user, const string &pass);
    unsigned long login(const string &user, const string &pass);
    int upload(string filename);
    void upload_async(string filename,int curent_folder_id, void (*callback)(int, void*), void* arg);
    int download(string filename);
    string del(string filename);
    vector<FileInfo> list_files(int parent_id);
    void close_client();
    int get_uid() const { return user_id; }
};
