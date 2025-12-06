#pragma once
constexpr int PORT = 6969;
constexpr int MAX_EVENTS = 100;
constexpr int THREAD_POOL_SIZE = 8;
constexpr unsigned char PACKET_IDENTIFIER = 0xE3;

constexpr unsigned char RESET_CODE = 0x00;
constexpr unsigned char REGISTER = 0x06;
constexpr unsigned char LOGIN = 0x01;
constexpr unsigned char DATA_LINK = 0x09;
constexpr unsigned char PREPARE_DOWNLOAD = 0x12;
constexpr unsigned char DOWNLOAD = 0x02;
constexpr unsigned char PREPARE_UPLOAD = 0x13;
constexpr unsigned char UPLOAD = 0x03;
constexpr unsigned char LIST = 0x04;
constexpr unsigned char DELETE = 0x05;

constexpr unsigned char ERROR = 0xFF;
constexpr unsigned char ERR_ALR_REG = 0xF1;
constexpr unsigned char OK = 0xFE;

struct Header {
unsigned long data_len;
unsigned char op_code;
unsigned char packet_identifier;
};

struct LoginData {
    unsigned char username[32];
    unsigned char password[64];
};
struct LinkData {
    unsigned long session_token;
};
struct LoginResponse {
    unsigned long session_token;
};

/*Implementation Guide for You (Next Steps)
Thread Pool (threadpool.h):
Look at process_task. This is the brain.
Look at handle_login. Currently, it compares strings "admin"/"secret". You need to add SQLite logic there.
Network (network.h):
Look at handle_client_data. This is where the Binary Protocol is enforced.
Currently, it does a "naive" recv (it assumes the network is fast enough to send the whole packet instantly). Later, you will need to implement a buffer loop to handle "partial packets" for large file uploads.
Session (session.h):
This is fully functional. It uses a shared_mutex so 100 threads can read is_authenticated simultaneously without slowing each other down.
This architecture gives you the Security (Gatekeeper) and Performance (Epoll/Threads) you asked for.*/