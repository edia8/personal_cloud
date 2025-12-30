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
constexpr unsigned char LOGOUT = 0x0A;

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
    int user_id;
};

struct ListRequest {
    int parent_id;
};

struct FileInfo {
    int id;
    char name[64];
    unsigned long size;
    bool is_folder;
};

struct PrepareUploadRequest {
    unsigned long filesize;
    char filename[64];
    int parent_id;
};



//functie de send care nu trimite data partial
bool send_full_packet(int fd, const void* data, unsigned long length);

// functie de recieve care nu primeste data partial
bool recv_full_packet(int fd, void* buffer, unsigned long length);
