#pragma once
#include    <unordered_map>
#include    <string>
#include    <vector>
#include    <pthread.h>
#include    <random>
#include    <unistd.h>

using namespace std;

enum SocketType {
    NEAUTENTIFICAT,
    USER,
    DATA
};

struct ClientStat {
    SocketType type = SocketType::NEAUTENTIFICAT;
    int op_code;
    int user_id = -1;
    string username;
    bool has_header = false;
    vector<unsigned char> upload_buffer;
    unsigned long expected_len=0;
    // TODO: Phase 3 - Add Encryption Context here
    // uint8_t aes_key[32];
    // uint8_t aes_iv[16];
};

class SessionManager {
private:
    unordered_map<unsigned long, int> tokenToUserID;
    unordered_map<int,ClientStat> sessions;
    pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
    pthread_rwlock_t token_lock = PTHREAD_RWLOCK_INITIALIZER;
public:
    //epoll
    void add_session(int fd) {
        pthread_rwlock_wrlock(&lock);
        sessions[fd] = ClientStat();
        pthread_rwlock_unlock(&lock);
    }
    void remove_session(int fd) {
        pthread_rwlock_wrlock(&lock);
        sessions.erase(fd);
        pthread_rwlock_unlock(&lock);

    }
    //by thread
    ClientStat* get_client_stats(int fd) {
        pthread_rwlock_rdlock(&lock);
        auto it = sessions.find(fd);
        ClientStat *ret = nullptr;
        if(it != sessions.end()) {
            ret =  &it->second;
        }
        pthread_rwlock_unlock(&lock);
        return ret;
    }
    void set_auth_user(int fd,int user_id, const string name) {
        pthread_rwlock_wrlock(&lock);
        sessions[fd].type = SocketType::USER;
        sessions[fd].user_id = user_id;
        sessions[fd].username = name;
        pthread_rwlock_unlock(&lock);
    }
    void set_auth_data(int fd,int user_id) {
        pthread_rwlock_wrlock(&lock);
        sessions[fd].type = SocketType::DATA;
        sessions[fd].user_id = user_id;
        pthread_rwlock_unlock(&lock);
    }
    int get_user_id(int fd) {
        pthread_rwlock_rdlock(&lock);
        int user_id = -1;
        auto it = sessions.find(fd);
        if(it != sessions.end()) {
            user_id = it->second.user_id;
        }
        pthread_rwlock_unlock(&lock);
        return user_id;
    }
    //token system
    unsigned long generate_token(int user_id) {
        pthread_rwlock_wrlock(&token_lock);
        unsigned long token = (unsigned long)rand() << 32 | rand();
        tokenToUserID[token] = user_id;
        pthread_rwlock_unlock(&token_lock);
        return token;
    }

    int redeem_token(unsigned long token) {
        pthread_rwlock_rdlock(&token_lock);
        auto it = tokenToUserID.find(token);
        int uid = -1;
        if(it != tokenToUserID.end()) {
            uid = it->second;
        }
        pthread_rwlock_unlock(&token_lock);
        return uid;
    }

    void logout_user(int user_id) {
        //remove DATA sessions
        pthread_rwlock_wrlock(&lock);
        for(auto it = sessions.begin(); it != sessions.end(); ) {
            if(it->second.user_id == user_id && it->second.type == SocketType::DATA) {
                //daca inchid socket-ul este scos din epoll
                close(it->first); 
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }
        pthread_rwlock_unlock(&lock);

        //scot token-urile
        pthread_rwlock_wrlock(&token_lock);
        for(auto it = tokenToUserID.begin(); it != tokenToUserID.end(); ) {
            if(it->second == user_id) {
                it = tokenToUserID.erase(it);
            } else {
                ++it;
            }
        }
        pthread_rwlock_unlock(&token_lock);
    }
};