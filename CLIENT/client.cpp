#include "client.hpp"
#include    <cstring>
#include    <fcntl.h>
#include    <sys/stat.h>
#include    <endian.h>
#include    <cstdio>
#include    <openssl/evp.h>
#include    <openssl/rand.h>
#include    <sstream>
#include    <iomanip>

using namespace std;

string sha256(const string& str) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;
    
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if(context == nullptr) return "";

    if(!EVP_DigestInit_ex(context, EVP_sha256(), nullptr)) {
        EVP_MD_CTX_free(context);
        return "";
    }
    if(!EVP_DigestUpdate(context, str.c_str(), str.length())) {
        EVP_MD_CTX_free(context);
        return "";        
    }
    
    if(EVP_DigestFinal_ex(context, hash, &lengthOfHash)) {
        EVP_MD_CTX_free(context);
        
        char hex_string[65];
        for(unsigned int i = 0; i < lengthOfHash; ++i)
            sprintf(hex_string + (i * 2), "%02x", hash[i]);
        
        return string(hex_string);
    }
    EVP_MD_CTX_free(context);
    return "";
}

//functie de send care nu trimite data partial
bool send_full_packet(int fd, const void* data, unsigned long length) {
    const char* ptr = static_cast<const char*>(data);
    unsigned long total_sent = 0;
    while (total_sent < length) {
        long sent = write(fd, ptr + total_sent, length - total_sent);
        if (sent <= 0) return false;//sv deconectat
        total_sent += sent;
    }
    return true;
}

// functie de recieve care nu primeste data partial
bool recv_full_packet(int fd, void* buffer, unsigned long length) {
    char* ptr = static_cast<char*>(buffer);
    unsigned long total_received = 0;
    while (total_received < length) {
        long r = read(fd, ptr + total_received, length - total_received);
        if (r <= 0) return false; //sv deconectat
        total_received += r;
    }
    return true;
}

bool ClientBackend::connect(string ip, int port) {
    return user_sock.connect_to_server(ip,port);
}

ClientBackend::~ClientBackend() {
    if (active_uploads > 0) {
        cout << "[Client] Waiting for active uploads to finish...\n";
        while (active_uploads > 0) {
            usleep(100000); // 100ms
        }
        cout << "[Client] All uploads finished.\n";
    }
    close_client();
}

void ClientBackend::close_client() {

    if (!user_sock.is_valid()) return;

    //send logout packet
    Header header;
    header.op_code = LOGOUT;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = 0;

    pthread_mutex_lock(&mutex_user);

    if (!send_full_packet(user_sock.get(), &header, sizeof(header))) {
        cerr << "Failed to send LOGOUT packet.\n";
        pthread_mutex_unlock(&mutex_user);
        return;
    }

    //asteapta ok
    Header resp;
    if (recv_full_packet(user_sock.get(), &resp, sizeof(resp))) {
        if (resp.op_code == OK) {
            cout << "Logout successful.\n";
        } else {
            cerr << "Logout failed or server error.\n";
        }
    } else {
        cerr << "Server disconnected during logout.\n";
    }
    pthread_mutex_unlock(&mutex_user);
    //inchid socket
    data_sock.reset(-1);
    
    is_logged_in = false;
}

void ClientBackend::send_link_packet(unsigned long token) {
    if (!data_sock.is_valid()) {
        data_sock.connect_to_server(IP, PORT); 
    }

    LinkData payload;
    payload.session_token = token;

    Header header;
    header.op_code = DATA_LINK;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htobe64(sizeof(payload));

    std::vector<unsigned char> packet;
    packet.resize(sizeof(header) + sizeof(payload));
    
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

    if (!send_full_packet(data_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send Link packet.\n";
    } else {
        cout << "Conexiune FPT facuta\n";
    }
}

int ClientBackend::register_user(const string &username, const string &password) {
    if (!user_sock.is_valid()) {
        cerr << "Not connected.\n";
        return 0;
    }
    LoginData payload;
    bzero(&payload,sizeof(payload));

    string hashed_pass = sha256(password);
    strncpy((char*)payload.username, username.c_str(), sizeof(payload.username) - 1);
    strncpy((char*)payload.password, hashed_pass.c_str(), sizeof(payload.password) - 1);

    Header header;
    header.op_code = REGISTER;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htobe64(sizeof(payload));

    vector<unsigned char> packet;
    packet.resize(sizeof(header) + sizeof(payload));
    
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

    pthread_mutex_lock(&mutex_user);

    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send Register packet.\n";
        pthread_mutex_unlock(&mutex_user);
        return 0;
    }

    cout << "Register request sent. Waiting for response...\n";
    Header resp_header;
    if (recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        if(resp_header.op_code == OK && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            pthread_mutex_unlock(&mutex_user);
            return 1;//cod success
        }else if(resp_header.op_code == ERROR && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            pthread_mutex_unlock(&mutex_user);
            return 0;//cod eroare 
        }else if(resp_header.op_code == ERR_ALR_REG && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            cout<<"Acest username este deja folosit\n";
            pthread_mutex_unlock(&mutex_user);
            return 2; //cod pt user_alr_used
        }
    }
    pthread_mutex_unlock(&mutex_user);
    return 0;
}

unsigned long ClientBackend::login(const std::string& username, const std::string& password) {
    if (!user_sock.is_valid()) {
        cerr << "Not connected.\n";
        return 0;
    }

    LoginData payload;
    //bzero pt evitare garbage
    bzero(&payload,sizeof(payload));
    
    string hashed_pass = sha256(password);
    strncpy((char*)payload.username, username.c_str(), sizeof(payload.username) - 1);
    strncpy((char*)payload.password, hashed_pass.c_str(), sizeof(payload.password) - 1);

    Header header;
    header.op_code = LOGIN;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htobe64(sizeof(payload));

    //trimit header+creds
    std::vector<unsigned char> packet;
    packet.resize(sizeof(header) + sizeof(payload));
    
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));
    
    pthread_mutex_lock(&mutex_user);

    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send Login packet.\n";
        pthread_mutex_unlock(&mutex_user);
        return 0;
    }

    cout << "S-a trimit req de login. Waiting for response...\n";

    //asteptam pentru raspuns
    Header resp_header;
    if (recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        if (resp_header.op_code == OK && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            std::cout << "Login Successful!\n";
            is_logged_in = true;
            
            //citim raspuns de login
            LoginResponse resp_data;
            if (recv_full_packet(user_sock.get(), &resp_data, sizeof(resp_data))) {
                this->user_id = resp_data.user_id;
                pthread_mutex_unlock(&mutex_user);
                return resp_data.session_token;
            } else {
                cerr << "Nu s-a primit login data.\n";
                pthread_mutex_unlock(&mutex_user);
                return 0;
            }
        } else if(resp_header.op_code == ERROR && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            cerr << "Login Failed. Server responded with OpCode: " << (int)resp_header.op_code << "\n";
            pthread_mutex_unlock(&mutex_user);
            return 0;
        }
    } else {
        cerr << "Server disconnected during login.\n";
        pthread_mutex_unlock(&mutex_user);
        return 0;
    }
    return 0;
}



int ClientBackend::upload(string filename) {
    if (!user_sock.is_valid() || !data_sock.is_valid()) {
        cerr << "Sockets not connected.\n";
        return 1;//"Error: Sockets not connected"
    }

    FILE *file_fd = fopen(filename.c_str(),"rb");
    if(file_fd == nullptr) {
        cerr<<"Nu s-a putut deschide fisierul"<<filename;
        return 8;
    }
    
    struct stat st;
    if(-1 == stat(filename.c_str(),&st)) {
        cerr<< "Eroare la populare stat\n";
        fclose(file_fd);
        return 9;
    }
    unsigned long int filesize = st.st_size;

    // Extract filename from path
    string base_filename = filename;
    unsigned long last_slash = filename.find_last_of("/\\");
    if (last_slash != string::npos) {
        base_filename = filename.substr(last_slash + 1);
    }

    //initiere handshake
    PrepareUploadRequest req;
    
    unsigned long encrypted_size = (filesize / 16 + 1) * 16;
    if (filesize % 16 == 0) encrypted_size = filesize + 16;
    req.filesize = htobe64(encrypted_size);

    strncpy(req.filename, base_filename.c_str(), 63);
    req.filename[63] = '\0';

    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        cerr << "Failed to generate random key.\n";
        fclose(file_fd);
        return 1;
    }
    memcpy(req.file_key, key, 32);

    Header prep_header;
    prep_header.op_code = PREPARE_UPLOAD;
    prep_header.packet_identifier = PACKET_IDENTIFIER;
    prep_header.data_len = htobe64(sizeof(req));

    pthread_mutex_lock(&mutex_data);
    pthread_mutex_lock(&mutex_user);

    vector<unsigned char> packet;
    packet.resize(sizeof(prep_header) + sizeof(req));
    memcpy(packet.data(), &prep_header, sizeof(prep_header));
    memcpy(packet.data() + sizeof(prep_header), &req, sizeof(req));

    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send PREPARE_UPLOAD.\n";
        pthread_mutex_unlock(&mutex_user);
        pthread_mutex_unlock(&mutex_data);
        fclose(file_fd);
        return 2;//"Error: Failed to send PREPARE_UPLOAD"
    }

    //asteptam ok de la sv
    Header resp_header;
    if (!recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        cerr << "Server disconnected during prepare phase.\n";
        pthread_mutex_unlock(&mutex_user);
        pthread_mutex_unlock(&mutex_data);
        fclose(file_fd);
        return 3;//"Error: Server disconnected";
    }

    if (resp_header.op_code != OK) {
        cerr << "Server denied upload request.\n";
        pthread_mutex_unlock(&mutex_user);
        pthread_mutex_unlock(&mutex_data);
        fclose(file_fd);
        return 4;//"Error: Server denied upload request";
    }
    cout << "Server is ready for data.\n";
    pthread_mutex_unlock(&mutex_user);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    unsigned char in_buffer[4096];
    unsigned char out_buffer[4096 + 16]; 
    int out_len;
    
    while (true) {
        size_t bytes_read = fread(in_buffer, 1, sizeof(in_buffer), file_fd);
        if (bytes_read > 0) {
            EVP_EncryptUpdate(ctx, out_buffer, &out_len, in_buffer, bytes_read);
            
            if (out_len > 0) {
                Header data_header;
                data_header.op_code = UPLOAD;
                data_header.packet_identifier = PACKET_IDENTIFIER;
                data_header.data_len = htobe64(out_len);

                vector<unsigned char> packet;
                packet.resize(sizeof(data_header) + out_len);
                memcpy(packet.data(), &data_header, sizeof(data_header));
                memcpy(packet.data() + sizeof(data_header), out_buffer, out_len);

                if (!send_full_packet(data_sock.get(), packet.data(), packet.size())) {
                    cerr << "Failed to send file data.\n";
                    break;
                }
            }
        } else {
            break;
        }
    }
    
    EVP_EncryptFinal_ex(ctx, out_buffer, &out_len);
    if (out_len > 0) {
        Header data_header;
        data_header.op_code = UPLOAD;
        data_header.packet_identifier = PACKET_IDENTIFIER;
        data_header.data_len = htobe64(out_len);

        vector<unsigned char> packet;
        packet.resize(sizeof(data_header) + out_len);
        memcpy(packet.data(), &data_header, sizeof(data_header));
        memcpy(packet.data() + sizeof(data_header), out_buffer, out_len);
        send_full_packet(data_sock.get(), packet.data(), packet.size());
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(file_fd);

    //citim header
    Header echo_header;
    if (!recv_full_packet(data_sock.get(), &echo_header, sizeof(echo_header))) {
        cerr << "Failed to receive echo header.\n";
        pthread_mutex_unlock(&mutex_data);
        return 6;//"Error: Failed to receive echo header";
    }

    if (echo_header.op_code == OK) {
        pthread_mutex_unlock(&mutex_data);
        return 0;
    }

    //citim data
    unsigned int payload_len = be64toh(echo_header.data_len);
    vector<char> echo_buffer(payload_len + 1); // +1 pt NULLLLL
    
    if (!recv_full_packet(data_sock.get(), echo_buffer.data(), payload_len)) {
        cerr << "Failed to receive echo data.\n";
        pthread_mutex_unlock(&mutex_data);
        return 7;//"Error: Failed to receive echo data";
    }
    
    echo_buffer[payload_len] = '\0'; // NU UITA DE NULL
    cout << "Server responded: " << echo_buffer.data() << '\n';
    pthread_mutex_unlock(&mutex_data);

    return 7; // Error because not OK

}

struct UploadContext {
    ClientBackend* instance;
    string filename;
    void (*callback)(int, void*);
    void* callback_arg;
};

static void* upload_thread_func(void* arg) {
    UploadContext* ctx = (UploadContext*)arg;
    int res = ctx->instance->upload(ctx->filename);
    if (ctx->callback) {
        ctx->callback(res, ctx->callback_arg);
    }
    ctx->instance->notify_upload_finished();
    delete ctx;
    return nullptr;
}

void ClientBackend::upload_async(string filename, void (*callback)(int, void*), void* arg) {
    UploadContext* ctx = new UploadContext{this, filename, callback, arg};
    pthread_t thread;
    active_uploads++;
    if (pthread_create(&thread, nullptr, upload_thread_func, ctx) != 0) {
        cerr << "Failed to create upload thread.\n";
        active_uploads--;
        delete ctx;
        // Optionally call callback with error immediately
        if (callback) callback(-1, arg);
    } else {
        pthread_detach(thread);
    }
}

int ClientBackend::download(string filename) {
    if (!user_sock.is_valid() || !data_sock.is_valid()) {
        cerr << "Sockets not connected.\n";
        pthread_mutex_unlock(&mutex_user);
        return 1;
    }

    // trimite header ca sv sa astepte download
    Header prep_header;
    prep_header.op_code = PREPARE_DOWNLOAD;
    prep_header.packet_identifier = PACKET_IDENTIFIER;
    prep_header.data_len = 0; //Header gol pt handshake

    pthread_mutex_lock(&mutex_data);
    pthread_mutex_lock(&mutex_user);

    if (!send_full_packet(user_sock.get(), &prep_header, sizeof(prep_header))) {
        cerr << "Nu s-a trimis PREPARE_DOWNLOAD.\n";
        pthread_mutex_unlock(&mutex_user);
        pthread_mutex_unlock(&mutex_data);
        return 2;
    }

    // astept ok
    Header resp_header;
    if (!recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        cerr << "Server deconectat.\n";
        pthread_mutex_unlock(&mutex_user);
        pthread_mutex_unlock(&mutex_data);
        return 3;
    }

    if (resp_header.op_code != OK) {
        cerr << "Server nu vrea download request.\n";
        pthread_mutex_unlock(&mutex_user);
        pthread_mutex_unlock(&mutex_data);
        return 4;
    }
    cout << "Server e gata pentru data.\n";

    pthread_mutex_unlock(&mutex_user);
    
    // s-a facut handshake, trimitem data
    string demo_data = filename;
    
    Header data_header;
    data_header.op_code = DOWNLOAD;
    data_header.packet_identifier = PACKET_IDENTIFIER;
    data_header.data_len = htobe64(demo_data.size());

    vector<unsigned char> packet;
    packet.resize(sizeof(data_header) + demo_data.size());

    memcpy(packet.data(), &data_header, sizeof(data_header));
    memcpy(packet.data() + sizeof(data_header), demo_data.c_str(), demo_data.size());

    if (!send_full_packet(data_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send data packet.\n";
        pthread_mutex_unlock(&mutex_data);
        return 5;
    }

    // Wait for DOWNLOAD header with file size
    Header file_header;
    if (!recv_full_packet(data_sock.get(), &file_header, sizeof(file_header))) {
        cerr << "Failed to receive file header.\n";
        pthread_mutex_unlock(&mutex_data);
        return 6;
    }

    if (file_header.op_code == ERROR) {
        cerr << "Server reported error during download.\n";
        pthread_mutex_unlock(&mutex_data);
        return 8;
    }

    if (file_header.op_code != DOWNLOAD) {
        cerr << "Unexpected header opcode: " << (int)file_header.op_code << "\n";
        pthread_mutex_unlock(&mutex_data);
        return 9;
    }

    unsigned long filesize = be64toh(file_header.data_len);
    
    unsigned char key[32];
    if (!recv_full_packet(data_sock.get(), key, 32)) {
        cerr << "Failed to receive encryption key.\n";
        pthread_mutex_unlock(&mutex_data);
        return 14;
    }
    filesize -= 32;

    FILE *f = fopen(filename.c_str(), "wb");
    if (!f) {
        cerr << "Cannot open file for writing: " << filename << "\n";
        pthread_mutex_unlock(&mutex_data);
        return 10;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);

    unsigned long received = 0;
    unsigned char in_buffer[4096];
    unsigned char out_buffer[4096 + 16];
    int out_len;

    while (received < filesize) {
        unsigned long chunk = sizeof(in_buffer);
        if (filesize - received < chunk) chunk = filesize - received;
        
        if (!recv_full_packet(data_sock.get(), in_buffer, chunk)) {
            cerr << "Connection lost during download.\n";
            fclose(f);
            remove(filename.c_str());
            pthread_mutex_unlock(&mutex_data);
            return 11;
        }
        
        EVP_DecryptUpdate(ctx, out_buffer, &out_len, in_buffer, chunk);
        if (out_len > 0) {
            fwrite(out_buffer, 1, out_len, f);
        }
        received += chunk;
    }
    
    EVP_DecryptFinal_ex(ctx, out_buffer, &out_len);
    if (out_len > 0) {
        fwrite(out_buffer, 1, out_len, f);
    }

    EVP_CIPHER_CTX_free(ctx);
    fclose(f);

    // Wait for final OK
    Header ok_header;
    if (!recv_full_packet(data_sock.get(), &ok_header, sizeof(ok_header))) {
        cerr << "Failed to receive final OK.\n";
        pthread_mutex_unlock(&mutex_data);
        return 12;
    }

    if (ok_header.op_code != OK) {
        cerr << "Final packet was not OK.\n";
        pthread_mutex_unlock(&mutex_data);
        return 13;
    }

    pthread_mutex_unlock(&mutex_data);
    return 0;
}
string ClientBackend::del(string filename) {
    if (!user_sock.is_valid()) {
        cerr << "Socket neconectat.\n";
        return "Error: Socket neconectat";
    }
    Header del_h;
    string demo_data = filename;
    del_h.packet_identifier = PACKET_IDENTIFIER;
    del_h.op_code = DELETE;
    del_h.data_len = htobe64(demo_data.size());
    vector<unsigned char> packet;
    packet.resize(sizeof(del_h) + demo_data.size());

    memcpy(packet.data(), &del_h, sizeof(del_h));
    memcpy(packet.data() + sizeof(del_h), demo_data.c_str(), demo_data.size());

    pthread_mutex_lock(&mutex_user);

    if(!send_full_packet(user_sock.get(),packet.data(),packet.size())) {
        cerr<<"Eroare la trimitere delete\n";
        pthread_mutex_unlock(&mutex_user);
        return "Error: trimitere delete";
    }
    //procesare sv
    Header del_resp;
    if(!recv_full_packet(user_sock.get(),&del_resp,sizeof(del_resp))) {
        cerr<<"Eroare la primire delete\n";
        pthread_mutex_unlock(&mutex_user);
        return "Error: primire delete";
    }
    if(del_resp.op_code!=OK || del_resp.packet_identifier != PACKET_IDENTIFIER){
        cerr<<"Eroare la pachet code";
        pthread_mutex_unlock(&mutex_user);
        return "Error: pachetul nu este bun";
    }
    unsigned int len = be64toh(del_resp.data_len);
    vector<char> buffer(len+1);
    
    if (!recv_full_packet(user_sock.get(), buffer.data(),len)) {
        cerr << "Nu s-a primit data.\n";
        pthread_mutex_unlock(&mutex_user);
        return "Error: Nu s-a primit data";
    }
    buffer[len] = '\0';
    cout<<"Server a trimis "<<buffer.data()<<'\n';
    pthread_mutex_unlock(&mutex_user);
    return string(buffer.data());
}

vector<FileInfo> ClientBackend::list_files() {
    if (!user_sock.is_valid()) return {};

    Header header;
    header.op_code = LIST;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = 0;

    vector<unsigned char> packet;
    packet.resize(sizeof(header));
    memcpy(packet.data(), &header, sizeof(header));

    pthread_mutex_lock(&mutex_user);
    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        pthread_mutex_unlock(&mutex_user);
        return {};
    }

    Header resp_header;
    if (!recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        pthread_mutex_unlock(&mutex_user);
        return {};
    }

    if (resp_header.op_code != OK) {
        pthread_mutex_unlock(&mutex_user);
        return {};
    }

    unsigned long len = be64toh(resp_header.data_len);
    vector<FileInfo> files(len / sizeof(FileInfo));
    if (len > 0) {
        if (!recv_full_packet(user_sock.get(), files.data(), len)) {
            pthread_mutex_unlock(&mutex_user);
            return {};
        }
    }
    pthread_mutex_unlock(&mutex_user);
    return files;
}

string ClientBackend::share_file(string filename, string target_username) {
    if (!user_sock.is_valid()) {
        return "Error: Not connected";
    }

    ShareRequest req;
    bzero(&req, sizeof(req));
    
    strncpy(req.filename, filename.c_str(), sizeof(req.filename) - 1);
    strncpy(req.target_username, target_username.c_str(), sizeof(req.target_username) - 1);

    Header header;
    header.op_code = SHARE_FILE;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htobe64(sizeof(req));

    vector<unsigned char> packet;
    packet.resize(sizeof(header) + sizeof(req));
    
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), &req, sizeof(req));

    pthread_mutex_lock(&mutex_user);

    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        pthread_mutex_unlock(&mutex_user);
        return "Error: Failed to send share request";
    }

    Header resp;
    if (!recv_full_packet(user_sock.get(), &resp, sizeof(resp))) {
        pthread_mutex_unlock(&mutex_user);
        return "Error: Server disconnected";
    }

    unsigned long len = be64toh(resp.data_len);
    if (len > 0) {
        vector<char> buffer(len + 1);
        if (!recv_full_packet(user_sock.get(), buffer.data(), len)) {
            pthread_mutex_unlock(&mutex_user);
            return "Error: Failed to receive response message";
        }
        buffer[len] = '\0';
        pthread_mutex_unlock(&mutex_user);
        return string(buffer.data());
    }

    pthread_mutex_unlock(&mutex_user);

    if (resp.op_code == OK) {
        return "Success: File shared with " + target_username;
    } else {
        return "Error: Could not share file (User not found or File invalid)";
    }
}
