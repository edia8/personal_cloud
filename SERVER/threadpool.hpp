#pragma once
#include    <cstring>
#include    <queue>
#include    <cstring>
#include    <unistd.h>
#include    <iostream>
#include    <arpa/inet.h>
#include    <sys/epoll.h>
#include    <endian.h>
#include    <cstdio>
#include    <sys/stat.h>
#include    <ctime>
#include    <fstream>
#include    <fcntl.h>
#include    <sys/sendfile.h>
#include    <map>
#include    "protocol.hpp"
#include    "session.hpp"
#include    "database.hpp"

struct DownloadState {
    int file_fd;
    off_t offset;
    size_t file_size;
    string filename;
};

struct Task {
    int socket_fd;
    int epoll_fd;
};
class ThreadPool {
private:
    DataBase db{"user_database.db"};
    vector<pthread_t> mestesugari;
    queue<Task> tasks;
    pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    bool stop = false;
    SessionManager &session_manager;

    // Download State Management
    map<int, DownloadState> active_downloads;
    pthread_mutex_t download_lock = PTHREAD_MUTEX_INITIALIZER;

    bool is_download_active(int fd) {
        pthread_mutex_lock(&download_lock);
        bool active = active_downloads.find(fd) != active_downloads.end();
        pthread_mutex_unlock(&download_lock);
        return active;
    }

    static void* worker_entry(void *arg) {
        ThreadPool* pool = static_cast<ThreadPool*>(arg);
        pool->worker_routine();
        return nullptr;
    }

    void worker_routine() {
        while(true) {
            Task task;
            pthread_mutex_lock(&queue_lock);
            while(this->tasks.empty() && !this->stop) {
                pthread_cond_wait(&cond,&queue_lock);
            }
            if(this->stop && this->tasks.empty()) {
                pthread_mutex_unlock(&queue_lock);
                return;
            }
            task = move(this->tasks.front());
            this->tasks.pop();
            pthread_mutex_unlock(&queue_lock);

            process_task(task);
        }
    }
    void process_task(Task &task) {
    ClientStat *cs = session_manager.get_client_stats(task.socket_fd);
    if(cs == nullptr) return;

    char buffer[4096];
    long bytes = read(task.socket_fd,buffer,sizeof(buffer));

    if(bytes <= 0) {
        if(bytes == 0 || errno != EAGAIN) {
            close(task.socket_fd);
            session_manager.remove_session(task.socket_fd);
            cout<<"Client Deconectat: "<<task.socket_fd<<'\n';
            return;
        }
    } else {
        cs->upload_buffer.insert(cs->upload_buffer.end(),buffer,buffer+bytes);
    }
    while(true) {
        if(!cs->has_header) {
            if(cs->upload_buffer.size() >= sizeof(Header)) {
                Header *header = (Header*)cs->upload_buffer.data();
                if(header->packet_identifier != PACKET_IDENTIFIER) {
                    close(task.socket_fd);
                    session_manager.remove_session(task.socket_fd);
                    return;
                }
                cs->op_code = header->op_code;
                cs->expected_len = be64toh(header->data_len);
                cs->has_header = true;
                //scot header din buffer-ul partial
                cs->upload_buffer.erase(cs->upload_buffer.begin(),cs->upload_buffer.begin()+sizeof(Header));
            } else {
                break; //trebuie sa mai vina data in buffer
            }
        } //nu pun else pt ca ar da skip dar poate a venit un packet care continea o parte de header si continut

        if(cs->has_header) {
            if(cs->upload_buffer.size() >= cs->expected_len) {
                vector<unsigned char> data(cs->upload_buffer.begin(),cs->upload_buffer.begin()+cs->expected_len);
                cs->upload_buffer.erase(cs->upload_buffer.begin(),cs->upload_buffer.begin()+cs->expected_len);
                    execute_command(task.socket_fd, task.epoll_fd, cs, data);
                    cs->op_code = RESET_CODE;
                    cs->has_header = false;
                    cs->expected_len = 0;
            }else {
                break;
            }   
        }
    }
    struct epoll_event epv;
    uint32_t events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    if (is_download_active(task.socket_fd)) {
        events |= EPOLLOUT;
    }
    epv.events = events;
    epv.data.fd = task.socket_fd;
    epoll_ctl(task.epoll_fd,EPOLL_CTL_MOD,task.socket_fd,&epv);
    }

    void execute_command(int fd, int epoll_fd, ClientStat *cs, vector<unsigned char> &data) {

        if(cs->type == SocketType::NEAUTENTIFICAT) {
            if(cs->op_code == REGISTER) {
                register_handler(fd,cs,data);
            }
            if(cs->op_code == LOGIN) {
                login_handler(fd,cs,data);
            }
            else if(cs->op_code == DATA_LINK) {
                link_handler(fd,cs,data);
            }
            else {
                cout<<"Actiune invalida 1"<<cs->op_code<<'\n';return;
            }
        } else if(cs->type == SocketType::USER) {
            if(cs->op_code == LIST) {
                list_handler(fd,cs,data);
            }
            else if(cs->op_code == PREPARE_DOWNLOAD) {
                prepare_download_handler(fd,cs,data);
            }
            else if(cs->op_code == PREPARE_UPLOAD) {
                prepare_upload_handler(fd,cs,data);
            }
            else if(cs->op_code == DELETE) {
                delete_handler(fd,cs,data);
            }
            else if(cs->op_code == LOGOUT) {
                logout_handler(fd,cs,data);
            }
            else {
                cout<<"Actiune invalida 2\n";return;
            }
        } else if(cs->type == SocketType::DATA) {
                if(cs->op_code == UPLOAD) {
                    upload_handler(fd, cs, data);
                } else if(cs->op_code == DOWNLOAD) {
                    start_download(fd, epoll_fd, cs, data);
                }
                else {
                cout<<"Actiune invalida 3\n";return;                   
                }
        }

    }
    void register_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        LoginData* credentials = (LoginData*)data.data();
        string tmpname = ((char*)credentials->username);
        string tmppass = ((char*)credentials->password);
        int success = db.register_user(tmpname,tmppass);
        if(success==1) {
            Header h = {htobe64((unsigned long)0),OK,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
            cout<<"User inregistrat in db\n";
        }else if(success==2) {
            Header h = {htobe64((unsigned long)0),ERR_ALR_REG,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
        }else {
            Header h = {htobe64((unsigned long)0),ERROR,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
            cout<<"Eroare la register\n";
        }
    }
    void login_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        LoginData* credentials = (LoginData*)data.data();
        int user_id;
        bool success = false;
        //DB check..
        string tmpname = ((char*)credentials->username);
        string tmppass = ((char*)credentials->password);
        user_id = db.verify_login(tmpname,tmppass);
        success = (user_id != -1);
        if(success) {
            unsigned long token = session_manager.generate_token(user_id);
            session_manager.set_auth_user(fd,user_id,tmpname);
            cs->token = token;
            Header h = {htobe64(sizeof(LoginResponse)),OK,PACKET_IDENTIFIER};
            LoginResponse response = {token, user_id};
            //SA SCHIMB CU UN SEND_FULL PACKET SI AICI DUPA
            write(fd,&h,sizeof(h));
            write(fd,&response,sizeof(LoginResponse));
            cout<<"User Logged in, token sent\n";
        } else {
            Header h = {htobe64((unsigned long)0),ERROR,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
        }
    }
    void link_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        LinkData *link = (LinkData*)data.data();
        int user_id = session_manager.redeem_token(link->session_token);
    
        if(user_id != -1) {
            //valid user
            session_manager.set_auth_data(fd,user_id);
            cs->token = link->session_token;
            cout<<"Data socket linked for user with uid "<<user_id<<" Token: " << cs->token << " Session: " << cs << '\n';
        } else {
            cout<<"Invalid token\n";
            close(fd);
        }
    }
    void logout_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        int uid = cs->user_id;
        
        //inchidem sesiunea curenta
        session_manager.logout_user(uid);

        //schimb data la socket
        cs->type = SocketType::NEAUTENTIFICAT;
        cs->user_id = -1;
        cs->username = "";

        //trimit ok la client
        Header h = {0, OK, PACKET_IDENTIFIER};
        write(fd, &h, sizeof(h));
        cout << "User " << uid << " logged out.\n";
    }
    void list_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
                        ListRequest* req = (ListRequest*)data.data();
                int parent_id = req->parent_id;
                
                vector<DataBase::FileEntry> files = db.get_files(cs->user_id, parent_id);
                
                vector<FileInfo> response_data;
                for(const auto& f : files) {
                    FileInfo fi;
                    fi.id = f.id;
                    strncpy(fi.name, f.name.c_str(), 63);
                    fi.name[63] = 0;
                    fi.size = f.size;
                    fi.is_folder = f.is_folder;
                    response_data.push_back(fi);
                }
                
                Header h;
                h.packet_identifier = PACKET_IDENTIFIER;
                h.op_code = OK;
                h.data_len = htobe64(response_data.size() * sizeof(FileInfo));
                
                write(fd, &h, sizeof(h));
                if (!response_data.empty()) {
                    write(fd, response_data.data(), response_data.size() * sizeof(FileInfo));
                }
                cout << "Sent file list for user " << cs->user_id << " folder " << parent_id << "\n";
    }
    void prepare_download_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        Header h = {0, OK, PACKET_IDENTIFIER};
        write(fd, &h, sizeof(h));
        cout << "Client prepared for download.\n";
    }
    void prepare_upload_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        PrepareUploadRequest* req = (PrepareUploadRequest*)data.data();
        unsigned long filesize = be64toh(req->filesize);
        string original_filename = req->filename;
        int folder_id = ntohl(req->parent_id);
        if(db.exist_already(session_manager.get_user_id(fd),original_filename,folder_id)) {
                cerr << "PREPARE_UPLOAD: A file with the same name already exists in the directory.\n";
                Header h = {0, ERROR, PACKET_IDENTIFIER};
                write(fd, &h, sizeof(h));
                return;
        }

        // Find the data socket for this user
        cout << "PREPARE_UPLOAD: User Token " << cs->token << ". Looking for Data Session...\n";
        ClientStat* data_cs = session_manager.get_data_session(cs->token);
        if (data_cs) {
            cout << "PREPARE_UPLOAD: Found Data Session at " << data_cs << " (FD: " << "unknown" << ")\n";
            data_cs->upload_total_size = filesize;
            data_cs->upload_current_size = 0;
            data_cs->original_filename = original_filename;
            
            // Generate temp filename
            string temp_filename = "temp_upload_" + to_string(cs->user_id) + "_" + to_string(time(nullptr)) + "_" + to_string(rand()) + ".dat";
            data_cs->upload_filename = temp_filename;
            
            // Open file for writing
            if (data_cs->upload_file) {
                cout << "WARNING: PREPARE_UPLOAD attempted while upload in progress. Rejecting.\n";
                Header h = {0, ERROR, PACKET_IDENTIFIER};
                write(fd, &h, sizeof(h));
                return;
            }
            data_cs->upload_file = fopen(temp_filename.c_str(), "wb");
            cout << "PREPARE_UPLOAD: Opened file " << temp_filename << " at ptr " << data_cs->upload_file << "\n";
            
            if (data_cs->upload_file) {
                Header h = {0, OK, PACKET_IDENTIFIER};
                write(fd, &h, sizeof(h));
                cout << "Client prepared for upload. Expecting " << filesize << " bytes on data socket. Filename: " << original_filename << "\n";
            } else {
                Header h = {0, ERROR, PACKET_IDENTIFIER};
                write(fd, &h, sizeof(h));
                cerr << "Failed to open temp file for upload.\n";
            }
        } else {
            Header h = {0, ERROR, PACKET_IDENTIFIER};
            write(fd, &h, sizeof(h));
            cerr << "No data socket found for user " << cs->user_id << ".\n";
        }
    }
    void delete_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        string filename(data.begin(),data.end());
        
        // Get physical path from DB using display name (filename)
        string full_path = db.get_filepath(cs->user_id, filename);
        
        if (full_path.empty()) {
             string response_buffer = "Delete Failed: File not found in DB";
             Header h = {htobe64(response_buffer.size()), OK, PACKET_IDENTIFIER};
             write(fd, &h, sizeof(h));
             write(fd, response_buffer.c_str(), response_buffer.size());
             return;
        }

        // Delete from DB
        bool db_success = db.remove_file_entry(cs->user_id, filename);
        
        // Delete from Disk
        int unlink_ret = unlink(full_path.c_str());
        
        string response_buffer;
        if (db_success && unlink_ret == 0) {
             response_buffer = "Delete Successful: " + filename;
        } else {
             response_buffer = "Delete Failed: " + filename;
             if (!db_success) response_buffer += " (DB Error)";
             if (unlink_ret != 0) response_buffer += " (File Error)";
        }

        Header h;
        h.packet_identifier = PACKET_IDENTIFIER;
        h.op_code = OK;
        h.data_len = htobe64(response_buffer.size());

        write(fd,&h,sizeof(h));
        write(fd,response_buffer.c_str(),response_buffer.size());
        cout<<"Delete processed for " << full_path << "\n";
    }
    void upload_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        if (!cs->upload_file) {
            cerr << "Upload handler called but no file open. Session: " << cs << ", Token: " << cs->token << "\n";
            return;
        }

        unsigned long written = fwrite(data.data(), 1, data.size(), cs->upload_file);
        if (written != data.size()) {
            cerr << "Error writing to temp file.\n";
            // Handle error (maybe close and cleanup)
        }
        cs->upload_current_size += written;

        // cout << "Received chunk: " << written << " bytes. Total: " << cs->upload_current_size << "/" << cs->upload_total_size << "\n";

        if (cs->upload_current_size >= cs->upload_total_size) {
            fclose(cs->upload_file);
            cs->upload_file = nullptr;
            cout << "Upload complete. File saved as " << cs->upload_filename << "\n";

            // Create storage directory
            string user_storage_dir = "SERVER/storage/" + to_string(cs->user_id);
            mkdir("SERVER/storage", 0777); 
            mkdir(user_storage_dir.c_str(), 0777);

            // Generate physical filename
            string physical_filename = "file_" + to_string(time(nullptr)) + "_" + to_string(rand()) + ".dat";
            string final_path = user_storage_dir + "/" + physical_filename;

            // Move file
            if (rename(cs->upload_filename.c_str(), final_path.c_str()) != 0) {
                perror("Error moving file");
            } else {
                // Add metadata to database
                string display_name = cs->original_filename;
                if (display_name.empty()) {
                    display_name = "upload_" + to_string(time(nullptr)) + "_" + to_string(rand());
                }
                db.add_file_entry(cs->user_id, display_name, final_path, cs->upload_total_size);
                cout << "File moved to " << final_path << " and DB entry added. Display Name: " << display_name << "\n";
            }

            Header h;
            h.packet_identifier = PACKET_IDENTIFIER;
            h.op_code = OK;
            h.data_len = 0;

            //send header back to client
            write(fd, &h, sizeof(h));
        }
    }
    void start_download(int fd, int epoll_fd, ClientStat *cs, vector<unsigned char> &data) {
        string filename(data.begin(), data.end());
        
        string filepath = db.get_filepath(cs->user_id, filename);
        if (filepath.empty()) {
            Header h;
            h.packet_identifier = PACKET_IDENTIFIER;
            h.op_code = ERROR;
            h.data_len = 0;
            write(fd, &h, sizeof(h));
            return;
        }

        int file_fd = open(filepath.c_str(), O_RDONLY);
        if (file_fd < 0) {
            Header h;
            h.packet_identifier = PACKET_IDENTIFIER;
            h.op_code = ERROR;
            h.data_len = 0;
            write(fd, &h, sizeof(h));
            return;
        }

        struct stat st;
        if (fstat(file_fd, &st) < 0) {
            close(file_fd);
            return;
        }

        // Send Header (Blocking for simplicity, small packet)
        Header h;
        h.packet_identifier = PACKET_IDENTIFIER;
        h.op_code = DOWNLOAD;
        h.data_len = htobe64(st.st_size);
        write(fd, &h, sizeof(h));

        // Register State
        pthread_mutex_lock(&download_lock);
        active_downloads[fd] = {file_fd, 0, (size_t)st.st_size, filename};
        pthread_mutex_unlock(&download_lock);

        // Modify Epoll to listen for EPOLLOUT
        struct epoll_event epv;
        epv.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT;
        epv.data.fd = fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epv);

        cout << "Download started for " << filename << " (Zero-Copy)\n";
    }

public:
    void resume_download(int fd, int epoll_fd) {
        pthread_mutex_lock(&download_lock);
        auto it = active_downloads.find(fd);
        if (it == active_downloads.end()) {
            pthread_mutex_unlock(&download_lock);
            // Spurious EPOLLOUT or race condition. Re-arm EPOLLIN to be safe.
            struct epoll_event epv;
            epv.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
            epv.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epv);
            return;
        }
        
        DownloadState &state = it->second;
        
        // Zero-Copy Transfer
        ssize_t sent = sendfile(fd, state.file_fd, &state.offset, state.file_size - state.offset);
        
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket buffer full, wait for next EPOLLOUT
                pthread_mutex_unlock(&download_lock);
                
                struct epoll_event epv;
                epv.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT;
                epv.data.fd = fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epv);
                return;
            } else {
                perror("sendfile error");
                close(state.file_fd);
                active_downloads.erase(it);
                pthread_mutex_unlock(&download_lock);
                return;
            }
        }

        if (state.offset >= state.file_size) {
            // Transfer Complete
            close(state.file_fd);
            cout << "Download complete: " << state.filename << "\n";
            active_downloads.erase(it);
            pthread_mutex_unlock(&download_lock);

            // Send Final OK
            Header ok_h;
            ok_h.packet_identifier = PACKET_IDENTIFIER;
            ok_h.op_code = OK;
            ok_h.data_len = 0;
            write(fd, &ok_h, sizeof(ok_h));

            // Revert to EPOLLIN only
            struct epoll_event epv;
            epv.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
            epv.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epv);
        } else {
            // More data to send, re-arm EPOLLOUT
            pthread_mutex_unlock(&download_lock);
            struct epoll_event epv;
            epv.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT;
            epv.data.fd = fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epv);
        }
    }

    ThreadPool(unsigned long num_threads, SessionManager &mgr): session_manager(mgr) {
        mestesugari.resize(num_threads);
        for(unsigned long i=0;i<num_threads;i++) {
            int ret = pthread_create(&mestesugari[i], nullptr, worker_entry, this);
            
            if (ret != 0) {
                std::cerr << "Failed to create thread: " << i << "\n";
                // Vad daca trebuie sa dau exit sau sa reduc pool-ul
            }
        }
    }
    ~ThreadPool() {
        pthread_mutex_lock(&queue_lock);
        stop = true;
        pthread_mutex_unlock(&queue_lock);
        pthread_cond_broadcast(&cond);
        for(pthread_t &mestesugar : mestesugari) {
            pthread_join(mestesugar,nullptr);
        }
    }
    void add_task(Task task) {
        pthread_mutex_lock(&queue_lock);
        tasks.push(move(task));
        pthread_mutex_unlock(&queue_lock);
        pthread_cond_signal(&cond);
    }
};