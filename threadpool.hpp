#pragma once
#include    <cstring>
#include    <queue>
#include    <cstring>
#include    <unistd.h>
#include    <iostream>
#include    <arpa/inet.h>
#include    <sys/epoll.h>
#include    "protocol.hpp"
#include    "session.hpp"
#include    "database.hpp"

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
    if(cs== nullptr) return;

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
                cs->expected_len = ntohl(header->data_len);
                cs->op_code = header->op_code;
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
                    // --- EXECUTE LOGIC ---
                    // NOTE: In a real implementation, you would save op_code in ctx when parsing header.
                    // Here we assume a hypothetical `ctx->current_opcode`.
                    // For now, let's assume we handle a generic dispatch:
                    execute_command(task.socket_fd,cs,data);
                    cs->op_code = RESET_CODE;
                    cs->has_header = false;
                    cs->expected_len = 0;
            }else {
                break;
            }   
        }
    }
    struct epoll_event epv;
    epv.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT;
    epv.data.fd = task.socket_fd;
    epoll_ctl(task.epoll_fd,EPOLL_CTL_MOD,task.socket_fd,&epv);
    }

    void execute_command(int fd,ClientStat *cs, vector<unsigned char> &data) {
        // Logic depends on socket state
        // To properly implement this, we need the OpCode. 
        // Let's assume we peeked it or stored it. 
        // I will focus on the LINK logic here.

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
                
            }
            else if(cs->op_code == PREPARE_DOWNLOAD) {

            }
            else if(cs->op_code == PREPARE_UPLOAD) {

            }
            else if(cs->op_code == DELETE) {

            }
            else {
                cout<<"Actiune invalida 2\n";return;
            }
        } else if(cs->type == SocketType::DATA) {
                if(cs->op_code == UPLOAD) {

                } else if(cs->op_code == DOWNLOAD) {

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
            Header h = {htonl((int)0),OK,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
            cout<<"User inregistrat in db\n";
        }else if(success==2) {
            Header h = {htonl((int)0),ERR_ALR_REG,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
        }else {
            Header h = {htonl((int)0),ERROR,PACKET_IDENTIFIER};
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
            Header h = {htonl(sizeof(LoginResponse)),OK,PACKET_IDENTIFIER};
            LoginResponse response = {token};
            //use a loop in production
            write(fd,&h,sizeof(h));
            write(fd,&response,sizeof(LoginResponse));
            cout<<"User Logged in, token sent\n";
        } else {
            Header h = {htonl((int)0),ERROR,PACKET_IDENTIFIER};
            write(fd,&h,sizeof(h));
        }
    }
    void link_handler(int fd, ClientStat *cs, vector<unsigned char> &data) {
        LinkData *link = (LinkData*)data.data();
        int user_id = session_manager.redeem_token(link->session_token);
    
        if(user_id != -1) {
            //valid user
            session_manager.set_auth_data(fd,user_id);
            cout<<"Data socket linked for user with uid "<<user_id<<'\n';
        } else {
            cout<<"Invalid token\n";
            close(fd);
        }
    }
    void upload_handler(Task &task) {

    }
    void download_handler(Task &task) {

    }
public: 
    ThreadPool(unsigned long num_threads, SessionManager &mgr): session_manager(mgr) {
        mestesugari.resize(num_threads);
        for(unsigned long i=0;i<num_threads;i++) {
            int ret = pthread_create(&mestesugari[i], nullptr, worker_entry, this);
            
            if (ret != 0) {
                std::cerr << "Failed to create thread: " << i << "\n";
                // In a real app, you might want to handle this error (exit or reduce pool size)
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