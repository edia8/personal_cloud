#pragma once
#include    <sys/socket.h>
#include    <netinet/in.h>
#include    <fcntl.h>
#include    <unistd.h>
#include    "protocol.hpp"
#include    "session.hpp"
#include    "threadpool.hpp"

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

class Network {
private:
    int server_fd;
    int epoll_fd;
    SessionManager &session_manager;
    ThreadPool & thread_pool;
public:
    Network(SessionManager& sm, ThreadPool& tp) : session_manager(sm), thread_pool(tp) {}
    void init() {
        server_fd = socket(AF_INET,SOCK_STREAM,0);
        if(server_fd < 0) {
            perror("Eroare la creare socket");
            exit(1);
        }
        int optiune = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optiune, sizeof(optiune)); 
    
        struct sockaddr_in address;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_family = AF_INET;
        address.sin_port = htons(PORT);

        if(bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            perror("Bind failed");
            exit(2);
        }
        if(listen(server_fd, 10) < 0) {
            perror("Listen failed");
            exit(3);
        }
        epoll_fd = epoll_create1(0);
        if(epoll_fd < 0) {
            perror("Epoll create failed");
            exit(4);
        }
        struct epoll_event epv;
        epv.events = EPOLLIN;
        epv.data.fd = server_fd;
        if(epoll_ctl(epoll_fd,EPOLL_CTL_ADD,server_fd,&epv) < 0) {
            perror("Eroare epoll server add");
            exit(5);
        }
        cout<<"Server started on port "<<PORT<<'\n'; 
    }
    void run() {
        struct epoll_event events[MAX_EVENTS];
        while(true) {
            int nfds = epoll_wait(epoll_fd,events,MAX_EVENTS,-1);

            for(int i=0;i<nfds;i++) {
                int curent_fd = events[i].data.fd;

                if(curent_fd == server_fd) {
                    handle_new_connection();
                }
                else {
                    if (events[i].events & EPOLLOUT) {
                        thread_pool.resume_download(curent_fd, epoll_fd);
                    }
                    if (events[i].events & EPOLLIN) {
                        handle_client_data(curent_fd);
                    }
                }
            }
        }
    }
private:
    void handle_new_connection() {
        struct sockaddr_in client_address;
        socklen_t client_len = sizeof(client_address);
        int client_fd = accept(server_fd,(struct sockaddr*) &client_address,&client_len);
        
        if(client_fd < 0) return;
        set_nonblocking(client_fd);

        struct epoll_event epv;
        epv.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLONESHOT;
        epv.data.fd = client_fd;
        epoll_ctl(epoll_fd,EPOLL_CTL_ADD,client_fd,&epv);
        session_manager.add_session(client_fd);
        cout<<"New client Connected: "<<client_fd<<'\n';
    }
    void handle_client_data(int fd) {
        Task task;
        task.socket_fd = fd;
        task.epoll_fd = epoll_fd;
        thread_pool.add_task(task);
    }
};