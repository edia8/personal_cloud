/*COMPILARE SERVER:

gcc -c sqlite3.c -o sqlite3.o
g++ server.cpp sqlite3.o -o server

*/

#include <iostream>
#include <ctime>
#include <csignal>
#include "session.hpp"
#include "threadpool.hpp"
#include "network.hpp"

int main() {
    signal(SIGPIPE, SIG_IGN);
    srand(time(nullptr));
    // 1. Initialize Core Components
    std::cout << "Initializing Session Manager...\n";
    SessionManager session_mgr;

    std::cout << "Initializing Thread Pool (" << THREAD_POOL_SIZE << " threads)...\n";
    ThreadPool thread_pool(THREAD_POOL_SIZE, session_mgr);

    std::cout << "Initializing Network Engine...\n";
    Network server(session_mgr, thread_pool);

    // 2. Setup Server (Bind/Listen)
    server.init();

    // 3. Start Event Loop (Blocking)
    // This will run forever until Ctrl+C
    server.run();

    return 0;
}