#pragma once
#include    "sqlite3.h"
#include    <pthread.h>
#include    <string>
#include    <iostream>

using namespace std;

class DataBase {
private:
    sqlite3* db;
    pthread_rwlock_t db_lock = PTHREAD_RWLOCK_INITIALIZER;
public:
    DataBase(const string &path) {
        if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
            cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
            exit(1);
        }

        //Create Table if it doesn't exist
        const char* sql = 
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT NOT NULL UNIQUE, "
            "password_hash TEXT NOT NULL);";

        char* errMsg = 0;
        if (sqlite3_exec(db, sql, 0, 0, &errMsg) != SQLITE_OK) {
            cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        } else {
            cout<<"Open database...\n";
        }
    }
    ~DataBase() {
        sqlite3_close(db);
    }

    int register_user(const string &username,const string &passwd) {
        pthread_rwlock_wrlock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "INSERT INTO users (username, password_hash) VALUES (?, ?);";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_rwlock_unlock(&db_lock);
            return false; // Likely DB error
        }
        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, passwd.c_str(), -1, SQLITE_TRANSIENT);

        int success = 0;
        int sqlite_code = sqlite3_step(stmt);
        if (sqlite_code == SQLITE_DONE) {
            success = 1;
        } else if(sqlite_code == SQLITE_CONSTRAINT){
            success = 2;
            // Likely SQLITE_CONSTRAINT (Username already exists)
            cerr << "Register fail: " << sqlite3_errmsg(db) << std::endl;
        }

        //Cleanup
        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return success;
    }
    int verify_login(const string &user, const string &passwd) {
        pthread_rwlock_wrlock(&db_lock);
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id,password_hash FROM users WHERE username = ?;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            return -1;
        }

        sqlite3_bind_text(stmt, 1, user.c_str(), -1, SQLITE_TRANSIENT);

        int login_success = -1;

        //Execute & Fetch Result
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            // User found
            int user_id = sqlite3_column_int(stmt, 0);
            const unsigned char* db_hash_ptr = sqlite3_column_text(stmt, 1);
            
            if (db_hash_ptr) {
                std::string db_hash = reinterpret_cast<const char*>(db_hash_ptr);

                //Verify Password
                if (db_hash == passwd) { 
                    login_success = user_id;
                }
            }
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return login_success;
    }
};