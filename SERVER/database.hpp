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

        // Create Files Table
        const char* sql_files = 
            "CREATE TABLE IF NOT EXISTS files ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER NOT NULL, "
            "filename TEXT NOT NULL, "
            "filepath TEXT NOT NULL, "
            "size INTEGER, "
            "upload_date TEXT DEFAULT CURRENT_TIMESTAMP, "
            "FOREIGN KEY(user_id) REFERENCES users(id));";

        if (sqlite3_exec(db, sql_files, 0, 0, &errMsg) != SQLITE_OK) {
            cerr << "SQL error creating files table: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        } else {
            cout << "Files table initialized...\n";
        }

        // Add columns for folder support (if they don't exist)
        sqlite3_exec(db, "ALTER TABLE files ADD COLUMN is_folder INTEGER DEFAULT 0;", 0, 0, 0);
        sqlite3_exec(db, "ALTER TABLE files ADD COLUMN parent_id INTEGER DEFAULT 0;", 0, 0, 0);
    }
    ~DataBase() {
        sqlite3_close(db);
    }

    struct FileEntry {
        int id;
        string name;
        bool is_folder;
        unsigned long size;
    };

    vector<FileEntry> get_files(int user_id, int parent_id) {
        vector<FileEntry> files;
        pthread_rwlock_rdlock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT id, filename, is_folder, size FROM files WHERE user_id = ? AND parent_id = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_rwlock_unlock(&db_lock);
            return files;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, parent_id);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            FileEntry fe;
            fe.id = sqlite3_column_int(stmt, 0);
            fe.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            fe.is_folder = sqlite3_column_int(stmt, 2);
            fe.size = sqlite3_column_int64(stmt, 3);
            files.push_back(fe);
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return files;
    }

    string get_filepath(int user_id, const string &filename) {
        pthread_rwlock_rdlock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT filepath FROM files WHERE user_id = ? AND filename = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_rwlock_unlock(&db_lock);
            return "";
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_TRANSIENT);

        string filepath = "";
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            filepath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return filepath;
    }

    bool exist_already(int user_id, const string &filename, int parent_id) {
        pthread_rwlock_rdlock(&db_lock);
        sqlite3_stmt *stmt;
        cout<<"[DB] "<<parent_id<<'\n';
        const char *sql = "SELECT 1 FROM files WHERE user_id = ? AND filename = ? AND parent_id = ? LIMIT 1;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_rwlock_unlock(&db_lock);
            return false;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, parent_id);

        bool exists = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            exists = true;
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return exists;
    }

    bool add_file_entry(int user_id, const string &filename, const string &filepath, unsigned long size) {
        pthread_rwlock_wrlock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "INSERT INTO files (user_id, filename, filepath, size) VALUES (?, ?, ?, ?);";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_rwlock_unlock(&db_lock);
            return false;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, filepath.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, size);

        bool success = false;
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            success = true;
        } else {
            cerr << "Insert failed: " << sqlite3_errmsg(db) << endl;
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return success;
    }

    bool remove_file_entry(int user_id, const string &filename) {
        pthread_rwlock_wrlock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "DELETE FROM files WHERE user_id = ? AND filename = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_rwlock_unlock(&db_lock);
            return false;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_TRANSIENT);

        bool success = false;
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            if (sqlite3_changes(db) > 0) {
                success = true;
            }
        } else {
            cerr << "Delete failed: " << sqlite3_errmsg(db) << endl;
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return success;
    }

    bool remove_file_entry_by_path(int user_id, const string &filepath) {
        pthread_rwlock_wrlock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "DELETE FROM files WHERE user_id = ? AND filepath = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_rwlock_unlock(&db_lock);
            return false;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filepath.c_str(), -1, SQLITE_TRANSIENT);

        bool success = false;
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            if (sqlite3_changes(db) > 0) {
                success = true;
            }
        } else {
            cerr << "Delete failed: " << sqlite3_errmsg(db) << endl;
        }

        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&db_lock);
        return success;
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