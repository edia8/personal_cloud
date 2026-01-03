#pragma once
#include    "sqlite3.h"
#include    <pthread.h>
#include    <string>
#include    <vector>
#include    <iostream>

using namespace std;

class DataBase {
private:
    sqlite3* db;
    pthread_mutex_t db_lock = PTHREAD_MUTEX_INITIALIZER;
public:
    DataBase(const string &path) {
        // Enable serialized mode explicitly if possible, though mutex handles it
        sqlite3_config(SQLITE_CONFIG_SERIALIZED);
        
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

        // Create Shared Files Table
        const char* sql_shared = 
            "CREATE TABLE IF NOT EXISTS shared_files ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "file_id INTEGER NOT NULL, "
            "shared_with_user_id INTEGER NOT NULL, "
            "FOREIGN KEY(file_id) REFERENCES files(id), "
            "FOREIGN KEY(shared_with_user_id) REFERENCES users(id));";

        if (sqlite3_exec(db, sql_shared, 0, 0, &errMsg) != SQLITE_OK) {
            cerr << "SQL error creating shared_files table: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        } else {
            cout << "Shared Files table initialized...\n";
        }

        // Add columns for folder support (if they don't exist)
        // sqlite3_exec(db, "ALTER TABLE files ADD COLUMN is_folder INTEGER DEFAULT 0;", 0, 0, 0);
        // sqlite3_exec(db, "ALTER TABLE files ADD COLUMN parent_id INTEGER DEFAULT 0;", 0, 0, 0);
    }
    ~DataBase() {
        sqlite3_close(db);
    }

    struct FileEntry {
        int id;
        string name;
        unsigned long size;
    };

    vector<FileEntry> get_files(int user_id) {
        vector<FileEntry> files;
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT f.id, f.filename, f.size FROM files f "
                          "LEFT JOIN shared_files sf ON f.id = sf.file_id "
                          "WHERE f.user_id = ? OR sf.shared_with_user_id = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_mutex_unlock(&db_lock);
            return files;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            FileEntry fe;
            fe.id = sqlite3_column_int(stmt, 0);
            fe.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            fe.size = sqlite3_column_int64(stmt, 2);
            files.push_back(fe);
        }

        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_lock);
        return files;
    }

    string get_filepath(int user_id, const string &filename) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT f.filepath FROM files f "
                          "LEFT JOIN shared_files sf ON f.id = sf.file_id "
                          "WHERE (f.user_id = ? OR sf.shared_with_user_id = ?) AND f.filename = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_mutex_unlock(&db_lock);
            return "";
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_int(stmt, 2, user_id);
        sqlite3_bind_text(stmt, 3, filename.c_str(), -1, SQLITE_TRANSIENT);

        string filepath = "";
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            filepath = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        }

        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_lock);
        return filepath;
    }

    int get_user_id_by_name(const string& username) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT id FROM users WHERE username = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_mutex_unlock(&db_lock);
            return -1;
        }

        sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

        int id = -1;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            id = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_lock);
        return id;
    }

    int get_file_id(int user_id, const string& filename) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT id FROM files WHERE user_id = ? AND filename = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_mutex_unlock(&db_lock);
            return -1;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_STATIC);

        int id = -1;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            id = sqlite3_column_int(stmt, 0);
        }

        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_lock);
        return id;
    }

    bool share_file(int file_id, int target_user_id) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "INSERT INTO shared_files (file_id, shared_with_user_id) VALUES (?, ?);";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_mutex_unlock(&db_lock);
            return false;
        }

        sqlite3_bind_int(stmt, 1, file_id);
        sqlite3_bind_int(stmt, 2, target_user_id);

        bool success = false;
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            success = true;
        }

        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_lock);
        return success;
    }

    bool exist_already(int user_id, const string &filename) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "SELECT 1 FROM files WHERE user_id = ? AND filename = ? LIMIT 1;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_mutex_unlock(&db_lock);
            return false;
        }

        sqlite3_bind_int(stmt, 1, user_id);
        sqlite3_bind_text(stmt, 2, filename.c_str(), -1, SQLITE_TRANSIENT);

        bool exists = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            exists = true;
        }

        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_lock);
        return exists;
    }

    bool add_file_entry(int user_id, const string &filename, const string &filepath, unsigned long size) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "INSERT INTO files (user_id, filename, filepath, size) VALUES (?, ?, ?, ?);";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_mutex_unlock(&db_lock);
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
        pthread_mutex_unlock(&db_lock);
        return success;
    }

    bool remove_file_entry(int user_id, const string &filename) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "DELETE FROM files WHERE user_id = ? AND filename = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_mutex_unlock(&db_lock);
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
        pthread_mutex_unlock(&db_lock);
        return success;
    }

    bool remove_file_entry_by_path(int user_id, const string &filepath) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "DELETE FROM files WHERE user_id = ? AND filepath = ?;";
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            cerr << "Prepare failed: " << sqlite3_errmsg(db) << endl;
            pthread_mutex_unlock(&db_lock);
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
        pthread_mutex_unlock(&db_lock);
        return success;
    }

    int register_user(const string &username,const string &passwd) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt *stmt;
        const char *sql = "INSERT INTO users (username, password_hash) VALUES (?, ?);";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_mutex_unlock(&db_lock);
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
        pthread_mutex_unlock(&db_lock);
        return success;
    }
    int verify_login(const string &user, const string &passwd) {
        pthread_mutex_lock(&db_lock);
        sqlite3_stmt* stmt;
        const char* sql = "SELECT id,password_hash FROM users WHERE username = ?;";
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) != SQLITE_OK) {
            pthread_mutex_unlock(&db_lock);
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
        pthread_mutex_unlock(&db_lock);
        return login_success;
    }
};