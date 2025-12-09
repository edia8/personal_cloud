#include "client.hpp"
#include <cstring>

using namespace std;

//functie de send care nu trimite data partial
bool ClientBackend::send_full_packet(int fd, const void* data, unsigned long length) {
    const char* ptr = static_cast<const char*>(data);
    unsigned long total_sent = 0;
    while (total_sent < length) {
        unsigned long sent = write(fd, ptr + total_sent, length - total_sent);
        if (sent <= 0) return false;//sv deconectat
        total_sent += sent;
    }
    return true;
}

// functie de recieve care nu primeste data partial
bool ClientBackend::recv_full_packet(int fd, void* buffer, unsigned long length) {
    char* ptr = static_cast<char*>(buffer);
    unsigned long total_received = 0;
    while (total_received < length) {
        unsigned long r = read(fd, ptr + total_received, length - total_received);
        if (r <= 0) return false; //sv deconectat
        total_received += r;
    }
    return true;
}

bool ClientBackend::connect(string ip, int port) {
    return user_sock.connect_to_server(ip,port);
}

void ClientBackend::close_client() {
    if (!user_sock.is_valid()) return;

    //send logout packet
    Header header;
    header.op_code = LOGOUT;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = 0;

    if (!send_full_packet(user_sock.get(), &header, sizeof(header))) {
        cerr << "Failed to send LOGOUT packet.\n";
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

    //inchid socket
    data_sock.reset(-1);
    
    is_logged_in = false;
}

void ClientBackend::send_link_packet(unsigned long token) {
    if (!data_sock.is_valid()) {
        data_sock.connect_to_server("10.100.0.30", PORT); 
    }

    LinkData payload;
    payload.session_token = token;

    Header header;
    header.op_code = DATA_LINK;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htonl(sizeof(payload));

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

    strncpy((char*)payload.username, username.c_str(), sizeof(payload.username) - 1);
    strncpy((char*)payload.password, password.c_str(), sizeof(payload.password) - 1);

    Header header;
    header.op_code = REGISTER;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htonl(sizeof(payload));

    vector<unsigned char> packet;
    packet.resize(sizeof(header) + sizeof(payload));
    
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send Register packet.\n";
        return 0;
    }

    cout << "Register request sent. Waiting for response...\n";
    Header resp_header;
    if (recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        if(resp_header.op_code == OK && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            return 1;//cod success
        }else if(resp_header.op_code == ERROR && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            return 0;//cod eroare 
        }else if(resp_header.op_code == ERR_ALR_REG && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            cout<<"Acest username este deja folosit\n";
            return 2; //cod pt user_alr_used
        }
    }
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
    
    strncpy((char*)payload.username, username.c_str(), sizeof(payload.username) - 1);
    strncpy((char*)payload.password, password.c_str(), sizeof(payload.password) - 1);

    Header header;
    header.op_code = LOGIN;
    header.packet_identifier = PACKET_IDENTIFIER;
    header.data_len = htonl(sizeof(payload));

    //trimit header+creds
    std::vector<unsigned char> packet;
    packet.resize(sizeof(header) + sizeof(payload));
    
    memcpy(packet.data(), &header, sizeof(header));
    memcpy(packet.data() + sizeof(header), &payload, sizeof(payload));

    if (!send_full_packet(user_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send Login packet.\n";
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
                return resp_data.session_token;
            } else {
                cerr << "Nu s-a primit login data.\n";
                return 0;
            }
        } else if(resp_header.op_code == ERROR && resp_header.packet_identifier == PACKET_IDENTIFIER) {
            cerr << "Login Failed. Server responded with OpCode: " << (int)resp_header.op_code << "\n";
            return 0;
        }
    } else {
        cerr << "Server disconnected during login.\n";
        return 0;
    }
    return 0;
}



string ClientBackend::upload(string filename) {
    if (!user_sock.is_valid() || !data_sock.is_valid()) {
        cerr << "Sockets not connected.\n";
        return "Error: Sockets not connected";
    }

    //initiere handshake
    Header prep_header;
    prep_header.op_code = PREPARE_UPLOAD;
    prep_header.packet_identifier = PACKET_IDENTIFIER;
    prep_header.data_len = 0; //Trimit numai un header

    if (!send_full_packet(user_sock.get(), &prep_header, sizeof(prep_header))) {
        cerr << "Failed to send PREPARE_UPLOAD.\n";
        return "Error: Failed to send PREPARE_UPLOAD";
    }

    //asteptam ok de la sv
    Header resp_header;
    if (!recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        cerr << "Server disconnected during prepare phase.\n";
        return "Error: Server disconnected";
    }

    if (resp_header.op_code != OK) {
        cerr << "Server denied upload request.\n";
        return "Error: Server denied upload request";
    }
    cout << "Server is ready for data.\n";

    //trimitem data dupa handshake
    string demo_data = filename;
    
    Header data_header;
    data_header.op_code = UPLOAD;
    data_header.packet_identifier = PACKET_IDENTIFIER;
    data_header.data_len = htonl(demo_data.size());

    vector<unsigned char> packet;
    packet.resize(sizeof(data_header) + demo_data.size());

    memcpy(packet.data(), &data_header, sizeof(data_header));
    memcpy(packet.data() + sizeof(data_header), demo_data.c_str(), demo_data.size());

    if (!send_full_packet(data_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send data packet.\n";
        return "Error: Failed to send data packet";
    }
    //citim header
    Header echo_header;
    if (!recv_full_packet(data_sock.get(), &echo_header, sizeof(echo_header))) {
        cerr << "Failed to receive echo header.\n";
        return "Error: Failed to receive echo header";
    }

    //citim data
    unsigned int payload_len = ntohl(echo_header.data_len);
    vector<char> echo_buffer(payload_len + 1); // +1 pt NULLLLL
    
    if (!recv_full_packet(data_sock.get(), echo_buffer.data(), payload_len)) {
        cerr << "Failed to receive echo data.\n";
        return "Error: Failed to receive echo data";
    }
    
    echo_buffer[payload_len] = '\0'; // NU UITA DE NULL
    cout << "Server responded: " << echo_buffer.data() << '\n';

    return string(echo_buffer.data());
}

string ClientBackend::download(string filename) {
    if (!user_sock.is_valid() || !data_sock.is_valid()) {
        cerr << "Sockets not connected.\n";
        return "Error: Sockets not connected";
    }

    // trimite header ca sv sa astepte download
    Header prep_header;
    prep_header.op_code = PREPARE_DOWNLOAD;
    prep_header.packet_identifier = PACKET_IDENTIFIER;
    prep_header.data_len = 0; //Header gol pt handshake

    if (!send_full_packet(user_sock.get(), &prep_header, sizeof(prep_header))) {
        cerr << "Nu s-a trimis PREPARE_DOWNLOAD.\n";
        return "Error: Nu s-a trimis PREPARE_DOWNLOAD";
    }

    // astept ok
    Header resp_header;
    if (!recv_full_packet(user_sock.get(), &resp_header, sizeof(resp_header))) {
        cerr << "Server deconectat.\n";
        return "Error: Server disconnected";
    }

    if (resp_header.op_code != OK) {
        cerr << "Server nu vrea download request.\n";
        return "Error: Server nu vrea download request";
    }
    cout << "Server e gata pentru data.\n";

    // s-a facut handshake, trimitem data
    string demo_data = filename;
    
    Header data_header;
    data_header.op_code = DOWNLOAD;
    data_header.packet_identifier = PACKET_IDENTIFIER;
    data_header.data_len = htonl(demo_data.size());

    vector<unsigned char> packet;
    packet.resize(sizeof(data_header) + demo_data.size());

    memcpy(packet.data(), &data_header, sizeof(data_header));
    memcpy(packet.data() + sizeof(data_header), demo_data.c_str(), demo_data.size());

    if (!send_full_packet(data_sock.get(), packet.data(), packet.size())) {
        cerr << "Failed to send data packet.\n";
        return "Error: Failed to send data packet";
    }

    //citim header
    Header echo_header;
    if (!recv_full_packet(data_sock.get(), &echo_header, sizeof(echo_header))) {
        cerr << "Nu s-a primit echo header.\n";
        return "Error: Nu s-a primit echo header";
    }

    //citim data
    unsigned int payload_len = ntohl(echo_header.data_len);
    vector<char> buffer(payload_len + 1); // +1 pt NULLLLL
    
    if (!recv_full_packet(data_sock.get(), buffer.data(), payload_len)) {
        cerr << "Nu s-a primit echo data.\n";
        return "Error: Nu s-a primit echo data";
    }
    
    buffer[payload_len] = '\0'; // NU UITA DE NULL
    cout << "Server responded: " << buffer.data() << '\n';

    return string(buffer.data());
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
    del_h.data_len = htonl(demo_data.size());
    vector<unsigned char> packet;
    packet.resize(sizeof(del_h) + demo_data.size());

    memcpy(packet.data(), &del_h, sizeof(del_h));
    memcpy(packet.data() + sizeof(del_h), demo_data.c_str(), demo_data.size());
    if(!send_full_packet(user_sock.get(),packet.data(),packet.size())) {
        cerr<<"Eroare la trimitere delete\n";
        return "Error: trimitere delete";
    }
    //procesare sv
    Header del_resp;
    if(!recv_full_packet(user_sock.get(),&del_resp,sizeof(del_resp))) {
        cerr<<"Eroare la primire delete\n";
        return "Error: primire delete";
    }
    if(del_resp.op_code!=OK || del_resp.packet_identifier != PACKET_IDENTIFIER){
        cerr<<"Eroare la pachet code";
        return "Error: pachetul nu este bun";
    }
    unsigned int len = ntohl(del_resp.data_len);
    vector<char> buffer(len+1);
    
    if (!recv_full_packet(user_sock.get(), buffer.data(),len)) {
        cerr << "Nu s-a primit data.\n";
        return "Error: Nu s-a primit data";
    }
    buffer[len] = '\0';
    cout<<"Server a trimis "<<buffer.data()<<'\n';
    return string(buffer.data());
}
