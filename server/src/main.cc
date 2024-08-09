#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PORT "3490"
#define BACKLOG 10
#define BUFFER_SIZE 1024

using namespace std;

enum class StatusCode {
    CONNECTION_ESTABLISHED = 100,
    MESSAGE_RECEIVED = 200,
    SERVER_DISCONNECTED = 300,
    ERROR = 400
};

const unordered_map<StatusCode, string> StatusMessages = {
    {StatusCode::CONNECTION_ESTABLISHED, "Connection established"},
    {StatusCode::MESSAGE_RECEIVED, "Message received"},
    {StatusCode::SERVER_DISCONNECTED, "Client disconnected"},
    {StatusCode::ERROR, "Error occurred"}};

string secret_key = "6510450411";
int sockfd;
vector<int> active_sockets;
pthread_mutex_t sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

string create_hmac(const string &key, const string &data) {
    unsigned char *digest;
    unsigned int len = EVP_MAX_MD_SIZE;
    char md_string[2 * EVP_MAX_MD_SIZE + 1];

    digest = (unsigned char *)malloc(len);

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char *)data.c_str(), data.length());
    HMAC_Final(ctx, digest, &len);
    HMAC_CTX_free(ctx);

    for (unsigned int i = 0; i < len; i++) {
        sprintf(&md_string[i * 2], "%02x", (unsigned int)digest[i]);
    }

    free(digest);

    return string(md_string);
}

bool verify_hmac(const string &key, const string &data,
                 const string &hmac_to_verify) {
    string computed_hmac = create_hmac(key, data);
    return computed_hmac == hmac_to_verify;
}

void *handle_client(void *arg) {
    int client_sockfd = *(int *)arg;
    char buffer[BUFFER_SIZE];
    ssize_t num_bytes;

    pthread_mutex_lock(&sockets_mutex);
    active_sockets.push_back(client_sockfd);
    pthread_mutex_unlock(&sockets_mutex);

    while ((num_bytes = recv(client_sockfd, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[num_bytes] = '\0';

        string received_data(buffer);
        size_t delimiter_pos = received_data.find('|');
        if (delimiter_pos != string::npos) {
            string message = received_data.substr(0, delimiter_pos);
            string received_hmac = received_data.substr(delimiter_pos + 1);

            if (verify_hmac(secret_key, message, received_hmac)) {
                printf("\nStatus Code: %d, Status: %s\n",
                       static_cast<int>(StatusCode::MESSAGE_RECEIVED),
                       StatusMessages.at(StatusCode::MESSAGE_RECEIVED).c_str());
                printf("Received: %s\n", message.c_str());

                pthread_mutex_lock(&sockets_mutex);
                for (int other_sockfd : active_sockets) {
                    if (other_sockfd != client_sockfd) {
                        send(other_sockfd, buffer, num_bytes, 0);
                    }
                }
                pthread_mutex_unlock(&sockets_mutex);
            } else {
                printf("server: invalid HMAC\n");
            }
        } else {
            printf("server: message format error\n");
        }
    }

    if (num_bytes == -1) {
        perror("recv");
        printf("Status Code: %d, Status: %s\n",
               static_cast<int>(StatusCode::ERROR),
               StatusMessages.at(StatusCode::ERROR).c_str());
    } else if (num_bytes == 0) {
        printf("server: connection closed by client\n");
        printf("Status Code: %d, Status: %s\n",
               static_cast<int>(StatusCode::SERVER_DISCONNECTED),
               StatusMessages.at(StatusCode::SERVER_DISCONNECTED).c_str());
    }

    close(client_sockfd);

    pthread_mutex_lock(&sockets_mutex);
    auto it =
        find(active_sockets.begin(), active_sockets.end(), client_sockfd);
    if (it != active_sockets.end()) {
        active_sockets.erase(it);
    }
    pthread_mutex_unlock(&sockets_mutex);

    return NULL;
}

void cleanup_and_exit(int signal) {
    close(sockfd);
    printf("Server shutting down...\n");
    exit(0);
}

int main() {
    struct addrinfo hints, *servinfo, *p;
    int rv, new_fd;
    struct sockaddr_storage client_addr;
    socklen_t addr_size;
    pthread_t thread;

    signal(SIGINT, cleanup_and_exit);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
            -1) {
            perror("server: socket");
            continue;
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "server: failed to bind\n");
        return 2;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror("server: listen");
        return 3;
    }

    printf("Server listening on port %s\n", PORT);

    while (true) {
        addr_size = sizeof(client_addr);
        if ((new_fd = accept(sockfd, (struct sockaddr *)&client_addr,
                             &addr_size)) == -1) {
            perror("server: accept");
            continue;
        }

        printf("Status Code: %d, Status: %s\n",
               static_cast<int>(StatusCode::CONNECTION_ESTABLISHED),
               StatusMessages.at(StatusCode::CONNECTION_ESTABLISHED).c_str());

        if (pthread_create(&thread, NULL, handle_client, &new_fd) != 0) {
            perror("pthread_create");
        }
        pthread_detach(thread);
    }

    cleanup_and_exit(SIGINT);
    return 0;
}
