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
#define BUFFER_SIZE 1024
#define NAME_SIZE 50

using namespace std;

enum class StatusCode {
    CONNECTION_ESTABLISHED = 100,
    MESSAGE_SENT = 200,
    MESSAGE_RECEIVED = 201,
    SERVER_DISCONNECTED = 300,
    ERROR = 400
};

const unordered_map<StatusCode, string> StatusMessages = {
    {StatusCode::CONNECTION_ESTABLISHED, "Connection established"},
    {StatusCode::MESSAGE_SENT, "Message sent"},
    {StatusCode::MESSAGE_RECEIVED, "Message received"},
    {StatusCode::SERVER_DISCONNECTED, "Server disconnected"},
    {StatusCode::ERROR, "Error occurred"}};

string secret_key = "6510450411";
int sockfd = -1;
bool running = true;
string client_name;

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

void *receive_messages(void *arg);
void cleanup_and_exit(int signal);

int main() {
    struct addrinfo hints, *servinfo, *p;
    char buffer[BUFFER_SIZE];
    int rv;
    pthread_t recv_thread;

    signal(SIGINT, cleanup_and_exit);

    cout << "Enter your name: ";
    getline(cin, client_name);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(0, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
            -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "client: failed to connect\n");
        return 2;
    }

    printf("Status Code: %d, Status: %s\n",
           static_cast<int>(StatusCode::CONNECTION_ESTABLISHED),
           StatusMessages.at(StatusCode::CONNECTION_ESTABLISHED).c_str());

    if (pthread_create(&recv_thread, NULL, receive_messages, NULL) != 0) {
        perror("pthread_create");
        cleanup_and_exit(SIGINT);
    }

    while (running) {
        printf("Enter message (type 'exit' to quit): ");
        fflush(stdout);
        if (fgets(buffer, BUFFER_SIZE, stdin) != NULL) {
            buffer[strcspn(buffer, "\n")] = 0;

            if (strncmp(buffer, "exit", 4) == 0) {
                running = false;
            } else {

                string message = client_name + ": " + buffer;
                string hmac = create_hmac(secret_key, message);

                string message_with_hmac = message + "|" + hmac;
                ssize_t num_bytes_sent = send(sockfd, message_with_hmac.c_str(),
                                              message_with_hmac.size(), 0);
                if (num_bytes_sent == -1) {
                    perror("client: send");
                    printf("Status Code: %d, Status: %s\n",
                           static_cast<int>(StatusCode::ERROR),
                           StatusMessages.at(StatusCode::ERROR).c_str());
                } else if (num_bytes_sent !=
                           (ssize_t)message_with_hmac.size()) {
                    printf("client: warning: partial send\n");
                } else {

                    printf("Status Code: %d, Status: %s\n",
                           static_cast<int>(StatusCode::MESSAGE_SENT),
                           StatusMessages.at(StatusCode::MESSAGE_SENT).c_str());
                }
            }
        } else {
            perror("fgets");
            printf("Status Code: %d, Status: %s\n",
                   static_cast<int>(StatusCode::ERROR),
                   StatusMessages.at(StatusCode::ERROR).c_str());
        }
    }

    cleanup_and_exit(SIGINT);
    return 0;
}

void *receive_messages(void *arg) {
    char buffer[BUFFER_SIZE];
    ssize_t num_bytes;

    while (running) {
        num_bytes = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
        if (num_bytes > 0) {
            buffer[num_bytes] = '\0';

            string received_data(buffer);
            size_t delimiter_pos = received_data.find('|');
            if (delimiter_pos != string::npos) {
                string message = received_data.substr(0, delimiter_pos);
                string received_hmac =
                    received_data.substr(delimiter_pos + 1);

                if (create_hmac(secret_key, message) == received_hmac) {
                    printf("\nStatus Code: %d, Status: %s\n",
                           static_cast<int>(StatusCode::MESSAGE_RECEIVED),
                           StatusMessages.at(StatusCode::MESSAGE_RECEIVED)
                               .c_str());
                    printf("Received: %s\n", message.c_str());
                } else {
                    printf("client: invalid HMAC\n");
                }
            } else {
                printf("client: message format error\n");
            }

            printf("Enter message (type 'exit' to quit): ");
            fflush(stdout);
        } else if (num_bytes == 0) {
            printf("\nStatus Code: %d, Status: %s\n",
                   static_cast<int>(StatusCode::SERVER_DISCONNECTED),
                   StatusMessages.at(StatusCode::SERVER_DISCONNECTED).c_str());
            running = false;
        } else {
            perror("recv");
            printf("Status Code: %d, Status: %s\n",
                   static_cast<int>(StatusCode::ERROR),
                   StatusMessages.at(StatusCode::ERROR).c_str());
            running = false;
        }
    }
    return NULL;
}

void cleanup_and_exit(int signal) {
    if (sockfd != -1) {
        close(sockfd);
        printf("Status Code: %d, Status: %s\n",
               static_cast<int>(StatusCode::SERVER_DISCONNECTED),
               StatusMessages.at(StatusCode::SERVER_DISCONNECTED).c_str());
    }
    exit(0);
}
