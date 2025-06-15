#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include "data_compress.h"
#include "http_parser.h"
#include "http_server.h"
#include "mime.h"
#include "picohttpparser.h"

#define CRLF "\r\n"

#define PATH "/home/ginseng/ktcp/root"

#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct dir_context dir_context;
};

static struct link_data {
    struct socket *socket;
    struct work_struct worker;
};

struct ktcp_attr {
    char enable;
    rwlock_t lock;
};

static struct ktcp_attr attr_obj;
static ssize_t ktcp_state_show(struct device *dev,
                               struct device_attribute *attr,
                               char *buf)
{
    read_lock(&attr_obj.lock);
    int ret = snprintf(buf, "%c\n", attr_obj.enable);
    read_unlock(&attr_obj.lock);
    return ret;
}
static ssize_t ktcp_state_store(struct device *dev,
                                struct device_attribute *attr,
                                const char *buf,
                                size_t count)
{
    write_lock(&attr_obj.lock);
    sscanf(buf, "%c", &(attr_obj.enable));
    write_unlock(&attr_obj.lock);
    return count;
}

static DEVICE_ATTR_RW(ktcp_state);

const char *search_mime_type(char *request)
{
    char *type = strrchr(request, '.');

    for (int i = 0; mime_type[i].type; i++) {
        if (strcmp(mime_type[i].type, type) == 0)
            return mime_type[i].label;
    }

    return "text/plain";
}

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {
        .msg_name = 0,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    return kernel_recvmsg(sock, &msg, &iov, 1, size, MSG_DONTWAIT);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };

        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);

        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static void catstr(char *res, char *first, char *second)
{
    int first_size = strlen(first);
    int second_size = strlen(second);
    memset(res, 0, 1024);
    memcpy(res, first, first_size);
    memcpy(res + first_size, second, second_size);
}

/*callback function to handle every entry in directory*/
static _Bool tracedir(struct dir_context *dir_context,
                      const char *name,
                      int namelen,
                      loff_t offset,
                      u64 ino,
                      unsigned int d_type)
{
    if (strcmp(name, ".") && strcmp(name, "..")) {
        struct http_request *request =
            container_of(dir_context, struct http_request, dir_context);
        char buf[200] = {0};

        snprintf(buf, 200,
                 "%lx\r\n<tr><td><a href=\"%s/%s\">%s</a></td></tr>\r\n",
                 34 + namelen + namelen + strlen(request->request_url),
                 request->request_url, name, name);

        pr_info("send url:%s", buf);
        http_server_send(request->socket, buf, strlen(buf));
    }
    return true;
}

static bool send_directory(struct http_request *request, int keep_alive)
{
    char path[1024] = {0};
    const char *root = PATH;
    catstr(path, root, request->request_url);

    struct file *fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        return false;
    }

    char response[SEND_BUFFER_SIZE] = {0};
    if (S_ISDIR(fp->f_inode->i_mode)) {
        snprintf(response, SEND_BUFFER_SIZE,
                 ""
                 "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF
                 "Content-Type: text/html" CRLF
                 "Transfer-Encoding: chunked" CRLF
                 "Connection: Keep-Alive" CRLF CRLF);
        http_server_send(request->socket, response, strlen(response));

        snprintf(response, SEND_BUFFER_SIZE, "7B\r\n%s%s%s%s",
                 "<html><head><style>\r\n",
                 "body{font-family: monospace; font-size: 15px;}\r\n",
                 "td {padding: 1.5px 6px;}\r\n",
                 "</style></head><body><table>\r\n");
        http_server_send(request->socket, response, strlen(response));

        request->dir_context.actor = tracedir;
        iterate_dir(fp, &request->dir_context);

        snprintf(response, SEND_BUFFER_SIZE, "%s",
                 "16\r\n</table></body></html>\r\n");
        http_server_send(request->socket, response, strlen(response));

        snprintf(response, SEND_BUFFER_SIZE, "%s", "0\r\n\r\n");
        http_server_send(request->socket, response, strlen(response));
    } else if (S_ISREG(fp->f_inode->i_mode)) {
        char *html_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        int html_length = kernel_read(fp, html_data, fp->f_inode->i_size, 0);
        char *type = search_mime_type(request->request_url);

        /*compress data*/
        char *comp_data = kmalloc(fp->f_inode->i_size, GFP_KERNEL);
        unsigned int comp_len = fp->f_inode->i_size;
        bool ret = data_compress(html_data, html_length, comp_data, &comp_len);
        if (!ret) {
            kfree(html_data);
            filp_close(fp, NULL);
            kfree(comp_data);
            return false;
        }

        snprintf(response, SEND_BUFFER_SIZE,
                 ""
                 "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF
                 "Content-Encoding: deflate" CRLF "Content-Type: %s" CRLF
                 "Content-Length:%d" CRLF "Connection: Keep-Alive" CRLF CRLF,
                 type, comp_len);
        http_server_send(request->socket, response, strlen(response));

        http_server_send(request->socket, comp_data, comp_len);
        kfree(comp_data);
        kfree(html_data);
    }

    filp_close(fp, NULL);
    return true;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    pr_info("requested_url = %s\n", request->request_url);
    pr_info("method = %d\ncomplete = %d\n", request->method, request->complete);
    send_directory(request, keep_alive);
    // kernel_sock_shutdown(request->socket, SHUT_RDWR);

    return 0;
}

enum http_method map_method(size_t method_len)
{
    if (method_len == 4)
        return HTTP_POST;
    else
        return HTTP_GET;
}

/*this function to handle http request*/
static int phr_parse(struct http_request *request, char *buf, ssize_t size)
{
    const char *method, *path;
    int pret, minor_version;
    struct phr_header headers[100];
    size_t buflen = size, prevbuflen = 0, method_len, path_len,
           num_headers = 100;

    pret =
        phr_parse_request(buf, buflen, &method, &method_len, &path, &path_len,
                          &minor_version, headers, &num_headers, prevbuflen);
    if (pret == -1)
        return 0;

    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;

    request->request_url[0] = '\0';


    if (path_len > 128)
        return 0;
    else if (path_len == 1 && path[path_len - 1] == '/')
        path_len = 0;
    strncat(request->request_url, path, path_len);

    request->method = map_method(method_len);

    http_server_response(request, 1);  // http_should_keep_alive(parser));
    request->complete = 1;

    return 1;
}

struct workqueue_struct *cmwq_workqueue;

static void http_server_worker(struct work_struct *w)
{
    struct link_data *data_for_link = container_of(w, struct link_data, worker);

    char *buf;
    // struct http_parser parser;
    // struct http_parser_settings setting = {
    //     .on_message_begin = http_parser_callback_message_begin,
    //     .on_url = http_parser_callback_request_url,
    //     .on_header_field = http_parser_callback_header_field,
    //     .on_header_value = http_parser_callback_header_value,
    //     .on_headers_complete = http_parser_callback_headers_complete,
    //     .on_body = http_parser_callback_body,
    //     .on_message_complete = http_parser_callback_message_complete,
    // };
    struct http_request request;
    // struct socket *socket = (struct socket *) arg;
    struct socket *socket = data_for_link->socket;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    read_lock(&attr_obj.lock);
    char enable = attr_obj.enable;
    read_unlock(&attr_obj.lock);


    request.socket = socket;
    // http_parser_init(&parser, HTTP_REQUEST);
    // parser.data = &request;

    unsigned long expire_time = jiffies;  // to record the linking time

    while (!kthread_should_stop() && enable == '1') {
        ssize_t ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret == -EAGAIN) {
                if (time_after(jiffies, expire_time + msecs_to_jiffies(5000))) {
                    pr_info("linking expired");
                    break;
                }
                msleep(10);
                continue;
            } else if (ret)
                pr_err("recv error: %d\n", ret);

            break;
        }

        expire_time = jiffies;  // update expire time

        // http_parser_execute(&parser, &setting, buf, ret);
        phr_parse(&request, buf, ret);
        if (request.complete)  // && !http_should_keep_alive(&parser))
            break;
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
    return;
}

static struct class *ktcp_class;
static struct device *ktcp_dev;

static int init_sys(void)
{
    ktcp_class = class_create("ktcp");
    if (IS_ERR(ktcp_class))
        return PTR_ERR(ktcp_class);
    ktcp_dev = device_create(ktcp_class, NULL, 0, NULL, "ktcp");
    if (IS_ERR(ktcp_dev)) {
        class_destroy(ktcp_class);
        return PTR_ERR(ktcp_dev);
    }
    device_create_file(ktcp_dev, &dev_attr_ktcp_state);

    attr_obj.enable = '1';
    rwlock_init(&attr_obj.lock);

    return 0;
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    struct task_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    cmwq_workqueue = alloc_workqueue("Ktcp", 0, 0);
    if (init_sys() != 0)
        pr_info("init_sys error");


    while (!kthread_should_stop()) {
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        struct link_data *worker;

        if (!(worker = kmalloc(sizeof(struct link_data), GFP_KERNEL)))
            return NULL;

        worker->socket = socket;
        INIT_WORK(&worker->worker, http_server_worker);
        queue_work(cmwq_workqueue, &worker->worker);
    }

    flush_workqueue(cmwq_workqueue);
    destroy_workqueue(cmwq_workqueue);
    device_destroy(ktcp_class, 0);
    class_destroy(ktcp_class);

    return 0;
}
