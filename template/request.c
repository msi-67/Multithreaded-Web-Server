#include "io_helper.h"
#include "request.h"
#include <string.h>
#include <stdio.h> 
#define MAXBUF (8192)
pthread_cond_t empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t full = PTHREAD_COND_INITIALIZER;
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;

//
//	TODO: add code to create and manage the buffer
//
int init_queue = 0;
int buffer_size;
int scheduling_algo;
int num_threads;
int buffer_max_size;
typedef enum {FALSE, TRUE} Boolean;
typedef enum {FAILURE, SUCCESS} status_code;
typedef struct Request_Queue
{
    char* filename;
    int fd;
    int filesize;
}Requests;

typedef struct Requests_Queue
{
    Requests requests;
	struct Requests_Queue* next;
}Req_Queue;

typedef struct Queue_tag
{
	Req_Queue* tail;
	Req_Queue* head;
	int count;
}Queue;

Queue Request_Response;

void initialise_queue(Queue* qptr)
{
	qptr->head = NULL;
	qptr->tail = NULL;
	qptr->count = 0;
}

Boolean isQueueEmpty(Queue* qptr)
{
	return (qptr->head == NULL && qptr->tail==NULL);
}

status_code Insert_Request(Queue* qptr, char* filename, int fd, int filesize)
{
    printf("Getting Request from Client......\n");
    if(qptr->count == buffer_max_size)
        return FAILURE;
    else
    {
		printf("in insert\n");
		Req_Queue* req;
		req = (Req_Queue*)malloc(sizeof(Req_Queue));
		if (req != NULL)
		{
			printf("req assigned space.\n");
		}
		
		req->requests.fd = fd;
		req->requests.filesize = filesize;
        req->requests.filename = strdup(filename);
		printf("%d %d %s\n",req->requests.fd, req->requests.filesize, req->requests.filename);
		// puts(req->requests.filename)
        req->next = NULL;
		printf("set to null\n");
        if (isQueueEmpty(qptr))
        {
            printf("In is empty\n");
            qptr->tail = req;
            printf("set tail to req\n");
            qptr->head = req;
            printf("set head to req\n");
        }
        else
        {
            qptr->tail->next = req;
            qptr->tail = req;
        }
		qptr->count++;
		return SUCCESS;
    }
}

status_code Insert_sorted(Queue* qptr, char* filename, int fd, int filesize)
{
    if (qptr->count >= buffer_max_size)
    {
        return FAILURE;
    }
    else
    {
        Req_Queue* req;
        req = (Req_Queue*)malloc(sizeof(Req_Queue));
		if (req != NULL)
		{
			printf("req assigned space.\n");
		}
		req->requests.fd = fd;
		req->requests.filesize = filesize;
        req->requests.filename = strdup(filename);
		req->next = NULL;
        if(isQueueEmpty(qptr))
        {
            qptr->head = req;
            qptr->tail = req;
        }
        else if(qptr->head->requests.filesize > req->requests.filesize)
        {
            req->next = qptr->head;
            qptr->head = req;
        }
        else
        {
            Req_Queue* nptr;
            nptr = qptr->head;
            while (req->requests.filesize > nptr->requests.filesize && nptr != qptr->tail)
            {
                nptr = nptr->next;
            }
            if(nptr != qptr->tail)
            {
                Req_Queue* link = nptr->next;
                nptr->next = req;
                req->next = link;
            }
            else
            {
                qptr->tail->next = req;
                qptr->tail = req;
            }
        }
        return SUCCESS; 
    }
}

status_code Delete_sorted(Queue* qptr, Requests* a)
{
    if(isQueueEmpty(qptr))return FAILURE;
    else
    {
        printf("Sending response to request SSF............\n");
		Req_Queue* nptr;
		nptr = qptr->head;
		*a = nptr->requests;
        printf("%d %d %s", a->fd, a->filesize, a->filename);
		qptr->head = qptr->head->next;
		if (qptr->head == NULL)
		{
			qptr->tail = NULL;
		}
		free(nptr);
		qptr->count--;
		return SUCCESS;        
    }
}
status_code Delete_Request(Queue *qptr, Requests *a)
{
    if(isQueueEmpty(qptr))return FAILURE;
    else
    {
		printf("Sending response to request............\n");
		Req_Queue* nptr;
		nptr = qptr->head;
		*a = nptr->requests;
        printf("%d %d %s", a->fd, a->filesize, a->filename);
		qptr->head = qptr->head->next;
		if (qptr->head == NULL)
		{
			qptr->tail = NULL;
		}
		free(nptr);
		qptr->count--;
		return SUCCESS;
	}  
}
//
// Sends out HTTP response in case of errors
//
void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];
    
    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
            "<!doctype html>\r\n"
            "<head>\r\n"
            "  <title>OSTEP WebServer Error</title>\r\n"
            "</head>\r\n"
            "<body>\r\n"
            "  <h2>%s: %s</h2>\r\n" 
            "  <p>%s: %s</p>\r\n"
            "</body>\r\n"
            "</html>\r\n", errnum, shortmsg, longmsg, cause);
    
    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));
    
    // Write out the body last
    write_or_die(fd, body, strlen(body));
    
    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];
    
    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
		readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
//
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;
    
    if (!strstr(uri, "cgi")) { 
        // static
        strcpy(cgiargs, "");
        sprintf(filename, ".%s", uri);
        if (uri[strlen(uri)-1] == '/') {
            strcat(filename, "index.html");
        }
        return 1;
    } else { 
        // dynamic
        ptr = index(uri, '?');
        if (ptr) {
            strcpy(cgiargs, ptr+1);
            *ptr = '\0';
        } else {
            strcpy(cgiargs, "");
        }
        sprintf(filename, ".%s", uri);
        return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) 
		strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif")) 
		strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg")) 
		strcpy(filetype, "image/jpeg");
    else 
		strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];
    
    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);
    
    // Rather than call read() to read the file into memory, 
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);
    
    // put together response
    sprintf(buf, ""
            "HTTP/1.0 200 OK\r\n"
            "Server: OSTEP WebServer\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: %s\r\n\r\n", 
            filesize, filetype);
       
    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}

//
// Fetches the requests from the buffer and handles them (thread logic)
//
void* thread_request_serve_static(void* arg)
{
    while (1)
    {
        while (scheduling_algo == 0)
        {
			printf("In thread..\n");
            status_code sc;
            Requests a;
            pthread_mutex_lock(&m);
            sc = Delete_Request(&Request_Response, &a);
			printf("This is sc of thread: %d\n",sc);
            while (sc == FAILURE)
            {
                pthread_cond_wait(&empty, &m);
                sc = Delete_Request(&Request_Response, &a);
            }
            printf("Delete ka sc\n");
            pthread_cond_signal(&full);
            pthread_mutex_unlock(&m);
            request_serve_static(a.fd,a.filename,a.filesize);
        }
        while (scheduling_algo == 1)
        {
            printf("sce 2\n");
            status_code sc;
            Requests a;
            pthread_mutex_lock(&m);
            sc = Delete_sorted(&Request_Response, &a);
            while (sc == FAILURE)
            {
                pthread_cond_wait(&empty, &m);
                sc = Delete_Request(&Request_Response, &a);
            }
            printf("Delete ka sc\n");
            pthread_cond_signal(&full);
            pthread_mutex_unlock(&m);
            request_serve_static(a.fd,a.filename,a.filesize);
        }
    }	// TODO: write code to actualy respond to HTTP requests
}

//
// Initial handling of the request
//
// Queue a;
void request_handle(int fd) {
	int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
    
	// get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%syeye\n", method, uri, version);

    if (strstr(filename, ".."))
    {
            request_error(fd, filename, "401", "Forbidden", "Illegal access attempt.");
            return;    
    }
        
	// verify if the request type is GET or not
    if (strcasecmp(method, "GET")) {
		request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
		return;
    }
    request_read_headers(fd);
    
	// check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);
    

	// get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
		request_error(fd, filename, "404", "Not found", "server could not find this file");
		return;
    }
    
	// verify if requested content is static
    if (is_static) {
		if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
			request_error(fd, filename, "403", "Forbidden", "server could not read this file");
			return;
		}
		// TODO: write code to add HTTP requests in the buffer based on the scheduling policy

		status_code sc;
		if(scheduling_algo == 0)
		{
		    pthread_mutex_lock(&m);
            if (init_queue == 0)
            {
                initialise_queue(&Request_Response);
                init_queue++;
            }
        	printf("Going into insert..\n");
            printf("THe queue empty :%d\n",isQueueEmpty(&Request_Response));
            sc = Insert_Request(&Request_Response,filename,fd,sbuf.st_size);
            printf("Insert ka sc %d\n",sc);
		    while (sc == FAILURE)
		    {
		        pthread_cond_wait(&full,&m);
		        sc = Insert_Request(&Request_Response,filename,fd,sbuf.st_size);
		    }

            printf("THe queue empty :%d\n",isQueueEmpty(&Request_Response));
		    pthread_cond_signal(&empty);
		    pthread_mutex_unlock(&m);
		}
        else if(scheduling_algo == 1)
        {
            pthread_mutex_lock(&m);
            if (init_queue == 0)
            {
                initialise_queue(&Request_Response);
                init_queue++;
            }
        	printf("Going into insert SSF..\n");
            printf("THe queue empty SSF :%d\n",isQueueEmpty(&Request_Response));
            sc = Insert_sorted(&Request_Response,filename,fd,sbuf.st_size);
            printf("Insert ka sc SSF %d\n",sc);
		    while (sc == FAILURE)
		    {
		        pthread_cond_wait(&full,&m);
		        sc = Insert_sorted(&Request_Response,filename,fd,sbuf.st_size);
            }
            printf("THe queue empty SSF:%d\n",isQueueEmpty(&Request_Response));
		    pthread_cond_signal(&empty);    
		    pthread_mutex_unlock(&m);
        }
    }else {
		request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    } 
}
