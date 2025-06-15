#ifndef _MIME_H_
#define _MIME_H_
typedef struct {
    const char *type;
    const char *label;
} mime_map;

extern mime_map mime_type[] = {
    {".png", "image/png"},
    {".pdf", "application/pdf"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".rar", "application/vnd.rar"},
    {".txt", "text/plain"},
    {".zip", "application/zip"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {NULL, NULL},
};
#endif