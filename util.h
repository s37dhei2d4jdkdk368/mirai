#pragma once

#include "includes.h"

#define CONVERT_ADDR(x) x & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff

void util_strcat(char *, char *);
void util_memcpy(void *, void *, int);
void util_zero(void *, int);

int util_strlen(char *);
int util_strcpy(char *, char *);
int util_atoi(char *, int);
int util_memsearch(char *, int, char *, int);
int util_stristr(char *, int, char *);

BOOL mem_exists(char *, int, char *, int);
BOOL util_strncmp(char *, char *, int);
BOOL util_strcmp(char *, char *);

char *util_itoa(int, int, char *);
char *util_fdgets(char *, int, int);

int util_isupper(char);
int util_isalpha(char);
int util_isspace(char);
int util_isdigit(char);

int _isupper(char);
int _isalpha(char);
int _isspace(char);
int util_isdigit(char);

void _strcat(char *, char *);
void _memcpy(void *, void *, int);
void _zero(void *, int);

int util_strlen(char *);
int _strcpy(char *, char *);
int _atoi(char *);
int _memsearch(char *, int, char *, int);
int _stristr(char *, int, char *);
int _startswith(char *, char *);

int memory_exists(char *, int, char *, int);
int _strncmp(char *, char *, int);
int _strcmp(char *, char *);
int _strcmp2(char *, char *);
void rand_bytes(unsigned char *, int);
char *_itoa(int, int, char *);
char *_fdgets(char *, int, int);
char *hex_to_text(char *);
char *_strdup(char *);
void _memset(void *, char, int);

ipv4_t util_local_addr(void);
int util_get_cpu_cores(void);
