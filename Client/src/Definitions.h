#ifndef _DEFINITION_H
#define _DEFINITION_H

#ifdef __APPLE__
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
#ifdef WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif

#define VERSION 1
#define CREDS_FILE "me.info"
#define CLIENT_UUID_LENGTH 16
#define USERNAME_MAX_LENGTH 255


#endif