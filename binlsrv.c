/*
 * Mini Binl Server
 * Copyright (c) 2005-2006 Gianluigi Tiesi <sherpya@netfarm.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this software; if not, write to the
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Compilation on linux: gcc binlsrv.c -o binlsrv
 * Compilation on mingw: gcc binlsrv.c -o binlsrv -lws2_32
 * Compilation on msvc : cl.exe binlsrv.c ws2_32.lib
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define PORT 4011

#ifdef _WIN32
#include <winsock2.h>
#define __BYTE_ORDER __LITTLE_ENDIAN
#define inline __inline
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
#else
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h> /* inet_ntoa */
#include <errno.h>
#include <inttypes.h>
#define INVALID_SOCKET      -1
#define SOCKET_ERROR        -1
#define closesocket         close
#define WSAGetLastError()   errno
#define WSACleanup()
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define SWAB32(x) x
#define SWAB16(x) x
#elif __BYTE_ORDER == __BIG_ENDIAN
#define SWAB32(x) (((uint32_t)(x) >> 24) | \
                  (((uint32_t)(x) >> 8) & 0xff00) | \
                  (((uint32_t)(x) << 8) & 0xff0000) | \
                  ((uint32_t)(x) << 24))
#define SWAB16(x) (((uint16_t)(x) >> 8) | (((uint16_t)(x) & 0xff) << 8))
#else
#error "Unknown byte order"
#endif

#define PKT_NCQ             0x51434e81 /* LE */
#define PKT_NCR             0x52434e82 /* LE */

#define NCR_OK              0x0        /* LE = BE */
#define NCR_KO              0xc000000d /* LE */

const char ris_params[] = "Description\0" "2\0" "Ris NIC Card\0"
                          "Characteristics\0" "1\0" "132\0"
                          "BusType\0" "1\0" "5\0";

typedef struct _DRIVER
{
    uint16_t vid, pid;
    char driver[256];
    char service[256];
} DRIVER;

static int m_socket = INVALID_SOCKET;

static void cleanup(int signum)
{
    printf("Shutting down...\n");
    closesocket(m_socket);
    WSACleanup();
    exit(0);
}

#ifdef _WIN32
static void stop_console_handler(void)
{
    SetConsoleCtrlHandler((PHANDLER_ROUTINE) cleanup, FALSE); 
}
#endif

char get_string(FILE *fd, char *dest, size_t size)
{
    int i = 0;
    char c = 0;

    while (i < size)
    {
        if(fread(&c, 1, sizeof(c), fd) != sizeof(c)) break;
        if(isspace(c)) break;
        dest[i++] = c;
    }
    dest[i] = 0;
    return c;
}

static inline void skipspaces(FILE *fd)
{
    char c = 0;
    while(!feof(fd) && !isspace(c))
        if(fread(&c, 1, sizeof(c), fd) != sizeof(c)) break;
}

static inline void eol(FILE *fd)
{
    char c = 0;
    while(!feof(fd) && (c != '\n') && (c != '\r'))
        if(fread(&c, 1, sizeof(c), fd) != sizeof(c)) break;
}

int find_drv(uint16_t cvid, uint16_t cpid, DRIVER *drv)
{
    uint32_t vid, pid;
    char buffer[1024];
    int found = 0;

    FILE *fd = fopen("nics.txt", "r");
    if (!fd)
    {
         printf("Problems opening nics.txt\n");
         return 0;
    }

    while (1)
    {
        if (fread(buffer, 1, 4, fd) != 4) break;
        buffer[4] = 0;
        sscanf(buffer, "%x", &vid);

        skipspaces(fd);

        if (fread(buffer, 1, 4, fd) != 4) break;
        buffer[4] = 0;
        sscanf(buffer, "%x", &pid);

        skipspaces(fd);

        if (!isspace(get_string(fd, drv->driver, sizeof(drv->driver))))
            skipspaces(fd);

        if (!isspace(get_string(fd, drv->service, sizeof(drv->service))))
            eol(fd);

        drv->vid = vid;
        drv->pid = pid;

        printf("Checking vs 0x%x - 0x%x: %s - ", vid, pid, drv->driver);

        if ((SWAB16(cvid) == vid) && (SWAB16(cpid) == pid))
        {
            found = 1;
            printf("Matched\n");
            break;
        }
        printf("No Match\n");
    }

    fclose(fd);
    return found;
}

void dump_packet(char *packet, size_t size, const char *filename)
{
    FILE *fd = fopen(filename, "wb");
    if (!fd) return;

    fwrite(packet, 1, size, fd);
    fclose(fd);
}

size_t ascii_to_utf16le(const char *src, char *dest, size_t offset)
{
    size_t ulen = 0, i = 0;
    size_t len = strlen(src);

    for (i = 0; i < len; i++)
    {
        dest[offset+ulen] = src[i];
        ulen += 2;
    }
    return ulen;
}

int main(int argc, char *argv[])
{
    DRIVER drv;
    struct sockaddr_in local, from;
    char buffer[1024];
    char packet[1024];
    uint32_t type = 0, value = 0, res = NCR_OK;
    uint16_t vid = 0, pid = 0;
    size_t fromlen = 0, offset = 0, retval = 0;
    
#ifdef _WIN32
    WSADATA wsaData;
    SetConsoleCtrlHandler((PHANDLER_ROUTINE) cleanup, TRUE);
    atexit(stop_console_handler);
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != NO_ERROR)
    {
        printf("Error at WSAStartup()\n");
        return -1;
    }
#else
    signal(SIGINT, cleanup);
#endif

    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (m_socket == INVALID_SOCKET)
    {
        printf("Error at socket(): %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(PORT);

    if (bind(m_socket, (struct sockaddr *) &local, sizeof(local)) == SOCKET_ERROR)
    {
        fprintf(stderr, "bind() failed with error %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    printf("Mini Binl Server - Copyright (c) 2005-2006 Gianluigi Tiesi\n");
    printf("Listening on port %d\n", PORT);

    while (1)
    {
        fromlen = sizeof(from);
        retval = recvfrom(m_socket, buffer, sizeof(buffer), 0, (struct sockaddr *) &from, &fromlen);
        printf("Received datagram from %s\n", inet_ntoa(from.sin_addr));

        if (retval < 0)
        {
            fprintf(stderr, "recv() failed: error %d\n", WSAGetLastError());
            continue;
        }

        if (retval == 0)
        {
            printf("Client closed connection\n");
            continue;
        }

        memcpy(&type, buffer, sizeof(type));
        printf("Received %d bytes, packet [0x%08x] from client\n", retval, SWAB32(type));

        if (SWAB32(type) != PKT_NCQ)
        {
            printf("Only NCQ packets are supported\n");
            continue;
        }

        memcpy(&vid, &buffer[0x24], sizeof(vid));
        memcpy(&pid, &buffer[0x26], sizeof(pid));
        printf("Vendor id 0x%x - Product id 0x%x\n", SWAB16(vid), SWAB16(pid));

        offset = 0;
        memset(packet, 0, sizeof(packet));
        type = SWAB32(PKT_NCR);
        memcpy(packet, &type, sizeof(type));
        offset += sizeof(type);

        if (find_drv(vid, pid, &drv))
        {
            size_t ulen = 0;
            res = SWAB32(NCR_OK);
            offset += 0x4; /* Packet len will be filled later */

            memcpy(&packet[offset], &res, sizeof(res));
            offset += sizeof(res);

            value = SWAB32(0x2); /* Type */
            memcpy(&packet[offset], &value, sizeof(value));
            offset += sizeof(value);

            value = SWAB32(0x24); /* Base offset */
            memcpy(&packet[offset], &value, sizeof(value));
            offset += sizeof(value);

            offset += 0x8; /* Driver name offset / Service name offset */

            value = SWAB32(sizeof(ris_params)); /* Parameters list length in chars */
            memcpy(&packet[offset], &value, sizeof(value));
            offset += sizeof(value); 

            offset += 0x4; /* Parameters list offset */

            printf("Found Driver is %s - Service is %s\n", drv.driver, drv.service);
            sprintf(buffer, "PCI\\VEN_%04X&DEV_%04X", drv.vid, drv.pid);

            ulen = ascii_to_utf16le(buffer, packet, offset);
            offset += ulen + 2; /* PCI\VEN_XXXX&DEV_YYYY */

            /* We can fill Driver name offset */
            value = SWAB32(offset);
            memcpy(&packet[0x14], &value, sizeof(value));

            ulen = ascii_to_utf16le(drv.driver, packet, offset);
            offset += ulen + 2; /* Driver name */

            /* We can fill Service name offset */
            value = SWAB32(offset);
            memcpy(&packet[0x18], &value, sizeof(value));

            ulen = ascii_to_utf16le(drv.service, packet, offset);
            offset += ulen + 2; /* Service name */

            /* We can fill Parameters list offset */
            value = SWAB32(offset);
            memcpy(&packet[0x20], &value, sizeof(value));

            /* And now params */
            memcpy(&packet[offset], ris_params, sizeof(ris_params));
            offset += sizeof(ris_params) + 2;

            /* Packet Len */
            value = SWAB32(offset);
            memcpy(&packet[0x4], &value, sizeof(value));

            printf("Found - Sending NCR OK\n");
            retval = sendto(m_socket, packet, offset, 0, (struct sockaddr *) &from, fromlen);
            if (retval < 0) fprintf(stderr, "send() failed: error %d\n", WSAGetLastError());
        }
        else
        {
            res = SWAB32(NCR_KO);
            value = SWAB32(offset);
            memcpy(&packet[offset], &value, sizeof(value));
            offset += sizeof(offset);
            memcpy(&packet[offset], &res, sizeof(res));
            offset += sizeof(res);
            printf("Not Found - Sending NCR Fail\n");
            retval = sendto(m_socket, packet, offset, 0, (struct sockaddr *) &from, fromlen);
            if (retval == SOCKET_ERROR) fprintf(stderr, "send() failed: error %d\n", WSAGetLastError());
        }
    }

    /* The server never reach this point */
    closesocket(m_socket);
    WSACleanup();
    return 0;
}
