#pragma once

#ifdef __SSIZE_T_
#ifdef _WIN32
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
#endif
#endif

#ifdef __NET_
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif
#endif

#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
#endif
