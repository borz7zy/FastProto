#pragma once

#ifdef _WIN32
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;

  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <io.h>
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
#else
  #include <unistd.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif
