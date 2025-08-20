#pragma once

#ifdef __SSIZE_T_
#ifdef _WIN32
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
#endif
#endif

#ifdef __NET_
#ifdef _WIN32
// includes here
#else
// includes here
#endif
#endif