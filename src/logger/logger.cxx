#include <fast_proto/logger.hxx>

#ifdef __ANDROID__
#include <android/log.h>

#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, __VA_ARGS__)
#else
#include <iostream>
using namespace std;
#endif

void FastProto::Logger::print_verbose(const char* tag, const char* msg) {
#ifdef __ANDROID__
  LOGV(tag, "%s", msg);
#else
  cout << "\"VERBOSE\"[" << tag << "]" << msg << "\n";
#endif
}

void FastProto::Logger::print_debug(const char* tag, const char* msg) {
#ifdef __ANDROID__
  LOGD(tag, "%s", msg);
#else
#ifdef _DEBUG
  cout << "\"DEBUG\"[" << tag << "]" << msg << "\n";
#endif
#endif
}

void FastProto::Logger::print_info(const char* tag, const char* msg) {
#ifdef __ANDROID__
  LOGI(tag, "%s", msg);
#else
  cout << "\"INFO\"[" << tag << "]" << msg << "\n";
#endif
}

void FastProto::Logger::print_warning(const char* tag, const char* msg) {
#ifdef __ANDROID__
  LOGW(tag, "%s", msg);
#else
  cout << "\"WARNING\"[" << tag << "]" << msg << "\n";
#endif
}

void FastProto::Logger::print_error(const char* tag, const char* msg) {
#ifdef __ANDROID__
  LOGE(tag, "%s", msg);
#else
  cerr << "\"ERROR\"[" << tag << "] " << msg << "\n";
#endif
}
