#ifndef MOD_PASSAUTH_LOG_HPP_
#define MOD_PASSAUTH_LOG_HPP_

#include <sstream>

#include "http_log.h"

#ifdef AP_SERVER_MINORVERSION_NUMBER
APLOG_USE_MODULE(acl_localdb);
#endif /* AP_SERVER_MINORVERSION_NUMBER */

#define LOG(level, server, fmt, ...) ap_log_error(APLOG_MARK, level, 0, server, fmt, ##__VA_ARGS__)
#define LOGS(level, server) (mod_passauth::detail::ErrorLogStream(APLOG_MARK, level, server))


namespace mod_passauth {
namespace detail {

class ErrorLogStream {
  public:
    ErrorLogStream(const char *func, int line, int level, const server_rec *s = NULL, apr_status_t status = 0)
      : func_(func), line_(line), level_(level), status_(status), s_(s) {}
    ~ErrorLogStream() {
      flush();
    }

    void flush() {
      if (!oss_.str().empty()) {
#ifdef AP_SERVER_MINORVERSION_NUMBER
        ap_log_error(func_, line_, 0, level_, status_, s_, oss_.str().c_str());
#else /* AP_SERVER_MINORVERSION_NUMBER */
        ap_log_error(func_, line_, level_, status_, s_, oss_.str().c_str());
#endif /* AP_SERVER_MINORVERSION_NUMBER */
      }
    }

    template<typename T>
    ErrorLogStream& operator<<(const T& value) {
      oss_ << value;
      return *this;
    }

  private:
    const char *func_;
    int line_;
    int level_;
    apr_status_t status_;
    const server_rec *s_;
    std::ostringstream oss_;
};


} /* namespace detail */
} /* namespace mod_passauth */

#endif /* MOD_PASSAUTH_LOG_HPP_ */
