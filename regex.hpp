#ifndef MOD_PASSAUTH_REGEX_HPP_
#define MOD_PASSAUTH_REGEX_HPP_

#include <pcreposix.h>

#include <string>
#include <exception>

#include <boost/array.hpp>
#include <boost/noncopyable.hpp>

namespace mod_passauth {
namespace detail {

class PCREPosixRegexError : public std::exception {
  public:
    PCREPosixRegexError(const std::string& desc, const std::string& regex_format, int errcode, const regex_t& regex) {
      boost::array<char, 1024> errbuf = {{0}};
      ::regerror(errcode, &regex, errbuf.data(), errbuf.size());
      what_ = desc + "(\"" + regex_format + "\"): " + errbuf.data();
    }
    virtual ~PCREPosixRegexError() throw() {}
    virtual const char *what() const throw() {
      return what_.c_str();
    }
  private:
    std::string what_;
};

class PCREPosixRegex : boost::noncopyable {
  public:
    explicit PCREPosixRegex(const std::string& regex_format, int cflags = REG_EXTENDED)
      : regex_format_(regex_format) {
      int rv = ::regcomp(&compiled_regex_, regex_format_.c_str(), cflags);
      if (rv != 0) {
        throw PCREPosixRegexError("regex failed to compile", regex_format_, rv, compiled_regex_);
      }
    }
    ~PCREPosixRegex() {
      ::regfree(&compiled_regex_);
    }

    bool match(const char *s, int eflags = 0) {
      return 0 == ::regexec(&compiled_regex_, s, 0, NULL, eflags);
    }

  private:
    std::string regex_format_;
    regex_t compiled_regex_;
};

} /* namespace detail */
} /* namespace mod_passauth */

#endif /* MOD_PASSAUTH_REGEX_HPP_ */
