#ifndef MOD_PASSAUTH_DETAIL_PROVIDER_HPP_
#define MOD_PASSAUTH_DETAIL_PROVIDER_HPP_

#include <sys/stat.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include <boost/noncopyable.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/bind.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/optional.hpp>
#include <boost/array.hpp>

#include "SQLiteCpp/SQLiteCpp.h"

#include "apr_time.h"
#include "apr_network_io.h"

#include "mod_passauth/config.hpp"
#include "mod_passauth/regex.hpp"

namespace mod_passauth {
namespace detail {

using mod_passauth::DBConfig;
 
class PassAuth {
public:
  PassAuth() {
    apr_status_t rv = apr_pool_create(&pool_, NULL);
    if (rv != APR_SUCCESS) {
      throw std::runtime_error("create apr_pool_t for mod_passauth::detail::App failed");
    }
  }

  ~PassAuth() {}

  bool isStateAllowed(int state) const;
  bool isSessionAllowd(std::string sessionid, std::string pwdtoken) const;
  bool isTimeAllowed(std::string allowtimebegin, std::string allowtimeend, apr_time_t time) const;
  bool PassAuth::binduserinfo(std::string useremail, std::string usercn) const;

private:
  int state;
  std::string sessionid;
  std::string allowtimebegin;
  std::string allowtimeend;
  std::string useremail;
  std::string usercn;
  apr_pool_t *pool_;
}


class AUTHRulesProvider {
public:
  AUTHRulesProvider(const DBConfig& config) {
      db_load(boost::bind(&AUTHRulesProvider::load, this));
  }
  ~AUTHRulesProvider() {}

  bool isAllowedToAccessAuth(apr_time_t time, std::string usertoken, std::string pwdtoken) const;
  void load(std::string usertoken);

private:
  void loadAuthsFromDB(SQLite::Database& db, std::string usertoken);
  std::map<const std::string, std::vector<boost::share_ptr<PassAuth>>> auths_indexd_by_user_token;
};

} /* namespace detail */
} /* namespace mod_passauth */

#endif /* MOD_PASSAUTH_DETAIL_PROVIDER_HPP_ */
