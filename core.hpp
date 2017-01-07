#ifndef mod_passauth_CORE_HPP_
#define mod_passauth_CORE_HPP_

#include "mod_passauth/provider.hpp" /* this must before "httpd.h" */

#include "apr_pools.h"
#include "apr_time.h"

#include "httpd.h"

#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <sstream>
#include <vector>

#include <boost/noncopyable.hpp>

#include "mod_passauth/config.hpp"
#include "mod_passauth/pool.hpp"

namespace mod_passauth {

class AUTH {
  public:
    ~AUTH() {}

    bool check_client_verify_mode(request_rec *r);
    std::tuple<std::string, std::string> get_token_from_req(request_rec *r);
    bool jump_auth_url(request_rec *r);
    bool loadAuth(std::strng usertoken) {
        return auth_rules_provider_.load(usertoken);
    }
    bool checkPermission(apr_time_t time, std::string pwdtoken) {
      return auth_rules_provider_.isAllowedToAccessAuth(time, pwdtoken);
    }

  private:
    explicit AUTH(const ModuleConfig& config)
      : auth_rules_provider_(config.auth_db_config) {
    }

    friend AUTH *make_auth(apr_pool_t *pool, const ModuleConfig& config);

    detail::AUTHRulesProvider auth_rules_provider_;
};

inline AUTH *make_auth(apr_pool_t *pool, const ModuleConfig& config) {
  AUTH *auth = new AUTH(config);
  detail::pool_register_delete(pool, auth);
  return auth;
}

} /* namespace mod_passauth */

#endif /* mod_passauth_CORE_HPP_ */
