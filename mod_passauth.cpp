#include "mod_passauth/core.hpp"

#include <boost/foreach.hpp>
#include <boost/bind.hpp>

#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_optional.h"

#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mod_ssl.h"

#include "ap_config.h"
#include <string.h>
#include <stdlib.h>
#include "pcreposix.h"


#include "mod_passauth/commands.hpp"
#include "mod_passauth/log.hpp"


#define COOKIE_SEQ 1
#define URL_SEQ    2
#define REFERER_SEQ 3

namespace {

#ifdef AP_SERVER_MINORVERSION_NUMBER
APR_DECLARE_OPTIONAL_FN(int, fep_put_error, (request_rec *, int code, const char *type, const char *desc, const char *prompt));
APR_OPTIONAL_FN_TYPE(fep_put_error) *global_fep_put_error = NULL;
#endif /* AP_SERVER_MINORVERSION_NUMBER */

inline int fep_put_error(request_rec *r, int code, const char *type, const char *desc, const char *prompt) {
#ifdef AP_SERVER_MINORVERSION_NUMBER
  if (!global_fep_put_error) {
    return DECLINED;
  }
  return global_fep_put_error(r, code, type, desc, prompt);
#else /* AP_SERVER_MINORVERSION_NUMBER */
  KOAL_SSL_SET_FEP_ERROR_OUTPUT(r, desc, prompt);
  return OK;
#endif /* AP_SERVER_MINORVERSION_NUMBER */
}

int passauth_pre_config(apr_pool_t * /*pconf*/, apr_pool_t * /*plog*/, apr_pool_t * /*ptemp*/) {
#ifdef AP_SERVER_MINORVERSION_NUMBER
  global_fep_put_error = APR_RETRIEVE_OPTIONAL_FN(fep_put_error);
  if (global_fep_put_error == NULL) {
    LOG(APLOG_WARNING, NULL, "optional function fep_put_error is not regisitered");
  }
#endif /* AP_SERVER_MINORVERSION_NUMBER */
  return OK;
}

int passauth_post_config(apr_pool_t *pconf, apr_pool_t * /*plog*/, apr_pool_t *ptemp, server_rec *main_server) {
  
  mod_passauth::PerDirectoryConfig *directory_config = mod_passauth::get_per_directory_config(r->per_dir_config);
  if (directory_config->authenable) {
    LOG(APLOG_INFO, r->server, "passauth is on, enter auth check routine");
  }
  else {
    return OK;
  }

  mod_passauth::ModuleConfig *module_config = mod_passauth::get_module_config(main_server);
  if (module_config->auth_db_config.db_path.empty()) {
    module_config->auth_db_config.db_path = "/kssl/WEBUI/cfg/UserPasswd.db";
    LOG(APLOG_ERR, main_server, "missing USERPASSWD_DB_PATH path config, set it is /kssl/WEBUI/cfg/UserPasswd.db");
  }

  apr_finfo_t sbuf;
  apr_status_t check;
  check = apr_stat(&sbuf, module_config->auth_db_config.db_path.c_str(), APR_FINFO_TYPE, ptemp);
  if (check || sbuf.filetype != APR_REG) {
    LOG(APLOG_ERR, main_server, "USERPASSWD_DB_PATH(%s) file not exists", module_config->user_db_config.db_path.c_str());
    return !OK;
  }

  return OK;
}

int passauth_post_read_request(request_rec *r)
{

  bool verifymode = false;
  verifymode = module_config->auth->check_client_verify_mode(r);
  if (!verifymode) {
    return OK;
  }

  if (apr_table_get(r->headers_in, "Referer")) {
    return OK;
  }

  mod_passauth::PerDirectoryConfig *directory_config = mod_passauth::get_per_directory_config(r->per_dir_config);
  if (directory_config->authenable) {
    LOG(APLOG_INFO, r->server, "passauth is on, enter auth check routine");
  }
  else {
    LOG(APLOG_INFO, r->server, "passauth is off, auth check DECLINED");
    return DECLINED;
  }

  mod_passauth::ModuleConfig *module_config = mod_passauth::get_module_config(r->server);
  try {
    module_config->auth = mod_passauth::make_auth(pconf, *module_config);
  } catch (const std::exception& e) {
    LOG(APLOG_ERR, main_server, "create passauth AUTH failed, throw exception(%s)", e.what());
    return !OK;
  } 
  std::string usertoken;
  std::string pwdtoken;
  std::tie(usertoken, pwdtoken) = module_config->auth->get_token_from_req(r);
  if (!usertoken.empty() && !pwdtoken.empty()) {
      try {
        if (!module_config->auth->loadAuth(usertoken)) {
          LOG(APLOG_INFO, r->server, "loadAuth from db failed.");
        }
      }catch (const std::exception &e) {
        LOG(APLOG_ERR, r->server, "load Auth from db failed, throw exception(%s)", e.what());
      }

      try {
        if (!module_config->auth->checkPermission(apr_time_now(), pwdtoken) {
          LOG(APLOG_INFO, r->server, "acl_localdb failed to pass ACL permisson check, HTTP_FORBIDDEN");
          fep_put_error(r, HTTP_FORBIDDEN, NULL, "网关内部权限系统拒绝本次访问请求", NULL);
          if (!server_config->check_every_request) {
            connection_config->last_result = false;
            LOG(APLOG_INFO, r->server, "acl_localdb is configed not to check every request, cache last result(NOT passed ACL)");
          }
          return HTTP_FORBIDDEN;
        }
      } catch (const std::exception& e) {
        /* connection_config->last_result remains boost::logic::indeterminate */
        LOG(APLOG_ERR, r->server, "acl_localdb ACL permisson check failed, throw exception(%s), HTTP_FORBIDDEN", e.what());
        fep_put_error(r, HTTP_FORBIDDEN, NULL, "网关内部权限系统出现异常", "网关内部权限系统出现异常（如果频繁出现本信息，请与管理员联系）");
        return HTTP_FORBIDDEN;
      }
  }
  else {
    module_config->auth->jump_auth_url(r);
  }

  LOG(APLOG_INFO, r->server, "acl_localdb pass ACL permisson check successfully, go on");
  return DECLINED;
}

void passauth_register_hooks(apr_pool_t *) {
  ap_hook_pre_config(passauth_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_config(passauth_post_config, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_post_read_request(passauth_post_read_request, NULL, NULL, APR_HOOK_MIDDLE);
}

} /* namespace */

extern "C" {

module AP_MODULE_DECLARE_DATA passauth_module = {
  STANDARD20_MODULE_STUFF,
  mod_passauth::create_dir_conf, /* Per-directory configuration handler */
  mod_passauth::merge_dir_conf,  /* Merge handler for per-directory configurations */
  mod_passauth::create_svr_conf, /* Per-server configuration handler */
  mod_passauth::merge_svr_conf,  /* Merge handler for per-server configurations */
  mod_passauth::directives,      /* Any directives we may have for httpd */
  passauth_register_hooks        /* Our hook registering function */
};

} /* extern "C" */

