#ifndef MOD_PASSAUTH_CONFIG_HPP_
#define MOD_PASSAUTH_CONFIG_HPP_

#include <string>
#include <vector>

#include <boost/logic/tribool.hpp>
#include <boost/shared_ptr.hpp>

#include "mod_passauth/mod_passauth.h"
#include "mod_passauth/regex.hpp"

namespace mod_passauth {
class AUTH;

#define SQL_SQLITE_PRAGMA_JOURNAL_MODE "PRAGMA journal_mode="
#define SQL_SQLITE_PRAGMA_JOURNAL_MODE_MEMORY SQL_SQLITE_PRAGMA_JOURNAL_MODE"MEMORY;"

struct DBConfig {
  DBConfig()
    : sqlite_busy_timeout_ms(3000)
    , sqlite_journal_mode(SQL_SQLITE_PRAGMA_JOURNAL_MODE_MEMORY) {}
  std::string db_path;
  int sqlite_busy_timeout_ms;
  std::string sqlite_journal_mode;
};

struct ModuleConfig {
  ModuleConfig()
    : auth(NULL) {}
  AUTH *auth;
  DBConfig auth_db_config;
};

struct PerServerConfig {
  PerServerConfig()
    : module_config(NULL)
  ModuleConfig *module_config;
  std::string jump_extr_auth_url;
  std::vector<boost::shared_ptr<detail::PCREPosixRegex> > match_uri_regexs;
};

struct PerDirectoryConfig {
  PerDirectoryConfig() : authenable(boost::logic::indeterminate) {}
  boost::tribool authenable;
};

inline PerServerConfig *get_per_server_config(server_rec *s) {
  return reinterpret_cast<mod_passauth::PerServerConfig *>(ap_get_module_config(s->module_config, &acl_localdb_module));
}
inline PerDirectoryConfig *get_per_directory_config(struct ap_conf_vector_t *dir_conf) {
  return reinterpret_cast<mod_passauth::PerDirectoryConfig *>(ap_get_module_config(dir_conf, &acl_localdb_module));
}
inline ModuleConfig *get_module_config(server_rec *s) {
  return (get_per_server_config(s))->module_config;
}

void *create_dir_conf(apr_pool_t *p, char *dummy);
void *merge_dir_conf(apr_pool_t *p, void *basev, void *addv);
void *create_svr_conf(apr_pool_t *p, server_rec *dummy);
void *merge_svr_conf(apr_pool_t *p, void *basev, void *addv);

PerConnectionConfig *create_per_connection_config(apr_pool_t *p);

} /* namespace mod_passauth */

#endif /* MOD_PASSAUTH_CONFIG_HPP_ */
