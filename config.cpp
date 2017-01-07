#include "mod_passauth/config.hpp"

#include <algorithm>
#include <iterator>

#include "mod_passauth/pool.hpp"

namespace mod_passauth {

void *create_dir_conf(apr_pool_t *p, char *) {
  PerDirectoryConfig *directory_config = new PerDirectoryConfig();
  detail::pool_register_delete(p, directory_config);
  return reinterpret_cast<void *>(directory_config);
}
void *merge_dir_conf(apr_pool_t *p, void *basev, void *addv) {
  PerDirectoryConfig *base = reinterpret_cast<PerDirectoryConfig *>(basev);
  PerDirectoryConfig *add = reinterpret_cast<PerDirectoryConfig *>(addv);
  PerDirectoryConfig *directory_config = new PerDirectoryConfig();
  detail::pool_register_delete(p, directory_config);
  directory_config->authenable = boost::logic::indeterminate(add->authenable) ? base->authenable : add->authenable;
  return reinterpret_cast<void *>(directory_config);
}

void *create_svr_conf(apr_pool_t *p, server_rec *) {
  PerServerConfig *server_config = new PerServerConfig();
  detail::pool_register_delete(p, server_config);
  server_config->module_config = new ModuleConfig();
  detail::pool_register_delete(p, server_config->module_config);
  return reinterpret_cast<void *>(server_config);
}
void *merge_svr_conf(apr_pool_t *p, void *basev, void *addv) {
  PerServerConfig *base = reinterpret_cast<PerServerConfig *>(basev);
  PerServerConfig *add = reinterpret_cast<PerServerConfig *>(addv);
  PerServerConfig *server_config = new PerServerConfig();
  detail::pool_register_delete(p, server_config);
  server_config->jump_extr_auth_url = add->jump_extr_auth_url.empty() ?
  base->jump_extr_auth_url : add->jump_extr_auth_url;
  std::merge(base->match_uri_regexs.begin(), base->match_uri_regexs.end(),
             add->match_uri_regexs.begin(),  add->match_uri_regexs.end(),
             std::back_inserter(server_config->match_uri_regexs));
  server_config->module_config = (add->module_config && add->module_config->acl) ? add->module_config : base->module_config;

  return reinterpret_cast<void *>(server_config);

}
} /* namespace mod_passauth */
