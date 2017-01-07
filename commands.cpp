#include "mod_passauth/commands.hpp"

#include <boost/lexical_cast.hpp>
#include <boost/make_shared.hpp>

#include "apr_pools.h"
#include "apr_strings.h"

#include "mod_passauth/config.hpp"
#include "mod_passauth/log.hpp"

namespace mod_passauth {
namespace {

const char *cmd_authengine(cmd_parms *, void *mconfig, int flag) {
  PerDirectoryConfig *directory_config = reinterpret_cast<PerDirectoryConfig *>(mconfig);
  directory_config->authenable = flag;
  return NULL;
}

char *wildcards2regex(apr_pool_t *pool, const char *wildcards_exp, char *regex_exp) {
  const char *src = NULL;
  char *dst = NULL;

  if (NULL == regex_exp) {
    int n = 3;        /*    正则表达式字符串长度，包含了开头的^，结尾的$和字符串结束的0    */
    src = wildcards_exp;
    while (*src) {
      switch (*src) {
        case '*':
          n += 2;    /*    通配符表达式中的 * 会被转换为正则表达式 .*    */
          break;
        case '?':
          n += 1;    /*    通配符表达式中的 ? 会被转换为正则表达式 .    */
          break;
        case '[':
        case ']':
        case '(':
        case ')':
        case '\\':
        case '+':
        case '-':
        case '.':
        case '^':
        case '$':
          n += 2;    /*    通配符表达式中的其他特殊字符会被转换为正则表达式的转义形式——前面加上\    */
          break;
        default:
          n += 1;
          break;
      }
      src++;
    }
    regex_exp = reinterpret_cast<char *>(apr_palloc(pool, n + 2));
  }

  dst = regex_exp;
  *dst++ = '^';

  src = wildcards_exp;
  while (*src) {
    switch (*src) {
      case '*':
        *dst++ = '.';    /*    通配符表达式中的 * 会被转换为正则表达式 .*    */
        *dst++ = '*';    /*    通配符表达式中的 * 会被转换为正则表达式 .*    */
        break;
      case '?':
        *dst++ = '.';    /*    通配符表达式中的 ? 会被转换为正则表达式 .    */
        break;
      case '[':
      case ']':
      case '(':
      case ')':
      case '\\':
      case '+':
      case '-':
      case '.':
      case '^':
      case '$':
        *dst++ = '\\';    /*    通配符表达式中的其他特殊字符会被转换为正则表达式的转义形式——前面加上\    */
        *dst++ = *src;
        break;
      default:
        *dst++ = *src;    /*    其他字符直接复制    */
        break;
    }
    src++;
  }

  *dst++ = '$';
  *dst = 0;

  return regex_exp;
}

const char *add_auth_address(cmd_parms *, void * /*mconfig*/, const char *url) {
  if (!ap_is_url(url)) {
    return "外部认证不是合法的url."
  }

  PerServerConfig *server_config = get_per_server_config(params->server);
  server_config->jump_extr_auth_url = url;

  return NULL;
}

const char *cmd_acl_localdb_uri_regex(cmd_parms *params, void *mconfig, const char *regex_format) {
  PerServerConfig *server_config = get_per_server_config(params->server);
  try {
    server_config->match_uri_regexs.push_back(boost::make_shared<detail::PCREPosixRegex>(regex_format));
  } catch (const std::exception& e) {
    LOG(LOG_WARNING, NULL, "Parse ACLLocalDBUriPattern %s failed %s", regex_format, e.what());
    return apr_psprintf(params->pool, "Parse ACLLocalDBUriPattern %s failed %s", regex_format, e.what());
  }
  return NULL;
}

const char *add_auth_filter(cmd_parms *params, void * /*mconfig*/, const char *pattern) {
  const char *regex_format = NULL;
  regex_format = wildcards2regex(params->pool, pattern, NULL);
  if (regex_format == NULL) {
    return apr_psprintf(params->pool, "ACLLocalDBUriPattern: wildcards2regex(%s) returns NULL", pattern);
  }
  return cmd_acl_localdb_uri_regex(params, NULL, regex_format);
}

const char *cmd_acl_localdb_param(cmd_parms *params, void * /*mconfig*/, const char *key, const char *value) {
  const char *err = NULL;
  if ((err = ap_check_cmd_context(params, GLOBAL_ONLY))) {
    return err;
  }

  ModuleConfig *module_config = get_module_config(params->server);

  if (strcasecmp(key, "SQLITE_JOURNAL_MODE") == 0) {
    module_config->user_db_config.sqlite_journal_mode = apr_pstrcat(params->pool, SQL_SQLITE_PRAGMA_JOURNAL_MODE, value, ";", NULL);
    module_config->apps_db_config.sqlite_journal_mode = apr_pstrcat(params->pool, SQL_SQLITE_PRAGMA_JOURNAL_MODE, value, ";", NULL);
  } else if (strcasecmp(key, "SQLITE_BUSY_TIMEOUT_MS") == 0) {
    module_config->user_db_config.sqlite_busy_timeout_ms = boost::lexical_cast<int>(value);
    module_config->apps_db_config.sqlite_busy_timeout_ms = boost::lexical_cast<int>(value);
  } else if (strcasecmp(key, "USER_DB_PATH") == 0) {
    module_config->user_db_config.db_path = ap_server_root_relative(params->pool, value);
  } else if (strcasecmp(key, "APPS_DB_PATH") == 0) {
    module_config->apps_db_config.db_path = ap_server_root_relative(params->pool, value);
  } else {
    return apr_pstrcat(params->pool, "Unkown localdb param key:", key, NULL);
  }
  return NULL;
}

} /* namespace */

#if defined(AP_HAVE_DESIGNATED_INITIALIZER)
#error "AP_HAVE_DESIGNATED_INITIALIZER must NOT be defined. Set 'NOTEST_CPPFLAGS = ' in Makefile "
#endif

/*
 * The reinterpret_cast is there because Apache's AP_INIT_TAKE1 macro needs to
 * take an old-style C function type with unspecified arguments.  The
 * static_cast, then, is just to enforce that we pass the correct type of
 * function -- it will give a compile-time error if we pass a function with the
 * wrong signature.
 */

#define CPP_AP_INIT_NO_ARGS(directive, func, mconfig, where, help) {                                 \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(static_cast<const char*(*)(cmd_parms*,void*)>(func)),                   \
  mconfig, where, RAW_ARGS, help }

#define CPP_AP_INIT_RAW_ARGS(directive, func, mconfig, where, help) {                                \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*)>(func)),                           \
  mconfig, where, RAW_ARGS, help }

#define CPP_AP_INIT_TAKE1(directive, func, mconfig, where, help) {                                   \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*)>(func)),                           \
  mconfig, where, TAKE1, help }

#define CPP_AP_INIT_ITERATE(directive, func, mconfig, where, help) {                                 \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*)>(func)),                           \
  mconfig, where, ITERATE, help }

#define CPP_AP_INIT_TAKE2(directive, func, mconfig, where, help) {                                   \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*)>(func)),               \
  mconfig, where, TAKE2, help }

#define CPP_AP_INIT_TAKE12(directive, func, mconfig, where, help) {                                  \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*)>(func)),               \
  mconfig, where, TAKE12, help }

#define CPP_AP_INIT_ITERATE2(directive, func, mconfig, where, help) {                                \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*)>(func)),               \
  mconfig, where, ITERATE2, help }

#define CPP_AP_INIT_TAKE13(directive, func, mconfig, where, help) {                                  \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*,const char*)>(func)),   \
  mconfig, where, TAKE13, help }

#define CPP_AP_INIT_TAKE23(directive, func, mconfig, where, help) {                                  \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*,const char*)>(func)),   \
  mconfig, where, TAKE23, help }

#define CPP_AP_INIT_TAKE123(directive, func, mconfig, where, help) {                                 \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*,const char*)>(func)),   \
  mconfig, where, TAKE123, help }

#define CPP_AP_INIT_TAKE3(directive, func, mconfig, where, help) {                                   \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,const char*,const char*,const char*)>(func)),   \
  mconfig, where, TAKE3, help }

#define CPP_AP_INIT_FLAG(directive, func, mconfig, where, help) {                                    \
  directive,                                                                                         \
  reinterpret_cast<cmd_func>(                                                                        \
         static_cast<const char*(*)(cmd_parms*,void*,int)>(func)),                                   \
  mconfig, where, FLAG, help }

#define CPP_AP_END_CMDS {NULL, NULL, NULL, 0, RAW_ARGS, NULL}

const command_rec directives[] = {
  CPP_AP_INIT_FLAG( "AuthEngine",   cmd_authengine,  NULL, OR_FILEINFO, "On or Off to enable or disable (default) the whole passauth engine"),
  CPP_AP_INIT_TAKE1( "AuthAddress",   add_auth_address,  NULL, RSRC_CONF, "外部用户认证的页面"),
  AP_INIT_TAKE1("AuthFilter", add_auth_filter, NULL, RSRC_CONF, "过滤请求"),
  CPP_AP_INIT_TAKE2("ACLLocalDBParam", cmd_acl_localdb_param, NULL, RSRC_CONF, "set acl_localdb database params"),
  CPP_AP_END_CMDS
};

} /* namespace mod_passauth */

