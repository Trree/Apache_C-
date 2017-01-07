#include "mod_passauth/provider.hpp"

#include <algorithm>
#include <iterator>
#include <iostream>
#include <sstream>

#include <boost/foreach.hpp>
#include <boost/scope_exit.hpp>
#include <boost/make_shared.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

#include "apr_errno.h"
#include "apr_strings.h"
#include "apr_uri.h"

#include "mod_passauth/log.hpp"

namespace mod_passauth {
namespace detail {

bool AUTH::check_client_verify_mode(request_rec *r)
{
  SSLSrvConfigRec *sc = mySrvConfig(r->server);
  SSLConnRec *sslconn = myConnConfig(r->connection);
  if (sc->server->auth.verify_mode == SSL_CVERIFY_OPTIONAL && sslconn->ssl->session->peer == NULL){
    LOG(APLOG_DEBUG, r->server, "Verified client model is optional, and client cert is NULL.");
    return true;
  }
  else {
    return false;
  }
}

std::string get_token(request_rec *r, const char *key, int flag)
{
  const char *info;
  const char *start_str;
  char seq;
  switch(flag){
    case COOKIE_SEQ:
      info = r->unparsed_uri;
      seq = '&';
      break;
    case URL_SEQ:
      info = apr_table_get(r->headers_in, "Cookie");
      seq = ';';
      break;
    case REFERER_SEQ:
      info = apr_table_get(r->headers_in, "Referer");
      seq = '&';
      break;
    default:
      info = NULL;
      break;
  }

  if (info) {
    if ((start_str = ap_strstr_c(info, key))) {
      char *token, *end_str;
      start_str += strlen(key) + 1;
      token = apr_pstrdup(r->pool, start_str);
      end_str = strchr(token, seq);
      if (end_str) {
        *end_str = '\0';
      }
      return token;
    }
  }
  return NULL;
}

std::tuple<std::string, std::string> AUTH::get_token_from_req(request_rec *r)
{
    std::string usertoken;
    std::string pwdtoken;
    std::string cookiepwdtoken;
    std::string cookieusertoken;
    std::string refererusertoken;
    std::string refererpwdtoken;
    const char *pwdkey = "password-session-id";
    const char *userkey = "username";
    auto bind_get_token(get_token, _1, _2);
    pwdtoken = bind_get_token(pwdkey, URL_SEQ);
    usertoken = bind_get_token(userkey, URL_SEQ);
    cookiepwdtoken = bind_get_token(pwdkey, COOKIE_SEQ);
    cookieusertoken = bind_get_token(userkey, COOKIE_SEQ);
    refererpwdtoken = bind_get_token(pwdkey, REFERER_SEQ);
    refererusertoken = bind_get_token(userkey, REFERER_SEQ);

    if (usertoken) {
        ;
    }
    else if (cookieusertoken) {
        usertoken = cookieusertoken;
    }
    else if (refererusertoken) {
        usertoken = refererusertoken;
    }
    if (pwdtoken) {
        ;
    }
    else if (cookiepwdtoken) {
        pwdtoken = cookiepwdtoken;
    }
    else if (refererpwdtoken) {
        pwdtoken = refererpwdtoken;
    }
    return std::make_tuple(usertoken, pwdtoken);

}

bool AUTH::jump_auth_url(request_rec *r)
{
    const char *custom_response = dconf->url;
    const char *custom_port = r->parsed_uri.port_str;
    r->status = HTTP_MOVED_TEMPORARILY;
    const char *ori_hostname = r->hostname;
    char *ori_uri = r->unparsed_uri;
    char *new_uri = apr_pstrcat(r->pool, custom_response, "/?redir=", ori_hostname, ":", custom_port, ori_uri, NULL);
    KLSSL_log( r->server, APLOG_DEBUG, "mod_passauth: redirect uri is %s",  new_uri);
    apr_table_setn(r->headers_out, "Location", new_uri);
    ap_send_error_response(r, 0);

    return OK;
}


