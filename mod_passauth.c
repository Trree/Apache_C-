
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "mod_ssl.h"
#include "openssl/x509.h"
#include "openssl/bio.h"
#include <string.h>
#include <stdlib.h>
#include "pcreposix.h"


#define COOKIE_SEQ 1
#define URL_SEQ    2
#define REFERER_SEQ 3

module AP_MODULE_DECLARE_DATA passauth_module;


/*
 * 过滤请求
 */

static int check_request(request_rec *r, passauth_dir_conf *dconf)
{
    regex_t *regexp;
    const char *filterreg = dconf->reg;
    regexp = ap_pregcomp(r->pool, filterreg, REG_EXTENDED | REG_NOSUB);
    if (regexp == NULL) {
        KLSSL_log( r->server, APLOG_DEBUG, "mod_passauth: auth filter  is failed  %s",  filterreg);
        return 1;
    }

    if (ap_regexec(regexp, r->unparsed_uri, 0, NULL, 0)) {
        return 1;
    }else {
        KLSSL_log( r->server, APLOG_DEBUG, "mod_passauth: auth filter matched   %s",  r->unparsed_uri);
        return 0;
    }
}

static int passauth_post_read_request(request_rec *r)
{

    //第一次请求中不带任何的token的
    if ((usertoken != NULL && usertoken != ""  && pwdtoken != NULL)) {
        if ((errmsg = KLSSL_parse_AuthSqlite(r, usertoken, pwdtoken)) != NULL) {
            KLSSL_log( r->server, APLOG_ERR, "KLSSL_parse_UserPasswdFile:  error %s",  errmsg);
            ap_die(HTTP_FORBIDDEN, r);
        }
    }
    else {
    }
    return OK;
}
