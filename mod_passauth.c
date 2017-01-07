
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

static const char *KLSSL_parse_AuthSqlite(request_rec *r, const char *username, char *keytoken)
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int rv = SQLITE_OK;
    char *pszSQL = NULL;
    char *errmsg;
    const char *pszAuthDB = NULL;
    const char *pwdsessionid = NULL;
    X509 *x = NULL;
    BIO *bp= NULL;
    const unsigned char *certstr = NULL;
    SSLConnRec *sslconn = myConnConfig(r->connection);
    int flag = 0;


    if (NULL == username) {
        return "KLSSL_parse_PassAuthFile: the username is NULL";
    }
    
    struct {
        int state;
        char szSessionId[128];
        char szUserEmail[128];
        char szUserCN[128];
        char szAllowTimeBgine[128];
        char szAllowTimeEnd[128];
    }tPassAuth;

    pszAuthDB = "/kssl/WEBUI/cfg/UserPasswd.db";
    rv = sqlite3_open_v2(pszAuthDB, &db, SQLITE_OPEN_READONLY, NULL);
    //rv = sqlite3_open(pszAuthDB, &db);
    if( rv != SQLITE_OK ) {
        KLSSL_log( r->server, APLOG_ERR, "KLSSL_parse_PassAuthFile: Open UserPasswd db failed %s",  sqlite3_errmsg(db));
        return "Open ClientPolicy config db failed";
    }
    
    pszSQL = "select UserEmail, AllowTimeBegin, AllowTimeEnd, PasswdSessionId, UserState, UserCN from UserAuth where Username = ?";
    rv = sqlite3_prepare_v2(db, pszSQL, strlen(pszSQL), &stmt, NULL);
    if( rv != SQLITE_OK ) {
        sqlite3_close(db);
        KLSSL_log( r->server, APLOG_ERR, "KLSSL_parse_UserPasswdFile: sqlite3_prepare error %s",  sqlite3_errmsg(db));
        return "KLSSL_parse_UserPasswdFile: table UserAuth, sqlite3_prepare error";
    }
    rv = sqlite3_bind_text(stmt, 1, username, strlen(username), SQLITE_TRANSIENT);
    if( rv != SQLITE_OK ) {
        sqlite3_close(db);
        KLSSL_log( r->server, APLOG_ERR, "KLSSL_parse_UserPasswdFile: sqlite3_bind_text error %s",  sqlite3_errmsg(db));
        return "KLSSL_parse_UserPasswdFile: table UserAuth, sqlite3_bind_text error";
    }
    
    while (1) {
        memset(&tPassAuth, 0, sizeof(tPassAuth));

        rv = sqlite3_step(stmt);
        if( rv != SQLITE_ROW )
            break;      
        strcpy((char*)tPassAuth.szUserEmail, sqlite3_column_text(stmt, 0));
        strcpy((char*)tPassAuth.szAllowTimeBgine, sqlite3_column_text(stmt, 1));
        strcpy((char*)tPassAuth.szAllowTimeEnd, sqlite3_column_text(stmt, 2));
		strcpy((char*)tPassAuth.szSessionId, sqlite3_column_text(stmt, 3));
        tPassAuth.state  = (int)sqlite3_column_int(stmt, 4);
		strcpy((char*)tPassAuth.szUserCN, sqlite3_column_text(stmt, 5));

        if (tPassAuth.state == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "PassAuth 用户状态关闭");
            flag = 1;
        }

        if (tPassAuth.szSessionId[0] != '\0' && flag != 1) {
            if (strcmp(keytoken, tPassAuth.szSessionId) != 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server, "PassAuth check_session faied");
                flag = 1;
            }
        } 
		
		if (tPassAuth.szAllowTimeBgine[0] != '\0' && tPassAuth.szAllowTimeEnd[0] != '\0' && flag != 1) {
			flag = check_time(r, tPassAuth.szAllowTimeBgine, tPassAuth.szAllowTimeEnd);
		}

        if (tPassAuth.szUserEmail[0] != '\0' && tPassAuth.szUserCN[0] != '\0' && flag != 1) {
            apr_table_set(r->notes, "KOAL_CERT_E", tPassAuth.szUserEmail);
            apr_table_set(r->notes, "KOAL_CERT_CN", tPassAuth.szUserCN);
        }
    }

    if( (rv != SQLITE_OK) && (rv != SQLITE_DONE) ) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return "KLSSL_parse_PassAuthFile: table UserPasswd, sqlite3_step error";
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if(flag) {
        return "the sessionid or time not match";
    }
   
    return NULL;
}

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
