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
bool PassAuth::isStateAllowed(int state) const {
  if (!state) {
    return false;
  }
  return true;
}

bool PassAuth::isSessionAllowd(std::string sessionid, std::string pwdtoken) const {
  if (pwdtoken.compare(sessionid)) {
    return false;
  }
  return true;
}

bool PassAuth::isTimeAllowed(std::string szbegintime, std::string szendtime, apr_time_t time) const {
	long long allow_time_begin;
	long long allow_time_end;
  /*将微妙转换成秒，时间戳精确到秒就可以*/
  long long timestamp = time / 1000000;
  allow_time_begin = std::stoll(szbegintime);
  allow_time_end = std::stoll(szendtime);
  if (allow_time_begin <= allow_time_end) {
    return (timestamp >= allow_time_begin) && (timestamp <= allow_time_end);
  } else {
    return (timestamp >= allow_time_begin) || (timestamp <= allow_time_end);
  }
}
bool PassAuth::binduserinfo(std::string useremail, std::string usercn) const {
  apr_table_set(r->notes, "KOAL_CERT_E", tPassAuth.szUserEmail);
  apr_table_set(r->notes, "KOAL_CERT_CN", tPassAuth.szUserCN);
  return true;
}

} /* namespace detail */
} /* namespace mod_passauth */

void AUTHRulesProvider::load(std::string usertoken) {
  const DBConfig& config = db_reloader_.config();
  SQLite::Database db(config.db_path, SQLite::OPEN_READONLY, config.sqlite_busy_timeout_ms);
  db.setBusyTimeout(config.sqlite_busy_timeout_ms);
  db.exec(config.sqlite_journal_mode);
  return loadAppsFromDB(db, usertoken);
}

void AUTHRulesProvider::loadAuthsFromDB(SQLite::Database& db, std::string usertoken) {
  SQLite::Statement query(db, "select UserEmail, UserCN, AllowTimeBegin, AllowTimeEnd, PasswdSessionId, UserState from UserAuth where Username = ?");
  query.bind(1, usertoken);
  while (query.executeStep()) {
    boost::shared_ptr<PassAuth> passauth = boost::make_shared<PassAuth>();

    const std::string useremail = query.getColumn(0);
    const std::string usercn = query.getColumn(1);
    const std::string allowtimebegin = query.getColumn(2);
    const std::string allowtimeend = query.getColumn(3);
    const std::string pwdsessionid = query.getColumn(4);
    int state = query.getColumn(5);
    passauth->state = state;
    passauth->useremail = useremail;
    passauth->usercn = usercn;
    passauth->allowtimebegin = allowtimebegin;
    passauth->allowtimeend = allowtimeend;
    passauth->pwdsessionid = pwdsessionid;

    auths_indexd_by_user_token.insert(usertoken, passauth);
  }
}

bool AUTHRulesProvider::isAllowedToAccessAuth(apr_time_t time, std::string usertoken, std::string pwdtoken) const {
  apr_pool_t *p = NULL;
  apr_status_t rv = apr_pool_create(&p, NULL);
  if (rv != APR_SUCCESS) {
    throw std::runtime_error("ACLRulesProvider::isAllowedToAccessApp: create apr_pool failed");
  }
  BOOST_SCOPE_EXIT((p)) {
    apr_pool_destroy(p);
  }BOOST_SCOPE_EXIT_END

  apr_uri_t parsed_proxy_uri;
  apr_uri_parse(p, url, &parsed_proxy_uri);


  boost::shared_ptr<PassAuth> passauth;
  auto auth_search = auths_indexd_by_user_token.find(usertoken);
  BOOST_FOREACH(const boost::shared_ptr<PassAuth>& this_passauth, auth_search->second) {
    passauth = this_passauth;
  }

  if (!passauth) {
    LOG(LOG_NOTICE, NULL, "user (%s) matches NO passauths", usertoken);
    return false;
  }
  if (!passauth->isStateAllowed(passauth->state)) {
    LOG(LOG_NOTICE, NULL, "access state(%d) check failed for user(%s)", passauth->state, usertoken);
    return false;
  }
  if (!passauth->isSessionAllowd(passauth->pwdsessionid, pwdtoken)) {
    LOG(LOG_NOTICE, NULL, "session tocken(%s) check failed for user(%s)", pwdtoken, usertoken);
    return false;
  }
  char ctime_buf[APR_CTIME_LEN] = {0};
  apr_ctime(ctime_buf, time);
  if (!passauth->isTimeAllowed(passauth->allowtimebegin, passauth->allowtimeend, time)) {
    LOG(LOG_NOTICE, NULL, "access time(%s) check failed for user(%s)", ctime_buf, usertoken);
    return false;
  }
  if (!passauth->binduserinfo(passauth->useremail, passauth->usercn)){
    LOG(LOG_NOTICE, NULL, "bind info failed for user(%s)", ctime_buf, usertoken);
    return false;
  }
  return true;
}

} /* namespace detail */
} /* namespace mod_passauth */
