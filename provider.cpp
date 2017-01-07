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

static int check_time(request_rec *r, char *szbegintime, char *szendtime)
{
	apr_time_t time;
	time = apr_time_now();
	long long begintime;
	long long endtime;
    /*将微妙转换成秒，时间戳精确到秒就可以*/
    long long secondtime = time / 1000000;
	begintime = atoll(szbegintime);
	endtime = atoll(szendtime);
	//apr_status_t rv = apr_time_exp_lt(&ts, time);
	if (begintime > secondtime) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		             "PassAuth check_time faied: begin time  is %s", szbegintime);
		return 1;
	}
	if (endtime < secondtime) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
		             "PassAuth check_time faied: end time  is %s", szendtime);
		return 1;
	}
	
	return 0;	
}

bool App::isIpAllowed(int role_id, const char *ip) const {
  std::map<int, PerRoleACLRule>::const_iterator rule_itr = per_role_acl_rules_.find(role_id);
  if (rule_itr == per_role_acl_rules_.end()) {
    return false;
  }
  apr_pool_t *p = NULL;
  apr_status_t rv = apr_pool_create(&p, pool_);
  if (rv != APR_SUCCESS) {
    throw std::runtime_error("acl App ctor: create apr_pool failed");
  }
  BOOST_SCOPE_EXIT((p)) {
    apr_pool_destroy(p);
  }BOOST_SCOPE_EXIT_END

  apr_sockaddr_t *sa = NULL;
  rv = apr_sockaddr_info_get(&sa, ip, APR_INET, 0, 0, p);
  if (rv != APR_SUCCESS) {
    std::ostringstream oss;
    oss << "acl_localdb detail::App::isIpAllowed: apr_sockaddr_info_get() failed: ip=" << ip;
    throw std::runtime_error(oss.str());
  }
  bool allow = false;
  BOOST_FOREACH(apr_ipsubnet_t *ip_subnet, rule_itr->second.allow_ipsubnets) {
    allow = apr_ipsubnet_test(ip_subnet, sa);
    if (allow) {
      break;
    }
  }
  return allow;
}

bool App::isTimeAllowed(int role_id, apr_time_t time) const {
  std::map<int, PerRoleACLRule>::const_iterator rule_itr = per_role_acl_rules_.find(role_id);
  if (rule_itr == per_role_acl_rules_.end()) {
    return false;
  }
  apr_time_exp_t tm;
  apr_status_t rv = apr_time_exp_lt(&tm, time);
  if (rv != APR_SUCCESS) {
    std::ostringstream oss;
    oss << "acl_localdb detail::App::isTimeAllowed: apr_time_exp_t() failed: time=" << time;
    throw std::runtime_error(oss.str());
  }
  int allow_time_begin_hhmm = rule_itr->second.allow_time_begin_hhmm;
  int allow_time_end_hhmm = rule_itr->second.allow_time_end_hhmm;
  int hhmm = tm.tm_hour * 100 + tm.tm_min;
  if (allow_time_begin_hhmm <= allow_time_end_hhmm) {
    return (hhmm >= allow_time_begin_hhmm) && (hhmm <= allow_time_end_hhmm);
  } else {
    return (hhmm >= allow_time_begin_hhmm) || (hhmm <= allow_time_end_hhmm);
  }
}


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
  apps_indexd_by_fixed_ip::const_iterator apps_itr
    = apps_[protocol].get<0>().find(parsed_proxy_uri.hostname);
  if (apps_itr != apps_[protocol].get<0>().end()) {
    BOOST_FOREACH(const boost::shared_ptr<App>& this_app, apps_itr->second) {
      if (this_app->isUrlMatchRegex(url)) {
        app = this_app;
        break;
      }
    }
  }

  if (!app) {
    BOOST_FOREACH(const boost::shared_ptr<App>& this_app, apps_[protocol].get<1>()) {
      if (this_app->isUrlMatchRegex(url)) {
        app = this_app;
        break;
      }
    }
  }

  if (!app) {
    LOG(LOG_NOTICE, NULL, "url(%s) matches NO apps", url);
    return false;
  }

  char ctime_buf[APR_CTIME_LEN] = {0};
  apr_ctime(ctime_buf, time);
  BOOST_FOREACH(int role_id, user_roles) {
    if (app->allow_roles.find(role_id) != app->allow_roles.end()) {
      if (!app->isTimeAllowed(role_id, time)) {
        LOG(LOG_NOTICE, NULL, "access time(%s) check failed for role_id(%d)", ctime_buf, role_id);
        continue;
      }
      if (!app->isIpAllowed(role_id, user_ip)) {
        LOG(LOG_NOTICE, NULL, "source IP(%s) check failed for role_id(%d)", user_ip, role_id);
        continue;
      }
      return true;
    } else {
      LOG(LOG_NOTICE, NULL, "url(%s) matches app(%s), but role_id(%d) is NOT allowed", url, app->app_name.c_str(), role_id);
    }
  }
  LOG(LOG_NOTICE, NULL, "url(%s) matches app(%s) but failed in matching any ACL rules", url, app->app_name.c_str());
  return false;
}

} /* namespace detail */
} /* namespace mod_passauth */
