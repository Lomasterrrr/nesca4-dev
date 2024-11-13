/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "include/nescaservices.h"

#include "include/nescadata.h"
#include "include/nescaengine.h"
#include "libncsnet/ncsnet/socket.h"
#include "libncsnet/ncsnet/http.h"
#include "libncsnet/ncsnet/ftp.h"
#include "libncsnet/ncsnet/utils.h"
#include <bits/types/struct_timeval.h>
#include <cstdio>
#include <map>
#include <sys/select.h>
#include <vector>
#include <string.h>

static std::string clearbuf(const std::string& input)
{
  std::string result;
  result.reserve(input.size());

  for (char ch:input) {
    if (ch=='\t'||ch=='\n')
      result+=' ';
    else if (ch!='\r'&&ch!='\a')
      result+=ch;
  }

  return result;
}

static void filtertargets(std::map<NESCATARGET*, std::vector<int>>& targets,
  const std::function<bool(NESCATARGET*, int)>& check)
{
  bool s;
  for (auto it=targets.begin();it!=targets.end();) {
    s=0;
    for (const auto&p:it->second) {
      if (!check(it->first, p)) {
        s=1;
        break;
      }
    }
    if (s) it=targets.erase(it);
    else ++it;
  }
}

bool NCSFTPSERVICE::check(NESCATARGET *target, int port)
{
  struct timeval s, e;
  u8 receive[BUFSIZ];
  std::string tmp;
  size_t pos;
  bool res=0;
  int ret;

  gettimeofday(&s, NULL);
  ret=sock_session(target->get_mainip().c_str(), port,
    to_ms(1000), receive, sizeof(receive));
  gettimeofday(&e, NULL);
  if (ret<0)
    return res;
  tmp=std::string((char*)receive);
  tmp=clearbuf(tmp);
  res=1;

  for (pos=0;pos<target->get_num_port();pos++)
    if (target->get_port(pos).port==port)
      break;

  /*
   * ftp header
   * 220---------- Welcome to Pure-FTPd 1.0.52 [privsep] [TLS] ----------
   */
  if (tmp.length()>0) {
    target->add_service(target->get_real_port(pos), S_FTP, s, e);
    target->add_info_service(target->get_real_port(pos),
        S_FTP, tmp, "header");
  }

  return res;
}

void NCSFTPSERVICE::FTPSERVICE(std::map<NESCATARGET*,std::vector<int>> targets,
  NESCADATA *ncsdata)
{
  filtertargets(targets, [this](NESCATARGET* target, int port) {
    return this->check(target, port);
  });
  /* bruteforce XXX */
}


/*
 * From old nesca4
 */
#define HTTP_BUFLEN 65535
static void prepare_redirect(const char* redirect, char* reshost, char* respath, ssize_t buflen)
{
  const char *ptr, *hostend;
  char *newurl=NULL;
  bool aee=false;
  int len=0;

  if (IS_NULL_OR_EMPTY(redirect))
    redirect="/";

  if (redirect[0]=='.')
    ++redirect;

  for (ptr=redirect;*ptr!='\0';++ptr){
    if (*ptr=='/') {
      ++len;
      if (len==4) {
        if (*(ptr+1)!='\0')
          aee=true;
        break;
      }
    }
  }
  if (aee) {
    ptr=strstr(redirect, "://");
    if (ptr) {
      ptr+=3;
      hostend=strchr(ptr, '/');
      if (!hostend)
        hostend=ptr+strlen(ptr);
      strncpy(reshost, ptr, hostend-ptr);
      reshost[hostend-ptr]='\0';
      ptr=hostend;
      if (ptr)
        memmove((void*)redirect, ptr, strlen(ptr)+1);
      else
        redirect = "/";
    }
    snprintf(respath, buflen, "%s", redirect);
  }
  else {
    if (find_word(redirect, "http://")==0||find_word(redirect, "https://")==0) {
      newurl=clean_url(redirect);
      if (newurl) {
        strncpy(reshost, newurl, buflen-1);
        reshost[buflen-1]='\0';
      }
      strncpy(respath, "/",  buflen-1);
      respath[buflen-1]='\0';
    }
    else
      if (redirect[0]!='/')
        snprintf(respath, HTTP_BUFLEN, "/%s", redirect);
  }
  if (newurl)
    free(newurl);
}

void send_http(struct http_request *r, NESCADATA *ncsdata, NESCATARGET *target,
    const u16 port, long long timeout)
{
  struct http_response  response;
  u8                    resbuf[HTTP_BUFLEN];
  char                  redirect[HTTP_BUFLEN];
  u8                    newbuf[HTTP_BUFLEN];
  char                  respath[HTTP_BUFLEN];
  char                  reshost[HTTP_BUFLEN];
  std::string           res, dns;
  struct timeval        s, e;
  size_t                pos;

  pos=0;
  dns=ncsdata->rawtargets.getdns(target->get_mainip());
  if (!dns.empty())
    http_add_hdr(r, "Host", dns.c_str());
  else
    http_add_hdr(r, "Host", (target->get_mainip().c_str()));

  gettimeofday(&s, NULL);
  http_qprc_pkt(target->get_mainip().c_str(), port, timeout, r, &response, resbuf, HTTP_BUFLEN);
  res=(char*)resbuf;

  target->add_service(target->get_real_port(pos), S_HTTP, s, e);

  http_qprc_redirect(response.hdr, resbuf, redirect, HTTP_BUFLEN);
  if (!std::string(redirect).empty()) {

    for (pos=0;pos<target->get_num_port();pos++)
      if (target->get_port(pos).port==port)
        break;
    gettimeofday(&e, NULL);
    target->add_info_service(target->get_real_port(pos),
        S_HTTP, (char*)redirect, "redirect");

    prepare_redirect(redirect, reshost, respath, HTTP_BUFLEN);
    http_update_uri(&r->uri, "", "", 0, respath);
    http_modify_hdr(r, "Host", reshost);
    http_qprc_pkt(target->get_mainip().c_str(), port, timeout, r, &response, newbuf, HTTP_BUFLEN);
    res=std::string((char*)newbuf);
  }
  if (!res.empty()) {
    res=clearbuf(res);
    target->add_info_service(target->get_real_port(pos),
        S_HTTP, res, "html");
  }
}

bool NCSHTTPSERVICE::check(NESCATARGET *target, int port)
{
  return 1;
}

void NCSHTTPSERVICE::HTTPSERVICE(std::map<NESCATARGET*,std::vector<int>> targets,
  NESCADATA *ncsdata)
{
  struct http_request r;

  filtertargets(targets, [this](NESCATARGET* target, int port) {
    return this->check(target, port);
  });

  http_init_req(&r, "GET", "", "", 0, "/", 0, 0);
  http_add_hdr(&r, "User-Agent", "oldteam");
  http_add_hdr(&r, "Connection", "close");

  for (const auto &t:targets)
    for (const auto&p:t.second)
      send_http(&r, ncsdata, t.first, p, to_ns(1000));
}

std::map<NESCATARGET*, std::vector<int>>
NESCASERVICES::forprobe(int service, NESCADATA *ncsdata)
{
  std::map<NESCATARGET*, std::vector<int>> res;
  std::vector<int> ports;
  bool yes;
  size_t i;

  for (const auto &t:ncsdata->targets) {
    for (i=yes=0;i<t->get_num_port();i++) {
      for (const auto&p:ncsdata->opts.get_s_param()) {
        if (t->get_port(i).port==p.port&&
          t->get_port(i).state==PORT_OPEN&&
          p.proto==service) {
          ports.push_back(t->get_port(i).port);
          yes=1;
        }
      }
    }
    if (yes) {
      res[t]=ports;
      ports.clear();
    }
  }

  return res;
}

NESCASERVICES::NESCASERVICES(NESCADATA *ncsdata)
{
  std::map<NESCATARGET*, std::vector<int>> res;
  size_t i;

  for (i=0;i<S_NUM;i++) {
    res=forprobe(i, ncsdata);
    switch (i) {
      case S_FTP: FTPSERVICE(res, ncsdata); break;
      case S_HTTP: HTTPSERVICE(res, ncsdata); break;
    }
  }

}



