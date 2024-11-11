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
#include <cstdio>
#include <vector>

bool NCSFTPSERVICE::check(NESCATARGET *target, int port)
{
  u8 receive[BUFSIZ];
  bool res=0;
  int ret;

  ret=sock_session(target->get_mainip().c_str(), port,
    to_ms(1000), receive, sizeof(receive));
  if (ret<0)
    return res;
  remove_specials((char*)receive);
  res=1;
  std::cout << receive << std::endl;

  return res;
}

void NCSFTPSERVICE::FTPSERVICE(std::map<NESCATARGET*,std::vector<int>> targets,
  NESCADATA *ncsdata)
{
  for (const auto &t:targets) {
    for (const auto&p:t.second) {
      check(t.first, p);
    }
  }
  /*
  for (const auto&t:targets) {
    if (!check(t.second, t.second->get_port(t.first)))
      continue;
  }
  */
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
  res=forprobe(S_FTP, ncsdata);

  FTPSERVICE(res, ncsdata);

}



