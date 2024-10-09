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

#include "include/nescadata.h"
#include "include/nescabrute.h"
#include "include/nescaprint.h"
#include "include/nescaengine.h"
#include <cstdio>
#include <sys/select.h>

NESCAPRINT  ncsprint;
NESCABRUTE  ncsbrute;
NESCADATA   ncsdata;
static int  nesca4(void);

/*
 * nesca4.cc
 */
int main(int argc, char **argv)
{
  if (argc<=1)
    ncsprint.usage(argc, argv);

  ncsprint.run();
  ncsdata.opts.opts_init();
  ncsdata.opts.cfg_apply("config/default.cfg", &ncsdata, &ncsprint);
  ncsdata.opts.args_apply(argc, argv, &ncsdata, &ncsprint);
  if (ncsdata.opts.check_cfg_flag()) {
    ncsdata.opts.cfg_apply(ncsdata.opts.get_cfg_param(), &ncsdata, &ncsprint);
    /* reapply */
    ncsdata.opts.args_apply(argc, argv, &ncsdata, &ncsprint);
  }
  ncsdata.dev.init(&ncsprint, &ncsdata.opts);
  ncsdata.rawtargets.load(argc, argv, &ncsdata.opts, &ncsprint, &ncsdata.dev);

  return nesca4();
}

int nesca4(void)
{
  size_t grouplen, group, groupplus, groupmax;
  std::vector<std::string> realgroup;
  u128 i=0, total=0;

  groupplus=ncsdata.opts.get_gplus_param();
  group=ncsdata.opts.get_gmin_param();
  groupmax=ncsdata.opts.get_gmax_param();

  ncsdata.rawtargets.load_from_file(group);
  ncsdata.rawtargets.load_random_ips(group);
  total=ncsdata.rawtargets.totlen();

  gettimeofday(&ncsdata.tstamp_s, NULL);
  while (i<total) {
    grouplen=std::min<size_t>(group, total-i);
    grouplen=std::min<size_t>(grouplen, groupmax);

    if (ncsdata.opts.check_stats_flag())
      ncsprint.nescastats(grouplen, total, i);

    realgroup=ncsdata.rawtargets.unload(grouplen);
    for (const auto&t:realgroup)
      ncsdata.add_target(t);

    if (!ncsdata.opts.check_n_ping_flag())
      _NESCAENGINE_ ping(&ncsdata, 1);
    if (!ncsdata.opts.check_n_flag())
      _NESCARESOLV_(ncsdata.targets, &ncsdata);
    if (!ncsdata.opts.check_sn_flag())
      _NESCAENGINE_ scan(&ncsdata, 0);

    for (auto t:ncsdata.targets)
      if (t->isok())
        ncsdata.ok++;
    for (auto t:ncsdata.targets) {
      ncsprint.nescatarget(t, 1);
      if (t->openports())
        putchar('\n');
      ncsdata.tmplast=(t->openports())?0:1;
    }

    i+=grouplen;
    group+=groupplus;
    ncsdata.rawtargets.load_from_file(group);
    ncsdata.rawtargets.load_random_ips(group);
    total=ncsdata.rawtargets.totlen();
    ncsdata.clear_targets();
  }
  gettimeofday(&ncsdata.tstamp_e, NULL);

  ncsprint.finish(&ncsdata);
  return 0;
}
