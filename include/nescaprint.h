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

#pragma once
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdlib>
#include <iostream>

#include "../libncsnet/ncsnet/sys/types.h"
#include "../libncsnet/ncsnet/utils.h"
#include "../nesca-config.h"

class NESCATARGET;
class NESCADATA;
struct NESCAPORT;
class NESCADEVICE;

u8 strmethod(int m);

class NESCAPRINT
{
  std::string is_service(NESCAPORT *port);
  std::string portblock(NESCAPORT *port, bool onlyok);

  public:
  void run(void);
  void usage(int argc, char **argv);
  void error(const std::string &err);
  void warning(const std::string &warn);
  void finish(NESCADATA *ncsdata);

  void nescatarget(NESCATARGET *target, bool onlyok);
  void nescadevice(NESCADEVICE *device);
  void nescastats(size_t grouplen, __uint128_t total, __uint128_t i);
  void PRINTTARGETS(NESCADATA *ncsdata);
};

class NESCAHTML
{

public:
  void nh_init(void);
  void nh_updt(NESCADATA *ncsdata);
};
