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

#include "../libncsnet/ncsnet/sys/types.h"
#include "nescadata.h"

/*
 * Each class for working with any service must have the
 * following functions,
 *
 * The main function that combines the others,
 *   void <SERVICE>SERVICE(....)
 *
 * To check if the service is available,
 *   bool check(...)
 */

class NCSFTPSERVICE
{
  protected:
  bool check(NESCATARGET *target, int port);

  public:
  void FTPSERVICE(std::map<NESCATARGET*,std::vector<int>> targets,
    NESCADATA *ncsdata);
};

class NCSHTTPSERVICE
{
  protected:
  bool check(NESCATARGET *target, int port);

  public:
  void HTTPSERVICE(std::map<NESCATARGET*,std::vector<int>> targets,
    NESCADATA *ncsdata);
};

class NESCASERVICES : public NCSHTTPSERVICE, public NCSFTPSERVICE
{
  std::map<NESCATARGET*, std::vector<int>>
    forprobe(int service, NESCADATA *ncsdata);
  public:
  NESCASERVICES(NESCADATA *ncsdata);
};

