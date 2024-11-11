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

#include "include/nescaprint.h"

#include "include/nescadata.h"
#include "include/nescaengine.h"
#include "libncsnet/ncsnet/ip4addr.h"
#include "libncsnet/ncsnet/ip6addr.h"
#include "libncsnet/ncsnet/mac.h"
#include "libncsnet/ncsnet/ncsnet.h"
#include <cstdio>

u8 strmethod(int m)
{
  switch (m) {
    case M_ICMP_PING_ECHO: return 'e';
    case M_ICMP_PING_INFO: return 'i';
    case M_ICMP_PING_TIME: return 't';
    case M_TCP_PING_SYN: return 's';
    case M_TCP_PING_ACK: return 'a';
    case M_TCP_SYN_SCAN: return 'S';
    case M_TCP_XMAS_SCAN: return 'x';
    case M_TCP_FIN_SCAN: return 'f';
    case M_TCP_NULL_SCAN: return 'n';
    case M_TCP_ACK_SCAN: return 'A';
    case M_TCP_WINDOW_SCAN: return 'w';
    case M_TCP_MAIMON_SCAN: return 'm';
    case M_TCP_PSH_SCAN: return 'p';
    case M_SCTP_INIT_SCAN: return 'I';
    case M_SCTP_COOKIE_SCAN: return 'C';
    case M_SCTP_INIT_PING: return 'N';
    case M_UDP_PING: return 'u';
    case M_UDP_SCAN: return 'U';
    case M_ARP_PING: return 'r';
  }
  return '?';
}

#define DEFAULT_SERVICES_PATH "resources/nesca-services"

std::string NESCAPRINT::is_service(NESCAPORT *port)
{
  std::string line, name, portproto, fproto;
  size_t sp, fport;

  std::ifstream f(DEFAULT_SERVICES_PATH);
  if (!f.is_open())
    return "???";

  while (std::getline(f, line)) {
    std::istringstream iss(line);
    if (iss>>name>>portproto) {
      sp=portproto.find('/');
      if (sp!=std::string::npos) {
        fport=std::stoi(portproto.substr(0, sp));
        fproto=portproto.substr(sp + 1);
        if ((int)fport==port->port&&fproto==
          ((port->proto==6)?"tcp":(port->proto==17)?"udp":"sctp"))
          break;
      }
    }

  }

  f.close();
  return name;

}

std::string NESCAPRINT::portblock(NESCAPORT *port, bool onlyok)
{
  std::string res, p, s, m, srv, num;

  res="";
  if (onlyok) if (!isokport(port)) return "";

  res+='\'';
  switch (port->proto) {
    case PR_TCP: p="tcp"; break;
    case PR_UDP: p="udp"; break;
    case PR_SCTP: p="sctp"; break;
    default: p="???"; break;
  }
  switch (port->state) {
    case PORT_OPEN: s="open"; break;
    case PORT_CLOSED: s= "closed"; break;
    case PORT_FILTER: s="filtered"; break;
    case PORT_ERROR: s="error"; break;
    case PORT_OPEN_OR_FILTER: s="open|filtered"; break;
    case PORT_NO_FILTER: s="unfiltered"; break;
    default: s="???"; break;
  }
  switch (port->method) {
    case M_TCP_SYN_SCAN: m="syn"; break;
    case M_TCP_XMAS_SCAN: m="xmas"; break;
    case M_TCP_FIN_SCAN: m="fin"; break;
    case M_TCP_ACK_SCAN: m="ack"; break;
    case M_TCP_WINDOW_SCAN: m="window"; break;
    case M_TCP_NULL_SCAN: m="null"; break;
    case M_TCP_MAIMON_SCAN: m="maimon"; break;
    case M_TCP_PSH_SCAN: m="psh"; break;
    case M_SCTP_INIT_SCAN: m="init"; break;
    case M_SCTP_COOKIE_SCAN: m="cookie"; break;
    case M_UDP_SCAN: m="udp"; break;
    default: m="???"; break;
  }

  num=(port->num>1)?"/"+std::to_string(port->num):"";
  srv=is_service(port);

  res+=std::to_string(port->port)+"/";
  res+=p+"/";
  res+=s+"/";
  res+=srv+"(";
  res+=m+")";
  res+=num;
  res+='\'';

  return res;
}

/*
 * Print results, print class NESCATARGET
 */
void NESCAPRINT::nescatarget(NESCATARGET *target, bool onlyok)
{
  std::string methodstr, block;
  size_t i=0;

  if (onlyok&&!target->isok())
    return;

  methodstr="'.";
  if (target->get_num_time()>0)
    for (i=0;i<target->get_num_time();i++)
      methodstr+=strmethod(target->get_type_time(i));
  if (target->get_num_port()>0)
    for (i=0;i<target->get_num_port();i++)
      methodstr+=strmethod(target->get_port(i).method);
  methodstr.erase(std::unique(methodstr.begin(),
    methodstr.end()), methodstr.end());
  methodstr+="'";

  std::cout << "Report nesca4 for ";
  if (!target->get_mainip().empty())
    std::cout << target->get_mainip();
  else
    std::cout << "???";
  std::cout << " (";
  if (target->get_num_dns()>0) {
    for (i=0;i<target->get_num_dns();i++) {
      std::cout << target->get_dns(i);
      if (i!=target->get_num_dns()-1)
        std::cout << " ";
    }
  }
  else std::cout << "???";
  std::cout << ") ";
  if (!target->get_mac().empty())
    std::cout << "[" << target->get_mac() << "] ";
  std::cout << methodstr << " ";
  if (target->get_num_time()>0) {
    for (i=0;i<target->get_num_time();i++) {
      printf("%0.1f ms", (double)(target->get_time_ns(i)/1000000.0));
      if (i!=target->get_num_time()-1)
        putchar(' ');
    }
  }
  putchar('\n');
  if (target->get_num_port()>0) {
    target->removedublports();
    if (onlyok&&!target->openports())
      return;
    for (i=0;i<target->get_num_port();i++) {
      NESCAPORT p=target->get_port(i);
      if (onlyok&&!isokport(&p))
        continue;
      block+=portblock(&p, onlyok);
      block+=',';
    }
    block.pop_back();
    if (!block.empty()) {
      std::cout << "\n  ports  ";
      std::cout << block;
    }
    putchar('\n');
  }
}

void NESCAPRINT::PRINTTARGETS(NESCADATA *ncsdata)
{
  for (const auto&t:ncsdata->targets) {
    this->nescatarget(t, 1);
    if (t->openports())
      putchar('\n');
    ncsdata->tmplast=(t->openports())?0:1;
    if (t->isok()) ncsdata->ok++;
  }
}

#include <iomanip>
static void print_u128(u128 value)
{
  u64 high = value >> 64;
  u64 low = static_cast<u64>(value);

  if (high>0) {
    std::cout << std::hex << high << std::setfill('0') << std::setw(16);
    std::cout << low << std::dec;
  }
  else
    std::cout << low << std::dec;
}

void NESCAPRINT::nescastats(size_t grouplen, __uint128_t total, __uint128_t i)
{
  u128 complete;
  int dots;

  if (total==0)
    return;

  complete=(i*100)/total;
  dots=(static_cast<uint64_t>(complete)*10)/100;
  std::cout << "\n\n * " << "completed ";
  print_u128(complete);
  std::cout << "% targets";
  std::cout << "\n * remaining ";
  print_u128(100-complete);
  std::cout << "%\n * ";
  for (;dots+1;dots--)
    putchar('.');
  std::cout << ",\n \n";
}

void NESCAPRINT::finish(NESCADATA *ncsdata)
{
  if (!ncsdata->ok)
    std::cout << "All scanned targets were unavailable, try another ping method.\n\n";
  if (ncsdata->tmplast)
    putchar('\n');
  std::cout << "NESCA4 finished ";
  print_u128(ncsdata->ok);
  std::cout << " up IPs (success) in ";
  std::cout << util_timediff(ncsdata->tstamp_s, ncsdata->tstamp_e) << "\n";
}

/*
 * Print class NESCADEVICE
 */
void NESCAPRINT::nescadevice(NESCADEVICE *device)
{
  mac_t mac, dstmac;
  ip4_t ip4, ip4_g;
  ip6_t ip6, ip6_g;

  mac=device->get_srcmac();
  dstmac=device->get_dstmac();
  ip4=device->get_srcip4();
  ip6=device->get_srcip6();
  ip4_g=device->get_gateway4();
  ip6_g=device->get_gateway6();

  std::cout << "DEVICE " << device->get_device() <<
    ((device->check_ipv6())?" [support ip6]":" [not support ip6]") <<
    ((device->check_ipv4())?" [support ip4]":" [not support ip4]") <<
    ": mac(" << mact_ntop_c(&mac) <<
    ") ip4(" << ip4t_ntop_c(&ip4) <<
    ") ip6(" << ip6t_ntop_c(&ip6) << ") gateway4(";

  std::cout << ip4t_ntop_c(&ip4_g) <<") gateway6(" <<
    ip6t_ntop_c(&ip6_g) << ") dstmac(" << mact_ntop_c(&dstmac)
    << ")\n";

}


/*
 * print usage (help menu)
 */
void NESCAPRINT::usage(int argc, char **argv)
{
  printf("Usage: %s [flags] <targets>\n", argv[0]);
  std::cout << "TARGETS\n";
  std::cout << "  <targets>: dns, ip4, ip6, cidr4, cidr6, range4, range6\n";
  std::cout << "  -import <file>: import targets from file\n";
  std::cout << "  -random-ip <num>: choose random ip4 target(s)\n";
  std::cout << "INTERFACE\n";
  std::cout << "  -dev <name>: set your interface\n";
  std::cout << "  -dst <mac>: set your dest mac\n";
  std::cout << "  -src <mac>: set your source mac\n";
  std::cout << "  -ip4 <ip4>: set your source ip4\n";
  std::cout << "  -ip6 <ip6>: set your source ip6\n";
  std::cout << "ENGINE\n";
  std::cout << "  -maxfds <num>: set your max open fds\n";
  std::cout << "  -pps <pps>: set max packet per second for send\n";
  std::cout << "  -gplus <num>: set plus target group size\n";
  std::cout << "  -gmax <num>: set max target group size\n";
  std::cout << "  -gmin <num>: set min target group size\n";
  std::cout << "  -stats: display engine statistics after exec\n";
  std::cout << "PACKETS\n";
  std::cout << "  -dlen <num>: append random data to sent packets\n";
  std::cout << "  -dhex <hex>: append a custom payload to sent packet\n";
  std::cout << "  -dstr <str>: append a custom ASCII string to sent packets\n";
  std::cout << "  -ttl <num>: set Time To Live\n";
  std::cout << "  -off <hex>: set fragmentation offset\n";
  std::cout << "  -ipopt <hex>: set ip options to packet\n";
  std::cout << "PINGER\n";
  std::cout << "  -ps, -pa, -py, -pu <ports>: use SYN/ACK/UDP/SCTP ping.\n";
  std::cout << "  -pr, -pe, -pi, -pm: use ARP or ICMP ping ECHO/INFO/TIMESTAMP\n";
  std::cout << "  -all-ping: use all ping methods\n";
  std::cout << "  -wait-ping <time>: set your max wait time for ping (timeout)\n";
  std::cout << "  -num-ping <num>: set count ping probes\n";
  std::cout << "  -n-ping: skip ping scan, disable ping\n";
  std::cout << "PORTSCAN\n";
  std::cout << "  -xmas, -fin, -psh, -null: use one of these scanning methods.\n";
  std::cout << "  -syn, -ack, -window, -maimon: use other TCP methods port scan.\n";
  std::cout << "  -init, -cookie, -udp: use init, cookie SCTP, or UDP port scan method.\n";
  std::cout << "  -all-scan: use all scan port methods.\n";
  std::cout << "  -wait-scan <time>: set your max wait time for scan (timeout)\n";
  std::cout << "  -num-scan <num>: set count scan probes\n";
  std::cout << "  -mtpl-scan <multiplier>: set your multiplier for calc scan timeout\n    Nb: <rtt> * <mult> = timeout\n";
  std::cout << "  -p <ports>: set ports for scan,\n    Ex: -p 80; -p 80,443; -p S:40-50,U:3,T:33,10-15\n";
  std::cout << "  -sn, -n-scan: skip port scan, disable port scan.\n";
  std::cout << "SERVICES\n";
  std::cout << "  -s <ports>: set ports for service,\n    Ex: -s http:40-50,ftp:3,rvi:33,10-15\n";
  std::cout << "OTHER\n";
  std::cout << "  -n: no resolv, skip resolution dns names\n";
  std::cout << "  -cfg <path>: set your config file for opts\n";
  std::cout << "  -badsum: send packets with bodus checksum\n";
  std::cout << "  -help: display this menu and exit\n";
  exit(0);
}


/*
 * print run string
 */
void NESCAPRINT::run(void)
{
  char formatted_date[11];
  get_current_date(formatted_date, sizeof(formatted_date));
  printf("Running NESCA4 (v%s) time %s at %s\n",
      PACKAGE_VERSION, get_time(), formatted_date);
}


/*
 * print error string
 */
void NESCAPRINT::error(const std::string &err)
{
  std::cout << "err: " << err << std::endl;
  exit(0);
}

void NESCAPRINT::warning(const std::string &warn)
{
  std::cout << "warn: " << warn << std::endl;
}
