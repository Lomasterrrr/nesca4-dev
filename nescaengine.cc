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

#include "include/nescaengine.h"
#include "include/nescadata.h"
#include "include/nescaprint.h"
#include "libncsnet/ncsnet/arp.h"
#include "libncsnet/ncsnet/eth.h"
#include "libncsnet/ncsnet/hex.h"
#include "libncsnet/ncsnet/icmp.h"
#include "libncsnet/ncsnet/ip.h"
#include "libncsnet/ncsnet/ip4addr.h"
#include "libncsnet/ncsnet/ip6addr.h"
#include "libncsnet/ncsnet/linuxread.h"
#include "libncsnet/ncsnet/mac.h"
#include "libncsnet/ncsnet/ncsnet.h"
#include "libncsnet/ncsnet/random.h"
#include "libncsnet/ncsnet/sctp.h"
#include "libncsnet/ncsnet/tcp.h"
#include "libncsnet/ncsnet/trace.h"
#include "libncsnet/ncsnet/udp.h"
#include "libncsnet/ncsnet/utils.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstddef>
#include <cstdlib>
#include <exception>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

static std::mutex stoprecv;

bool NESCARESOLV_try(NESCATARGET *target, NESCADATA *ncsdata)
{
  char host[NI_MAXHOST], service[NI_MAXSERV];
  struct sockaddr_storage addr={0};
  struct sockaddr_in6 *sa6=NULL;
  struct sockaddr_in *sa=NULL;
  int len=0, ret=0;
  const char *ip;

  if (!target->isok())
    return 0;

  memset(&addr, 0, sizeof(addr));
  ip=target->get_mainip().c_str();
  if (target->is_ip6host()) {
    sa6=(struct sockaddr_in6*)&addr;
    sa6->sin6_family=AF_INET6;
    inet_pton(AF_INET6, ip,
      &sa6->sin6_addr);
    len=sizeof(struct sockaddr_in6);
  }
  else {
    sa=(struct sockaddr_in*)&addr;
    sa->sin_family=AF_INET;
    sa->sin_addr.s_addr=inet_addr(ip);
    len=sizeof(struct sockaddr_in);
  }

  ret=getnameinfo((struct sockaddr*)&addr, len, host, sizeof(host), service, sizeof(service), 0);
  if (ret!=0)
    return 0;

  stoprecv.lock();
  target->add_dns(host);
  stoprecv.unlock();

  return 1;
}

bool _NESCARESOLV_(std::vector<NESCATARGET*> targets, NESCADATA *ncsdata)
{
  std::vector<std::future<bool>> futures;
  size_t threads=targets.size();
  bool success=1;
  size_t i=0;

  futures.reserve(threads);
  NESCAPOOL pool(threads);
  for (;i<threads;++i) {
    futures.emplace_back(pool.enqueue(
      [&, i]() {
        return NESCARESOLV_try(targets[i], ncsdata);
      }
    ));
  }

  for (auto&future:futures)
    if (!future.get())
      success=0;

  return success;

}

NESCAPOOL::NESCAPOOL(size_t numthreads) : stop(false)
{
  size_t i;
  for (i=0;i<numthreads;++i) {
    workers.emplace_back([this] {
      while (true) {
        std::function<void()>task;{
          std::unique_lock<std::mutex> lock(queuemutex);
          condition.wait(lock,[this]{return stop||!tasks.empty();});
          if (stop&&tasks.empty()) {return;}
            task=std::move(tasks.front());
            tasks.pop();
          }
          task();
        }
      }
    );
  }
}

NESCAPOOL::~NESCAPOOL()
{
  {
    std::unique_lock<std::mutex> lock(queuemutex);
    stop = true;
  }
  condition.notify_all();
  for (std::thread& worker:workers){worker.join();}
}


/*
 * ICMP4 error filter
 */
static int __received_icmp4_error(u8 *frame, size_t frmlen, void *arg, int *skip, int *proto)
{
  struct __arg_   *a=(struct __arg_*)arg;
  icmph_t *icmp=NULL;
  ip4h_t *ip=NULL;

  *skip=(14+sizeof(ip4h_t)+(sizeof(icmph_t)+4)+sizeof(ip4h_t));
  icmp=(icmph_t*)(frame+(14+sizeof(ip4h_t)));

  /*
   * ICMP4 redirect, source quench, param prob,
   * timexeed, dstunreach
   */

  if (icmp->type==ICMP4_REDIRECT||icmp->type==ICMP4_SRCQUENCH||
      icmp->type==ICMP4_PARAMPROB||icmp->type==ICMP4_TIMEXCEED||
      icmp->type==ICMP4_UNREACH) {

    /* src ip in ip header or icmp error */
    ip=(ip4h_t*)(frame+((14+sizeof(ip4h_t)+sizeof(icmph_t)+4)));
    *proto=ip->proto;
    if (!ip4t_compare(a->addr.ip4, ip->dst)) {
      ip=(ip4h_t*)(frame+14);
      if (!ip4t_compare(a->addr.ip4, ip->src))
        return 0;
    }

    /* dstunreach proto or port */
    if (icmp->type==ICMP4_UNREACH&&
      (icmp->code==ICMP4_UNREACH_PORT
        ||icmp->code==ICMP4_UNREACH_PROTO))
      return icmp->code;
  }

  return 0;
}


/*
 * ICMP6 error filter
 */
static int __received_icmp6_error(u8 *frame, size_t frmlen, void *arg, int *skip, int *proto)
{
  struct __arg_   *a=(struct __arg_*)arg;
  icmph_t *icmp=NULL;
  ip6h_t *ip=NULL;

  *skip=(14+sizeof(ip6h_t)+(sizeof(icmph_t)+4)+sizeof(ip6h_t));
  icmp=(icmph_t*)(frame+(14+sizeof(ip6h_t)));

  /*
   * ICMP6 dstunreach, pktobig, param prob,
   * timexeed
   */

  if (icmp->type==ICMP6_UNREACH||
    icmp->type==ICMP6_PARAMPROBLEM
    ||icmp->type==2/* pkt too big*/||
    icmp->type==ICMP6_TIMEXCEED) {

    /* src ip in ip header or icmp error */
    ip=(ip6h_t*)(frame+((14+sizeof(ip6h_t)+sizeof(icmph_t)+4)));
    *proto=ip->nxt;
    if (!ip6t_compare(a->addr.ip6, ip->dst)) {
      ip=(ip6h_t*)(frame+14);
      if (!ip6t_compare(a->addr.ip6, ip->src))
        return 0;
    }

    /* dstunreach port */
    if (icmp->type==ICMP6_UNREACH&&
      icmp->code==ICMP6_UNREACH_PORT)
      return icmp->code;
  }

  return 0;
}


/*
 * ICMP error filter
 */
static int __received_icmp_error(u8 *frame, size_t frmlen, void *arg, int icmpv)
{
  struct          filter_ { u16 srcport; u16 dstport; union{u16 icmpid; u32 vtagseq;}; };
  int             ret=0, skip=0, proto=0;
  struct __arg_  *a=(struct __arg_*)arg;

  if (icmpv==PR_ICMP)
    ret=__received_icmp4_error(frame, frmlen, arg, &skip, &proto);
  if (a->addrtype==PR_ICMPV6)
    ret=__received_icmp6_error(frame, frmlen, arg, &skip, &proto);
  if (!ret)
    return ret;

  if (proto!=a->proto)
    return 0;
  if (a->proto==PR_TCP||a->proto==PR_UDP||a->proto==PR_SCTP||
    a->proto==PR_ICMP) {
    struct filter_ *f=(struct filter_*)(frame+skip);
    if (a->proto==PR_ICMP&&(a->chk!=ntohs(f->icmpid)))
      return 0;
    if (a->proto==PR_TCP&&((a->chk!=ntohl(f->vtagseq))||
      (a->port!=ntohs(f->dstport))||a->srcport!=ntohs(f->srcport)))
      return 0;
    if (a->proto==PR_SCTP&&((a->chk!=ntohl(f->vtagseq))||
      (a->port!=ntohs(f->dstport))||a->srcport!=ntohs(f->srcport)))
      return 0;
    if (a->proto==PR_UDP&&(a->port!=ntohs(f->dstport)||
        a->srcport!=ntohs(f->srcport)))
      return 0;
  }

  return ret;
}


/*
 * Callback to receive arp, checks payload type, operation,
 * header, protocol, address length, and whether the sender's
 * ip matches the receiver's ip.
 */
static bool __received_arp_ping_callback(u8 *frame, size_t frmlen, void *arg)
{
  struct __arg_ *a=(struct __arg_*)arg;
  arp_op_hdr_request_ethip *arpreq;
  arph_t *arp;

  arp=(arph_t*)(frame+sizeof(mach_t));
  if (ntohs(arp->op)!=ARP_OP_REPLY)
    return 0;
  if (ntohs(arp->hdr)!=ARP_HDR_ETH)
    return 0;
  if (ntohs(arp->hdr)==ARP_HDR_AX25||
    ntohs(arp->hdr)==ARP_HDR_RESERVED) {
    if (ntohs(arp->pro)!=AX25_PRO_IP)
      return 0;
  }
  else if (ntohs(arp->pro)!=ARP_PRO_IP)
    return 0;

  if (arp->pln!=4) /* only ipv4 */
    return 0;
  if (arp->hln!=6) /* only mac as long as 6*/
    return 0;


  /*
   * The ip4 address of the recipient inside
   * the ARP request must match the local ip4
   * address, otherwise, the packet was not
   * addressed to us.
   */
  arpreq=(arp_op_request_ethip*)((frame)+(sizeof(mach_t)+sizeof(arph_t)));
  if (!ip4t_compare(arpreq->spa, a->addr.ip4))
    return 0;

  return 1;
}


/*
 * Callback for filter and recv ping
 */
static bool __ping_callback(u8 *frame, size_t frmlen, void *arg)
{
  struct __arg_   *a=(struct __arg_*)arg;
  int              skip=0, proto=0;
  mach_t          *datalink;
  ip6_t            cmp6;
  ip4_t            cmp4;

  if (frmlen<14)
    return 0;

  datalink=(mach_t*)frame;
  skip=0;


  /*
   * ARP
   */
  if (a->method==M_ARP_PING) {
    if (ntohs(datalink->type)!=ETH_TYPE_ARP)
      return 0;
    return __received_arp_ping_callback(frame, frmlen, arg);
  }


  /*
   * IP
   */
  if ((a->addrtype==4&&ntohs(datalink->type)!=ETH_TYPE_IPV4)||
    (a->addrtype==6&&ntohs(datalink->type)!=ETH_TYPE_IPV6))
    return 0;
  if (a->addrtype==4) {
    if ((frmlen-14)<sizeof(ip4h_t))
      return 0;
    ip4h_t *iph=(ip4h_t*)(frame+14);
    cmp4=iph->src;
    skip=sizeof(ip4h_t);
    proto=iph->proto;
  }
  else if (a->addrtype==6) {
    if ((frmlen-14)<sizeof(ip6h_t))
      return 0;
    ip6h_t *iph=(ip6h_t*)(frame+14);
    cmp6=iph->src;
    skip=sizeof(ip6h_t);
    proto=iph->nxt;
  }


  /*
   * ICMP error
   */
  if (proto==PR_ICMP||proto==PR_ICMPV6) {
    icmph_t *icmp=(icmph_t*)((frame+(14+skip)));
    if (proto==PR_ICMP&&icmp->type!=ICMP4_ECHOREPLY&&
        icmp->type!=ICMP4_TSTAMPREPLY
        &&icmp->type!=ICMP4_INFOREPLY)
      return (bool)__received_icmp_error(frame, frmlen, arg, proto);
    if (proto==PR_ICMPV6&&icmp->type!=ICMP6_ECHOREPLY)
      return (bool)__received_icmp_error(frame, frmlen, arg, proto);
  }

  /* Filter */
  if (proto!=a->proto)
    return 0;
  if (a->addrtype==6)
    if (!ip6t_compare(a->addr.ip6, cmp6))
      return 0;
  if (a->addrtype==4)
    if (!ip4t_compare(a->addr.ip4, cmp4))
      return 0;


  /*
   * ICMP echo ping
   * ICMP info ping
   * ICMP tstamp ping
   */
  if (proto==PR_ICMP) {
    icmph_t *icmp=(icmph_t*)((frame+(14+skip)));
    if (icmp->type!=ICMP4_ECHOREPLY&&a->method==M_ICMP_PING_ECHO)
      return 0;
    if (icmp->type!=ICMP4_TSTAMPREPLY&&a->method==M_ICMP_PING_TIME)
      return 0;
    if (icmp->type!=ICMP4_INFOREPLY&&a->method==M_ICMP_PING_INFO)
      return 0;
  }


  /*
   * ICMP6 echo ping
   */
  if (proto==PR_ICMPV6) {
    icmph_t *icmp=(icmph_t*)((frame+(14+skip)));
    if (icmp->type!=ICMP6_ECHOREPLY&&a->method==M_ICMP_PING_ECHO)
      return 0;
  }


  /*
   * TCP ACK ping
   * TCP SYN ping
   */
  if (proto==PR_TCP) {
    tcph_t *tcp=(tcph_t*)(frame+(14+skip));
    if (ntohs(tcp->th_sport)!=a->port||
      ntohs(tcp->th_dport)!=a->srcport)
      return 0;
    if (a->method==M_TCP_PING_ACK&&!(tcp->th_flags&TCP_FLAG_RST))
      return 0;
    if (a->method==M_TCP_PING_SYN&&!(tcp->th_flags&TCP_FLAG_RST)
        &&(tcp->th_flags&!(TCP_FLAG_SYN|TCP_FLAG_ACK)))
      return 0;
  }


  /*
   * UDP ping
   */
  if (proto==PR_UDP) {
    udph_t *udp=(udph_t*)(((frame+14)+skip));
    if (ntohs(udp->srcport)!=a->port||
      ntohs(udp->dstport)!=a->srcport)
      return 0;
  }


  /*
   * SCTP init ping
   */
  if (proto==PR_SCTP) {
    sctph_t *sctp=(sctph_t*)(((frame+14)+skip));
    if (ntohs(sctp->srcport)!=a->port||
      ntohs(sctp->dstport)!=a->srcport)
      return 0;
  }

  return 1;
}

static bool __scan_callback(u8 *frame, size_t frmlen, void *arg)
{
  struct __arg_   *a=(struct __arg_*)arg;
  int              skip=0, proto=0, ret=0;
  mach_t          *datalink;
  ip6_t            cmp6;
  ip4_t            cmp4;

  if (frmlen<14)
    return 0;

  datalink=(mach_t*)frame;
  skip=0;

  if ((a->addrtype==4&&ntohs(datalink->type)!=ETH_TYPE_IPV4)||
    (a->addrtype==6&&ntohs(datalink->type)!=ETH_TYPE_IPV6))
    return 0;

  if (a->addrtype==4) {
    if ((frmlen-14)<sizeof(ip4h_t))
      return 0;
    ip4h_t *iph=(ip4h_t*)(frame+14);
    cmp4=iph->src;
    skip=sizeof(ip4h_t);
    proto=iph->proto;
  }
  else if (a->addrtype==6) {
    if ((frmlen-14)<sizeof(ip6h_t))
      return 0;
    ip6h_t *iph=(ip6h_t*)(frame+14);
    cmp6=iph->src;
    skip=sizeof(ip6h_t);
    proto=iph->nxt;
  }

  /*
   * ICMP error
   */
  if (proto==PR_ICMP||proto==PR_ICMPV6) {
    icmph_t *icmp=(icmph_t*)((frame+(14+skip)));
    if (proto==PR_ICMP&&icmp->type!=ICMP4_ECHOREPLY&&
        icmp->type!=ICMP4_TSTAMPREPLY
        &&icmp->type!=ICMP4_INFOREPLY)
      ret=__received_icmp_error(frame, frmlen, arg, proto);
    if (proto==PR_ICMPV6&&icmp->type!=ICMP6_ECHOREPLY)
      ret=__received_icmp_error(frame, frmlen, arg, proto);
    if (ret) {
      /* icmp error is filtered port or closed udp */
      a->state=(ret==ICMP4_UNREACH_PORT&&a->method==M_UDP_SCAN)
        ?PORT_CLOSED:PORT_FILTER;
      return 1;
    }
    return 0;
  }

  /* Filter */
  if (proto!=a->proto)
    return 0;
  if (a->addrtype==6)
    if (!ip6t_compare(a->addr.ip6, cmp6))
      return 0;
  if (a->addrtype==4)
    if (!ip4t_compare(a->addr.ip4, cmp4))
      return 0;


  /*
   * TCP scan ports
   * ack, syn, null, fin, xmas, maimon, window, psh
   *
   * https://github.com/nmap/nmap/blob/master/scan_engine_raw.cc
   */
  if (proto==PR_TCP) {
    tcph_t *tcp=(tcph_t*)(frame+(14+skip));
    if (ntohs(tcp->th_sport)!=a->port||
      ntohs(tcp->th_dport)!=a->srcport)
      return 0;
    if (a->method==M_TCP_SYN_SCAN) {
      if ((tcp->th_flags&(TCP_FLAG_SYN|TCP_FLAG_ACK))
        ==(TCP_FLAG_SYN|TCP_FLAG_ACK))
        a->state=PORT_OPEN;
      else if (tcp->th_flags&TCP_FLAG_RST)
        a->state=PORT_CLOSED;
    }
    if (a->method==M_TCP_WINDOW_SCAN)
      if (tcp->th_flags&TCP_FLAG_RST)
        a->state=(tcp->th_win)?PORT_OPEN:PORT_CLOSED;
    if (a->method==M_TCP_XMAS_SCAN||
      a->method==M_TCP_NULL_SCAN||
      a->method==M_TCP_PSH_SCAN||
      a->method==M_TCP_MAIMON_SCAN||
      a->method==M_TCP_FIN_SCAN)
      if (tcp->th_flags&TCP_FLAG_RST)
        a->state=PORT_CLOSED;
    if (a->method==M_TCP_ACK_SCAN)
      if (tcp->th_flags&TCP_FLAG_RST)
        a->state=PORT_NO_FILTER;
  }


  /*
   * UDP scan ports
   *
   * https://nmap.org/book/scan-methods-udp-scan.html
   */
  if (proto==PR_UDP) {
    udph_t *udp=(udph_t*)(((frame+14)+skip));
    if (ntohs(udp->srcport)!=a->port||
      ntohs(udp->dstport)!=a->srcport)
      return 0;
    a->state=PORT_OPEN;
  }


  /*
   * SCTP scan ports
   * init, cookie
   *
   * https://nmap.org/book/man-port-scanning-techniques.html
   * https://github.com/nmap/nmap/blob/master/scan_engine_raw.cc
   */
  if (proto==PR_SCTP) {
    sctph_t *sctp=(sctph_t*)(((frame+14)+skip));
    sctp_chunk *chunk=(sctp_chunk*)(((frame+14)+(skip+sizeof(sctph_t))));
    if (ntohs(sctp->srcport)!=a->port||
      ntohs(sctp->dstport)!=a->srcport)
      return 0;
    if (a->method==M_SCTP_INIT_SCAN) {
      if (chunk->type==SCTP_INIT_ACK)
        a->state=PORT_OPEN;
      else if (chunk->type==SCTP_ABORT)
        a->state=PORT_CLOSED;
    }
    if (a->method==M_SCTP_COOKIE_SCAN)
      if (chunk->type==SCTP_ABORT)
        a->state=PORT_CLOSED;
  }

  return 1;
}

NESCAINIT::NESCAINIT(NESCADATA *ncsdata, bool ping)
{
  ni_initsendfd(&ncsdata->dev);
  ni_initmethods(&ncsdata->opts, ping);
  total=last_target=last_method=last_num=0;
}

size_t NESCAINIT::NI_NUM(std::vector<NESCATARGET*> targets)
{
  size_t res=0;
  res+=ni_methods.size();
  for (auto&m:ni_methods)
    res+=m.numprobes-1;
  res*=targets.size();
  return res;
}

NESCAINIT::~NESCAINIT(void)
{
  if (this->sendfd)
    eth_close(this->sendfd);
  NI_CLEAR();
}

void NESCAINIT::NI_CLEAR(void)
{
  std::vector<std::thread> threads;
  for (auto p:probes) {
    if (p->probe)
      free(p->probe);
    delete p;
  }
  probes.clear();
  for (auto res:results) {
    if (res->frame)
      free(res->frame);
    delete res;
  }
  results.clear();
  for (lr_t *lr:recvfds)
    if (lr) threads.emplace_back(lr_close, lr);
  for (auto&th:threads)
    th.join();
  recvfds.clear();
}


/*
 * Init socket for send
 */
void NESCAINIT::ni_initsendfd(NESCADEVICE *ncsdev)
{
  this->sendfd=eth_open(ncsdev->get_device().c_str());
}


/*
 * Init socket for recv
 */
void NESCAINIT::ni_initrecvfd(NESCATARGET *target, NESCADEVICE *ncsdev,
      NESCAOPTS *ncsopts, bool ping)
{
  long long timeout=0;
  lr_t *lr=NULL;
  size_t mtpl;

  if (ncsopts->check_mtpl_scan_flag()&&!ping&&target->get_num_time()>0) {
    mtpl=atoll(ncsopts->get_mtpl_scan_param().c_str());
    timeout=target->get_time_ns(0)*mtpl;
  }
  if (ncsopts->check_wait_scan_flag()&&!ping)
    timeout=(delayconv(ncsopts->get_wait_scan_param().c_str()));
  if (ncsopts->check_wait_ping_flag()&&ping)
    timeout=delayconv(ncsopts->get_wait_ping_param().c_str());

  lr=lr_open(ncsdev->get_device().c_str(), timeout);
  if (ping)
    lr_callback(lr, __ping_callback);
  else
    lr_callback(lr, __scan_callback);

  this->recvfds.push_back(lr);
}


/*
 * Init method
 */
void NESCAINIT::ni_initmethod(size_t numprobes, int method,
    std::vector<int> ports)
{
  int proto;
  proto=((method>=1&&method<=3)?PR_ICMP
      :(method>=4&&method<=13)?PR_TCP
      : (method>=14&&method<=16)?PR_SCTP
      : (method>=17&&method<=18)?PR_UDP
      : ETH_TYPE_ARP);
  NESCAMETHOD m={(((numprobes>0)?numprobes:1))*
    ((ports.empty())?1:ports.size()), 0, method,
      proto, ports};
  this->ni_methods.push_back(m);
}


/*
 * Init methods for probes
 */
void NESCAINIT::ni_initmethods(NESCAOPTS *ncsopts, bool ping)
{
  std::vector<int> tcports, udports, sctports;
  size_t numtmp;

  if (ping)
    goto ping;

  for (const auto&port:ncsopts->get_p_param()) {
    if (port.proto==PR_TCP)
      tcports.push_back(port.port);
    if (port.proto==PR_UDP)
      udports.push_back(port.port);
    if (port.proto==PR_SCTP)
      sctports.push_back(port.port);
  }

  if (ncsopts->check_syn_flag())
    ni_initmethod(1, M_TCP_SYN_SCAN, tcports);
  if (ncsopts->check_xmas_flag())
    ni_initmethod(1, M_TCP_XMAS_SCAN, tcports);
  if (ncsopts->check_fin_flag())
    ni_initmethod(1, M_TCP_FIN_SCAN, tcports);
  if (ncsopts->check_null_flag())
    ni_initmethod(1, M_TCP_NULL_SCAN, tcports);
  if (ncsopts->check_psh_flag())
    ni_initmethod(1, M_TCP_PSH_SCAN, tcports);
  if (ncsopts->check_window_flag())
    ni_initmethod(1, M_TCP_WINDOW_SCAN, tcports);
  if (ncsopts->check_ack_flag())
    ni_initmethod(1, M_TCP_ACK_SCAN, tcports);
  if (ncsopts->check_maimon_flag())
    ni_initmethod(1, M_TCP_MAIMON_SCAN, tcports);
  if (ncsopts->check_init_flag())
    ni_initmethod(1, M_SCTP_INIT_SCAN, sctports);
  if (ncsopts->check_cookie_flag())
    ni_initmethod(1, M_SCTP_COOKIE_SCAN, sctports);
  if (ncsopts->check_udp_flag())
    ni_initmethod(1, M_UDP_SCAN, udports);
  /* ..., */

  return;

ping:
  numtmp=atoll(ncsopts->get_num_ping_param().c_str());
  if (ncsopts->check_pe_flag())
    ni_initmethod(numtmp, M_ICMP_PING_ECHO, {});
  if (ncsopts->check_pm_flag())
    ni_initmethod(numtmp, M_ICMP_PING_TIME, {});
  if (ncsopts->check_pi_flag())
    ni_initmethod(numtmp, M_ICMP_PING_INFO, {});
  if (ncsopts->check_pu_flag())
    ni_initmethod(numtmp, M_UDP_PING, ncsopts->get_pu_param());
  if (ncsopts->check_ps_flag())
    ni_initmethod(numtmp, M_TCP_PING_SYN, ncsopts->get_ps_param());
  if (ncsopts->check_pa_flag())
    ni_initmethod(numtmp, M_TCP_PING_ACK, ncsopts->get_pa_param());
  if (ncsopts->check_py_flag())
    ni_initmethod(numtmp, M_SCTP_INIT_PING, ncsopts->get_py_param());
  if (ncsopts->check_pr_flag())
    ni_initmethod(numtmp, M_ARP_PING, {});
  /* ..., */
}

static u8 *get_payload(NESCAOPTS *ncsopts, size_t *reslen)
{
  size_t hexlen=0, strlen_=0, randlen=0, skip=0;
  u8 *res=NULL, *hex=NULL, *rand=NULL, *str=NULL;

  if (!ncsopts->check_dhex_flag()&&!ncsopts->check_dlen_flag()&&!ncsopts->check_dstr_flag())
    return NULL;

  if (ncsopts->check_dhex_flag()) {
    hex=hex_ahtoh(ncsopts->get_dhex_param().data(), &hexlen);
    *reslen+=hexlen;
  }
  if (ncsopts->check_dlen_flag()) {
    randlen=std::stoi(ncsopts->get_dlen_param());
    rand=(u8*)random_str(randlen, DEFAULT_DICTIONARY);
    *reslen+=randlen;
  }
  if (ncsopts->check_dstr_flag()) {
    strlen_=strlen(ncsopts->get_dstr_param().c_str());
    str=(u8*)ncsopts->get_dstr_param().c_str();
    *reslen+=strlen_;
  }

  res=(u8*)calloc(1,*reslen);
  if (!res)
    return NULL;

  /* init */
  if (hex) {
    memcpy(res+skip, hex, hexlen);
    skip+=hexlen;
  }
  if (str) {
    memcpy(res+skip, str, strlen_);
    skip+=strlen_;
  }
  if (rand) {
    memcpy(res+skip, rand, randlen);
    skip+=strlen_;
  }

  return res;
}


/*
 * eth build
 */
void NESCAINIT::ni_ethprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod)
{
  u8 *res=NULL;
  mac_t dst={};
  int type=0;

  switch (ncsmethod->method) {
    case M_ARP_PING:
      type=ETH_TYPE_ARP;
      mact_fill(&dst, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
      break;
    default:
      if (target->is_ip6host())
        type=ETH_TYPE_IPV6;
      else
        type=ETH_TYPE_IPV4;
      dst=ncsdata->dev.get_dstmac();
      break;
  }

  res=eth_build(ncsdata->dev.get_srcmac(), dst, type, probe->probe,
      probe->probelen, &probe->probelen);
  if (probe->probe)
    free(probe->probe);

  probe->probe=res;
  probe->method=ncsmethod->method;
  probe->filter.method=probe->method;
}


/*
 * ip4 build
 */
void NESCAINIT::ni_iprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod)
{
  u8 *res=NULL, *ipopts=NULL, off_[2]={0,0};
  size_t ipoptslen=0, offlen=0;
  ip4_t src, dst;
  u16 *off;
  int ttl;

  ip4t_pton(target->get_mainip().c_str(), &dst);
  src=ncsdata->dev.get_srcip4();

  ipopts=(ncsdata->opts.check_ipopt_flag())?
    hex_ahtoh(ncsdata->opts.get_ipopt_param().data(), &ipoptslen):NULL;

  ttl=(ncsdata->opts.check_ttl_flag())?std::stoi(ncsdata->opts.get_ttl_param())
    :random_num_u32(54, 255);

  if (ncsdata->opts.check_off_flag()) {
    hex_atoh(ncsdata->opts.get_off_param().data(), off_, offlen);
    off=(u16*)off_;
  }

  res=ip4_build(src, dst, ncsmethod->proto, ttl, random_u16(), 0, *off,
    ipopts, ipoptslen, probe->probe, probe->probelen, &probe->probelen);
  if (!res)
    return;
  if (probe->probe)
    free(probe->probe);

  probe->probe=res;
  probe->filter.addrtype=4;
  probe->filter.addr.ip4=dst;
  probe->filter.proto=ncsmethod->proto;
}


/*
 * Build icmp probe
 */
void NESCAINIT::ni_icmprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod)
{
  u8 *msg=NULL, *data=NULL;
  size_t msglen=0, datalen=0;
  int type=-1;

  probe->filter.chk=random_u16();
  data=get_payload(&ncsdata->opts, &datalen);
  switch (ncsmethod->method) {
    default:
    case M_ICMP_PING_ECHO:
      msg=icmp4_msg_echo_build((u16)probe->filter.chk, random_u16(), (char*)data, &msglen);
      type=ICMP4_ECHO;
      break;
    case M_ICMP_PING_INFO:
      msg=icmp4_msg_info_build((u16)probe->filter.chk, random_u16(), &msglen);
      type=ICMP4_INFO;
      break;
    case M_ICMP_PING_TIME:
      msg=icmp4_msg_tstamp_build((u16)probe->filter.chk, random_u16(), random_u32(), random_u32(), random_u32(), &msglen);
      type=ICMP4_TSTAMP;
      break;
  }
  if (!msg)
    return;
  if (data)
    free(data);
  probe->probe=icmp_build(type, 0, msg, msglen, &probe->probelen);
  icmp4_check(probe->probe, probe->probelen, ncsdata->opts.check_badsum_flag());
  free(msg);

  ni_iprobe(probe, target, ncsdata, ncsmethod);
  ni_ethprobe(probe, target, ncsdata, ncsmethod);
}


/*
 * Build arp probe
 */
void NESCAINIT::ni_arprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod)
{
  u8 *arp_op=NULL;
  mac_t dstmac_arp;
  size_t arpoplen;
  ip4_t tmp;

  ip4t_pton(target->get_mainip().c_str(), &tmp);
  mact_fill(&dstmac_arp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

  arp_op=arp_op_request_build(6, 4, ncsdata->dev.get_srcmac().octet,
    ncsdata->dev.get_srcip4().octet, dstmac_arp.octet, tmp.octet,
    &arpoplen);
  if (!arp_op)
    return;
  probe->probe=arp_build(ARP_HDR_ETH, ARP_PRO_IP, 6, 4, ARP_OP_REQUEST,
    arp_op, arpoplen, &probe->probelen);
  free(arp_op);

  ni_ethprobe(probe, target, ncsdata, ncsmethod);
  probe->filter.addr.ip4=tmp;
  probe->filter.addrtype=4;
}


/*
 * Build tcp probe
 */
void NESCAINIT::ni_tcprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod, int port)
{
  size_t datalen=0;
  u8 *data=NULL;
  u8 flags=0;
  ip4_t tmp;

  probe->filter.chk=random_u32();
  probe->filter.srcport=random_srcport();
  data=get_payload(&ncsdata->opts, &datalen);
  switch (ncsmethod->method) {
    case M_TCP_PING_ACK:
    case M_TCP_ACK_SCAN:
    case M_TCP_WINDOW_SCAN:
      flags=TCP_FLAG_ACK;
      break;
    case M_TCP_PING_SYN:
    case M_TCP_SYN_SCAN:
      flags=TCP_FLAG_SYN;
      break;
    case M_TCP_MAIMON_SCAN:
      flags=TCP_FLAG_FIN|TCP_FLAG_ACK;
      break;
    case M_TCP_PSH_SCAN:
      flags=TCP_FLAG_PSH;
      break;
    case M_TCP_FIN_SCAN:
      flags=TCP_FLAG_FIN;
      break;
    case M_TCP_XMAS_SCAN:
      flags=TCP_FLAG_FIN|TCP_FLAG_PSH|TCP_FLAG_URG;
      break;
    case M_TCP_NULL_SCAN:
      break;
  }
  probe->probe=tcp_build((u16)probe->filter.srcport, port, (u32)probe->filter.chk, 0, 0,
    flags, 1024, 0, NULL, 0, data, datalen, &probe->probelen);
  if (data)
    free(data);

  ip4t_pton(target->get_mainip().c_str(), &tmp);
  tcp4_check(probe->probe, probe->probelen, ncsdata->dev.get_srcip4(),
    tmp, ncsdata->opts.check_badsum_flag());

  probe->filter.port=port;
  ni_iprobe(probe, target, ncsdata, ncsmethod);
  ni_ethprobe(probe, target, ncsdata, ncsmethod);
}


/*
 * Build udp probe
 */
void NESCAINIT::ni_udprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod, int port)
{
  size_t datalen=0;
  u8 *data=NULL;
  ip4_t tmp;

  data=get_payload(&ncsdata->opts, &datalen);
  probe->filter.srcport=random_srcport();
  switch (ncsmethod->method) {
    default:
    case M_UDP_PING:
    case M_UDP_SCAN:
      probe->probe=udp_build((u16)probe->filter.srcport, port, data,
        datalen, &probe->probelen);
      break;
  }
  if (data)
    free(data);

  ip4t_pton(target->get_mainip().c_str(), &tmp);
  udp4_check(probe->probe, probe->probelen, ncsdata->dev.get_srcip4(),
    tmp, ncsdata->opts.check_badsum_flag());

  probe->filter.port=port;
  ni_iprobe(probe, target, ncsdata, ncsmethod);
  ni_ethprobe(probe, target, ncsdata, ncsmethod);
}


/*
 * Build sctp probe
 */
void NESCAINIT::ni_sctprobe(NESCAPROBE *probe, NESCATARGET *target,
    NESCADATA *ncsdata, NESCAMETHOD *ncsmethod, int port)
{
  u8 *chunk=NULL, *data=NULL;
  size_t datalen=0, chunklen=0;

  data=get_payload(&ncsdata->opts, &datalen);
  probe->filter.srcport=random_srcport();
  switch (ncsmethod->method) {
    default:
    case M_SCTP_INIT_PING:
    case M_SCTP_INIT_SCAN:
      probe->filter.chk=0;
      chunk=sctp_init_build(SCTP_INIT, 0, random_u32(), random_u32(), random_u16(), random_u16(), random_u32(), &chunklen);
      if (!chunk)
        return;
      probe->probe=sctp_build((u16)probe->filter.srcport, port, (u32)probe->filter.chk, chunk, chunklen, &probe->probelen);
      free(chunk);
      break;
    case M_SCTP_COOKIE_SCAN:
      probe->filter.chk=random_u32();
      chunk=sctp_chunk_build(SCTP_COOKIE_ECHO, 0, data, datalen, &chunklen);
      if (!chunk)
        return;
      probe->probe=sctp_build((u16)probe->filter.srcport, port, (u32)probe->filter.chk, chunk, chunklen, &probe->probelen);
      free(chunk);
      break;
  }
  sctp_check(probe->probe, probe->probelen, 0, ncsdata->opts.check_badsum_flag());
  if (data)
    free(data);

  probe->filter.port=port;
  ni_iprobe(probe, target, ncsdata, ncsmethod);
  ni_ethprobe(probe, target, ncsdata, ncsmethod);
}


/*
 * Init probe
 */
void NESCAINIT::ni_initprobe(NESCATARGET *target, NESCADATA *ncsdata,
    NESCAMETHOD *ncsmethod)
{
  NESCAPROBE *probe=new NESCAPROBE;
  int port;

  port=0;
  if (!ncsmethod->ports.empty()) {
    if (ncsmethod->lastport>ncsmethod->ports.size()-1)
      ncsmethod->lastport=0;
    port=ncsmethod->ports.at(ncsmethod->lastport);
    ncsmethod->lastport++;
  }

  if (ncsmethod->proto==PR_ICMP)
    ni_icmprobe(probe, target, ncsdata, ncsmethod);
  if (ncsmethod->proto==PR_SCTP)
    ni_sctprobe(probe, target, ncsdata, ncsmethod, port);
  if (ncsmethod->proto==PR_TCP)
    ni_tcprobe(probe, target, ncsdata, ncsmethod, port);
  if (ncsmethod->proto==PR_UDP)
    ni_udprobe(probe, target, ncsdata, ncsmethod, port);
  if (ncsmethod->proto==ETH_TYPE_ARP)
    ni_arprobe(probe, target, ncsdata, ncsmethod);

  probes.push_back(probe);
}


/*
 * Init res
 */
void NESCAINIT::ni_initres(NESCATARGET *target,
    NESCAMETHOD *ncsmethod)
{
  NESCARESULT *res=new NESCARESULT;
  res->c=target->get_mainip();
  res->frame=(u8*)calloc(1, MAXPKTLEN);
  res->frmlen=0;
  res->method=ncsmethod->method;
  results.push_back(res);
}


/*
 * Init
 */
bool NESCAINIT::NI_INIT(std::vector<NESCATARGET*> targets,
    NESCADATA *ncsdata, bool ping, size_t max)
{
  size_t i, j, k;
  for (j=this->last_target;j<targets.size();j++,this->last_target=j) {
    for (k=this->last_method;k<ni_methods.size();k++,this->last_method=k) {
      for (i=this->last_num;i<=ni_methods[k].numprobes-1;i++,this->last_num=i) {

        /* result init */
        ni_initres(targets[j], &ni_methods[k]);

        /* probe init */
        ni_initprobe(targets[j], ncsdata,
          &ni_methods[k]);

        /* recv fd init */
        ni_initrecvfd(targets[j], &ncsdata->dev,
          &ncsdata->opts, ping);

        /* stop if max */
        if (this->total==max) {
          this->last_target=j;
          this->last_method=k;
          this->last_num=i+1;
          this->total=0;
          return 0;
        }
        this->total++;
      }
      this->last_num=0;
    }
    this->last_method=0;
  }
  this->last_target=0;

  return 1;
}

std::vector<NESCARESULT*> NESCAINIT::ni_results(void)
{
  return this->results;
}

std::vector<NESCAPROBE*> NESCAINIT::ni_probes(void)
{
  return this->probes;
}

std::vector<lr_t*> NESCAINIT::ni_recvfds(void)
{
  return this->recvfds;
}

eth_t *NESCAINIT::ni_sendfd(void)
{
  return this->sendfd;
}

NESCASEND::NESCASEND(void)
{
  ok=err=sendbytes=tot=stats=0;
  pps=SIZE_MAX;
  return;
}

void NESCASEND::ns_setstats(void)
{
  this->stats=1;
}

void NESCASEND::ns_setpps(size_t pps)
{
  this->pps=pps;
}

void NESCASEND::ns_send(eth_t *fd, std::vector<NESCAPROBE*> probes, size_t num)
{
  struct timespec delay;
  size_t i=0;

  delay.tv_sec=0;
  delay.tv_nsec=1000000000/this->pps;

  gettimeofday(&this->tstamp_s, NULL);
  for (i=0;i<num;i++) {
    if ((eth_send(fd, probes[i]->probe,
        probes[i]->probelen))>0)
      ok++;
    else
      err++;
    sendbytes+=probes[i]->probelen;
    tot++;
    if (i<num-1)
      nanosleep(&delay, NULL);
  }
  gettimeofday(&this->tstamp_e, NULL);
  if (this->stats)
    ns_stats();
}

void NESCASEND::ns_stats(void)
{
  double p=(static_cast<double>(err)/tot)*100;
  stoprecv.lock();
  std::cout << "NESCASEND  Sent " << util_bytesconv(sendbytes);
  std::cout << " at " << util_timediff(this->tstamp_s,
    this->tstamp_e);
  std::cout << " (loss " << p << "%)";
  std::cout << " ok=" << ok << " err="
    << err << " tot=" << tot;
  std::cout << " > " << util_pps(this->tstamp_s, this->tstamp_e,
    tot) << std::endl;
  stoprecv.unlock();
}

NESCARECV::NESCARECV(void)
{
  ok=err=recvbytes=tot=stats=0;
  return;
}

void NESCARECV::nr_stats(void)
{
  double p=(static_cast<double>(err)/tot)*100;
  stoprecv.lock();
  std::cout << "NESCARECV  Recv " << util_bytesconv(recvbytes);
  std::cout << " at " << util_timediff(this->tstamp_s,
    this->tstamp_e);
  std::cout << " (loss " << p << "%)";
  std::cout << " ok=" << ok << " err="
    << err << " tot=" << tot;
  std::cout << " > " << util_pps(this->tstamp_s, this->tstamp_e,
    tot) << std::endl;
  stoprecv.unlock();
}

void NESCARECV::nr_setstats(void)
{
  this->stats=1;
}

void NESCARECV::_nr_recv(lr_t *fd, NESCAPROBE *probe, NESCARESULT *result)
{
  ssize_t ret=0;

  /* recv packet */
  ret=lr_live(fd, &result->frame, MAXPKTLEN, (void*)&probe->filter);

  if (ret>0) {
    /* res update */
    stoprecv.lock();

    /* fill res */
    result->state=probe->filter.state;
    result->port=probe->filter.port;
    result->frmlen=ret;
    result->t_end=fd->tstamp_e;
    result->t_start=fd->tstamp_s;
    result->ok=1;

    /* stats */
    ok++;
    recvbytes+=ret;

    stoprecv.unlock();
  }
  else {
    stoprecv.lock();
    result->ok=0;
    result->port=probe->filter.port;
    err++;
    stoprecv.unlock();
  }
  stoprecv.lock();
  tot++;
  stoprecv.unlock();
}

void NESCARECV::nr_recv(std::vector<lr_t*> fds, std::vector<NESCAPROBE*> probes, std::vector<NESCARESULT*> results)
{
  std::vector<std::future<void>> futures;
  size_t threads, i;

  threads=probes.size();
  futures.clear();
  i=0;

  NESCAPOOL pool(threads);
  gettimeofday(&this->tstamp_s, NULL);
  for (;i<probes.size();i++) {
    futures.emplace_back(pool.enqueue(std::bind(&NESCARECV::_nr_recv, this, fds.at(i), probes.at(i), results.at(i))));
    if (futures.size()>=static_cast<size_t>(threads)) {
      for (auto&future:futures)
        future.get();
      futures.clear();
    }
  }
  for (auto& future : futures)
    future.get();
  gettimeofday(&this->tstamp_e, NULL);
  if (this->stats)
    nr_stats();
}

NESCAREAD::NESCAREAD(void)
{
  return;
}

void NESCAREAD::nr_read(std::vector<NESCARESULT*> results, std::vector<NESCATARGET*> targets)
{
  NESCATARGET *t=NULL;
  std::string isc;

  for (const auto&res:results) {
    isc=res->c;
    auto it = std::find_if(targets.begin(), targets.end(),
    [&isc](NESCATARGET* target) { return target->get_mainip()==isc; });
    if (it!=targets.end()) {
      t=*it;
      switch (res->method) {

        /* Ping */
        case M_ICMP_PING_ECHO:
        case M_SCTP_INIT_PING:
        case M_UDP_PING:
        case M_TCP_PING_ACK:
        case M_TCP_PING_SYN:
        case M_ARP_PING:
        case M_ICMP_PING_TIME:
        case M_ICMP_PING_INFO:
          if (!res->ok)
            continue;
          t->set_ok();
          if (res->method==M_ARP_PING) {
            arp_op_request_ethip *arpreq=(arp_op_request_ethip*)
              ((res->frame)+(sizeof(mach_t)+sizeof(arph_t)));
            t->add_mac(mact_ntop_c(&arpreq->sha));
          }
          t->add_time(res->t_start, res->t_end, res->method);
          break;

        /* Scan */
        case M_TCP_SYN_SCAN:
        case M_TCP_WINDOW_SCAN:
        case M_SCTP_INIT_SCAN:
        case M_TCP_ACK_SCAN:
          res->state=(!res->ok)?PORT_FILTER:res->state; goto add;

        case M_TCP_XMAS_SCAN:
        case M_TCP_NULL_SCAN:
        case M_TCP_FIN_SCAN:
        case M_TCP_PSH_SCAN:
        case M_SCTP_COOKIE_SCAN:
        case M_TCP_MAIMON_SCAN:
        case M_UDP_SCAN:
            res->state=(!res->ok)?PORT_OPEN_OR_FILTER:res->state;
add:
          t->add_port(res->state, res->method, PR_TCP, res->port);
          break;
      }
      /* ..., XXX */
    }

  }
}

std::string NESCAINIT::ni_method(void)
{
  std::string res;
  res+='.';
  for (const auto&m:ni_methods)
    res+=strmethod(m.method);
  return res;
}

#include <sys/resource.h>

static int maxfds(void)
{
  struct rlimit limit;
  getrlimit(RLIMIT_NOFILE, &limit);
  return limit.rlim_cur;
}

void _NESCAENGINE_::NE_CONFIGURE(NESCADATA *ncsdata, bool ping)
{
  size_t pps;

  if (ncsdata->opts.check_pps_flag()) {
    pps=std::stoi(ncsdata->opts.get_pps_param());
    ns_setpps(pps);
  }
  if (ncsdata->opts.check_stats_flag()) {
    ns_setstats();
    nr_setstats();
    std::cout << "NESCAENGINE ";
    std::cout << ((ping)?"Ping for ":"Scan for ")
      << ncsdata->targets.size() << " targets";
    std::cout << " (" << ni_method() << ") methods" << std::endl;
  }

  this->grouplen=(NI_NUM(ncsdata->targets)/ncsdata->targets.size());
  __maxfds=(!ncsdata->opts.check_maxfds_flag())?(maxfds()-100):
    atoll(ncsdata->opts.get_maxfds_param().c_str());
  __maxfds=(__maxfds<this->grouplen)?this->grouplen:__maxfds;
  this->grouplen=((__maxfds)/this->grouplen);
}

void _NESCAENGINE_::NE_GROUPS(NESCADATA *ncsdata)
{
  size_t i=0;
  for (;i<ncsdata->targets.size();i+=grouplen) {
    std::vector<NESCATARGET*> group(ncsdata->targets.begin()+i,
      ncsdata->targets.begin()+std::min(ncsdata->targets.size(),i+grouplen));
    this->groups.push_back(group);
  }
}

_NESCAENGINE_::_NESCAENGINE_(NESCADATA *ncsdata, bool ping) : NESCAINIT(ncsdata, ping), NESCASEND(),
                                                              NESCARECV(), NESCAREAD()
{
  NE_CONFIGURE(ncsdata, ping);
  NE_GROUPS(ncsdata);

  for (i=0;i<groups.size();++i) {
    ret=NI_INIT(groups[i], ncsdata, ping,
      (!ncsdata->opts.check_maxfds_flag())?(maxfds()-100)
      :atoll(ncsdata->opts.get_maxfds_param().c_str()));

    std::thread recv_thread([&](void) {
      nr_recv(ni_recvfds(), ni_probes(), ni_results());
    });

    std::thread send_thread([&](void) {
      ns_send(ni_sendfd(), ni_probes(), ni_probes().size());
    });

    recv_thread.join();
    send_thread.join();

    nr_read(ni_results(), ncsdata->targets);

    NI_CLEAR();
    if (!ret) i--;
  }
}
