/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {

/*
  Sockets
  
  (Process, File Descripter) -> Socket
*/
std::map<std::pair<int, int>, Socket> socks;

TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {
  std::cout<<"INITIALIZED"<<std::endl;
}

void TCPAssignment::finalize() {
  socks.clear();
  std::cout<<"FINALIZED"<<std::endl;
}

void TCPAssignment::syscall_socket(UUID uuid, int pid, int domain, int type){
  int fd = createFileDescriptor(pid); // possible to return -1 
  if (fd < 0) returnSystemCall(uuid, -1);
  Socket s;
  s.pid = pid;
  s.fd = fd;
  s.bound = false;
  s.active = true;
  s.accepted = false;
  s.state = CLOSED;
  socks[{s.pid, s.fd}] = s;
  returnSystemCall(uuid, fd);
}

void TCPAssignment::syscall_close(UUID uuid, int pid, int fd) {
  if (!socks.count({pid, fd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, fd}];
  if (s->state == CLOSED || s->state == LSTN){
    removeFileDescriptor(pid, fd);
    socks.erase({pid, fd});
    returnSystemCall(uuid, 0);
  }
  else if (s->state == ESTABLISHED){
    if (!s->sndbuf.empty()){
      s->closed = true;
      s->uuid = uuid;
      return;
    }
    Pkt fin;
    pktForm(&fin, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, true, 0, NULL);
    s->localseq += 1;
    s->state = FIN_WAIT_1;
    s->uuid = uuid;
    sndPkt(fin);
  } else if (s->state == CLOSE_WAIT){
    Pkt fin;
    pktForm(&fin, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, true, 0, NULL);
    s->localseq += 1;
    s->uuid = uuid;
    s->state = LAST_ACK;
    sndPkt(fin);
  }
  
  // removeFileDescriptor(pid, fd);
  // socks.erase({pid, fd});
  // returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_bind(UUID uuid, int pid, int sockfd, struct sockaddr* sockaddr, socklen_t addrlen){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, sockfd}];
  if (s->bound){
    returnSystemCall(uuid, -1);
  }
  struct sockaddr_in addr = *(struct sockaddr_in *)sockaddr;
  uint32_t localip = ntohl(addr.sin_addr.s_addr);
  uint16_t localport = ntohs(addr.sin_port);
  for (auto [pidfd, sock]: socks){
    if (
      sock.bound && 
      (
        sock.localport == localport && 
        (sock.localip == INADDR_ANY || localip == INADDR_ANY || sock.localip == localip)
      )
    ){
      returnSystemCall(uuid, -1);
    }
  }
  s->bound = true;
  s->localip = localip;
  s->localport = localport;
  returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_getsockname(UUID uuid, int pid, int sockfd, struct sockaddr* sockaddr, socklen_t* addrlen){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, sockfd}];
  ((struct sockaddr_in*)sockaddr)->sin_family = AF_INET;
  *addrlen = sizeof(struct sockaddr_in);
  if (!s->bound){
    returnSystemCall(uuid, 0);
  }
  ((struct sockaddr_in*)sockaddr)->sin_addr.s_addr = htonl(s->localip);
  ((struct sockaddr_in*)sockaddr)->sin_port = htons(s->localport);
  returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_connect(UUID uuid, int pid, int sockfd, struct sockaddr* sockaddr, socklen_t addrlen){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, sockfd}];
  uint32_t destip = ntohl(((struct sockaddr_in *)sockaddr)->sin_addr.s_addr);
  uint16_t destport = ntohs(((struct sockaddr_in *)sockaddr)->sin_port);
  if (!s->bound){
    // IP and Ephemeral port
    ipv4_t destip_ipv4_t{(uint8_t)(destip>>24),(uint8_t)(destip>>16), (uint8_t)(destip>>8), (uint8_t)destip};
    auto localip_opt = getIPAddr(getRoutingTable(destip_ipv4_t));
    if (!localip_opt.has_value()){
      std::cout<<"Couldn't find IP address to use"<<std::endl;
      returnSystemCall(uuid, -1);
    }
    ipv4_t localip_ipv4_t = *localip_opt;
    s->localip = (localip_ipv4_t[0]<<24) + (localip_ipv4_t[1]<<16) + (localip_ipv4_t[2]<<8) + (localip_ipv4_t[3]);
    uint16_t localport = 0;
    std::vector<bool> ptable(65536, true);
    for (auto [pidfd, sock]: socks){
      if (sock.connected){
        if (
          sock.localport == s->localport &&
          sock.localip == s->localip &&
          sock.destip == destip &&
          sock.destport == destport
        )
        {
          ptable[sock.localport] = false;
        }
      }
    }
    for (int i = 1024; i < 65536; ++i){
      if (ptable[i]){
        localport = i;
      }
    }
    if (!localport){
      returnSystemCall(uuid, -1);
    }
    s->localport = localport;
    s->bound = true; // implicit bind
  }
  s->uuid = uuid;
  s->destip = destip;
  s->destport = destport;
  // (CLOSED)
  // SEND SYN to DEST (SYN_SENT)
  // RECV SYN, ACK and SEND ACK (ESTABLISHED)
  // Packet syn(54);
  // s->localseq = rand();
  // packetForm(&syn, s->localip, s->destip, s->localport, s->destport, s->localseq, 0, s->localrwnd, false, false, true, false);
  Pkt syn;
  pktForm(&syn, s->localip, s->destip, s->localport, s->destport, s->localseq, 0, s->localrwnd, false, false, true, false, 0, NULL);
  // sndPkt(syn);
  if (!s->timed){
    s->timed = true;
    std::pair<Socket*, uint32_t> payload = {s, s->localseq};
    s->timeuuid = addTimer(payload, ti(s));
  }
  
  s->sndbuf[s->localseq] = syn;
  s->sndtime[s->localseq] = getCurrentTime();
  s->localseq += 1;
  s->state = SYN_SENT;
  // sendPacket("IPv4", std::move(syn));
  sndPkt(syn);
}

void TCPAssignment::syscall_listen(UUID uuid, int pid, int sockfd, int backlog){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, sockfd}];
  s->active = false;
  s->accepted = false;
  s->state = LSTN; 
  s->queue = {};
  s->accept = {};
  s->backlog = backlog;
  s->localseq = rand(); // not needed but let's see
  returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_accept(UUID uuid, int pid, int sockfd, struct sockaddr* sockaddr, socklen_t* addrlen){
  
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, sockfd}]; // listening socket
  if (s->active){
    returnSystemCall(uuid, -1);
  }
  if (sockaddr) *addrlen = sizeof(struct sockaddr_in);
  if (s->accept.size() > 0){
    auto pidfd = s->accept[0];
    s->accept.erase(s->accept.begin());
    if (sockaddr) {
      ((struct sockaddr_in*)sockaddr)->sin_family = AF_INET;
      ((struct sockaddr_in*)sockaddr)->sin_addr.s_addr = htonl(socks[pidfd].destip);
      ((struct sockaddr_in*)sockaddr)->sin_port = htons(socks[pidfd].destport);
    }
   returnSystemCall(uuid, pidfd.second);
  }
  else {
    s->uuid = uuid;
    s->addr = sockaddr;
    s->accepted = true;
  }
}

void TCPAssignment::syscall_getpeername(UUID uuid, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket* s = &socks[{pid, sockfd}];
  if (!s->connected){
    returnSystemCall(uuid, -1);
  }
  *addrlen = sizeof(struct sockaddr_in);
  ((struct sockaddr_in*) addr)->sin_family = AF_INET;
  ((struct sockaddr_in*) addr)->sin_addr.s_addr = htonl(s->destip);
  ((struct sockaddr_in*) addr)->sin_port = htons(s->destport);
  returnSystemCall(uuid, 0);
}

void TCPAssignment::syscall_read(UUID uuid, int pid, int sockfd, void* buf, int count){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket *s = &socks[{pid, sockfd}];
  if (!s->connected){
    returnSystemCall(uuid, 0);
  }
  if (s->rcvbuf.empty()){
    // pending
    s->read = true;
    s->uuid = uuid;
  }
  else {
    uint32_t curcnt = count;
    char *bufp = (char *)buf;
    while (curcnt && !s->rcvbuf.empty()){
      auto it = s->rcvbuf.begin(); // (seqnum, (count, memory))
      if (curcnt < it->first + it->second.first - s->readseq){
        memcpy(bufp, it->second.second + (s->readseq - it->first), curcnt);
        s->readseq += curcnt;
        bufp += curcnt;
        curcnt = 0;
      }
      else {
        uint32_t readcnt = it->first + it->second.first - s->readseq;
        memcpy(bufp, it->second.second + (s->readseq - it->first), readcnt);
        bufp += readcnt;
        curcnt -= readcnt;
        s->readseq += readcnt;
        free(it->second.second);
        s->rcvbuf.erase(it);
      }
    }
    returnSystemCall(uuid, count - curcnt);
  }
 
}

void TCPAssignment::syscall_write(UUID uuid, int pid, int sockfd, void* buf, int count){
  if (!socks.count({pid, sockfd})){
    returnSystemCall(uuid, -1);
  }
  Socket *s = &socks[{pid, sockfd}];
  if (!s->connected){
    returnSystemCall(uuid, -1);
  }
  if (s->destrwnd == 0){
    s->uuid = uuid;
    s->writebuf = (char *)buf;
    s->writecnt = count;
    s->write = true;
  } else {
    int curcnt = count;
    char *bufp = (char *)buf;
    while (curcnt > 0 && s->destrwnd > 0){
      int pktsz = min(curcnt, min(s->destrwnd, 512));
      // Packet pkt(54 + pktsz);
      // pkt.writeData(54, bufp, pktsz);
      // packetForm(&pkt, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false);
      Pkt pkt;
      pktForm(&pkt, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, pktsz, bufp);
      if (!s->timed) {
        s->timed = true;
        std::pair<Socket *, uint32_t> payload = {s, s->localseq};
        s->timeuuid = addTimer(payload, ti(s));
      }     
      s->sndbuf[s->localseq] = pkt;
      s->localseq += pktsz;
      s->destrwnd -= pktsz;
      bufp += pktsz;
      curcnt -= pktsz;
      sndPkt(pkt);
    }
    returnSystemCall(uuid, count - curcnt);
  }
  
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) {

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, std::get<int>(param.params[0]), std::get<int>(param.params[1]));
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, std::get<int>(param.params[0]));
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, std::get<int>(param.params[0]),
                       std::get<void *>(param.params[1]),
                       std::get<int>(param.params[2]));
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, std::get<int>(param.params[0]),
                        std::get<void *>(param.params[1]),
                        std::get<int>(param.params[2]));
    break;
  case CONNECT:
    this->syscall_connect(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, std::get<int>(param.params[0]),
                         std::get<int>(param.params[1]));
    break;
  case ACCEPT:
    this->syscall_accept(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case BIND:
    this->syscall_bind(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        (socklen_t)std::get<int>(param.params[2]));
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(
        syscallUUID, pid, std::get<int>(param.params[0]),
        static_cast<struct sockaddr *>(std::get<void *>(param.params[1])),
        static_cast<socklen_t *>(std::get<void *>(param.params[2])));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  uint32_t localip;
  uint32_t destip;
  packet.readData(26, &destip, 4);
  packet.readData(30, &localip, 4);
  uint16_t csum;
  packet.readData(50, &csum, 2);
  csum = ntohs(csum);
  
  uint8_t *tcp_seg = (uint8_t *)malloc(packet.getSize() - 34);
  packet.readData(34, tcp_seg, packet.getSize() - 34);
  memset(tcp_seg + 16, 0, 2);
  uint16_t csumcalc = ~NetworkUtil::tcp_sum(destip, localip, tcp_seg, packet.getSize() - 34);
  if (csum != csumcalc) {
    free(tcp_seg);
    return;
  }
  free(tcp_seg);
  localip = ntohl(localip);
  destip = ntohl(destip);
  uint16_t localport;
  uint16_t destport;
  packet.readData(34, &destport, 2);
  packet.readData(36, &localport, 2);
  localport = ntohs(localport);
  destport = ntohs(destport);
  uint32_t destseqnum;
  uint32_t destacknum;
  packet.readData(38, &destseqnum, 4);
  packet.readData(42, &destacknum, 4);
  destseqnum = ntohl(destseqnum);
  destacknum = ntohl(destacknum);
  uint16_t destrwnd;
  packet.readData(48, &destrwnd, 2);
  destrwnd = ntohs(destrwnd);
  uint8_t flag;
  packet.readData(47, &flag, 1);
  bool ack, rst, syn, fin;
  ack = flag & 16;
  rst = flag & 4;
  syn = flag & 2;
  fin = flag & 1;
  Socket* s = NULL;
  uint32_t size = packet.getSize() - 54;
  // (localip, localport, destip, destport)
  for (auto [pidfd, sock]: socks){
    if (
      sock.localip == localip &&
      sock.destip == destip &&
      sock.localport == localport &&
      sock.destport == destport 
    ) {
      s = &socks[pidfd];
      break;
    }
  }
  if (s == NULL){ // Connection setup
    for (auto [pidfd, sock]: socks){
      if (sock.state == LSTN && (sock.localip == localip || sock.localip == INADDR_ANY) && sock.localport == localport){
        s = &socks[pidfd];
        break;
      }
    }
  }

  if (!s) {
    std::cout<<"IN YOUR FACE!"<<std::endl;
  } 

  if (s->state == SYN_SENT){
    if (ack && syn && s->localseq == destacknum) { // Recv SYNACK
      if (s->timed){
        s->timed = false;
        s->sndbuf.erase(s->localseq - 1);
        cancelTimer(s->timeuuid);
      }
      if (s->sndtime.count(s->localseq - 1)){
        s->SampleRTT = getCurrentTime() - s->sndtime[s->localseq - 1];
        s->sndtime.erase(s->localseq - 1);
      }
      s->destseq = destseqnum + 1;
      // Packet ack(54);
      Pkt ack;
      pktForm(&ack, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, 0, NULL);
      s->state = ESTABLISHED;
      s->destrwnd = destrwnd;
      s->readseq = s->destseq;
      s->connected = true;
      sndPkt(ack);
      returnSystemCall(s->uuid, 0);
    }
  }
  else if (s->state == LSTN){
    if (syn && !ack) {
      if (s->queue.size() == s->backlog) return;
      Socket sock;
      sock.active = false; // server-side socket
      sock.bound = true;
      sock.localip = localip;
      sock.localport = localport;
      sock.destip = destip;
      sock.destport = destport;
      sock.listen = s;
      sock.pid = s->pid;
      sock.fd = createFileDescriptor(s->pid);
      if (sock.fd < 0) return;
      sock.localseq = rand();
      sock.destrwnd = destrwnd;
      sock.destseq = destseqnum+1;
      sock.state = SYN_RCVD;
      
      s->queue.push_back({sock.pid, sock.fd});
      Pkt synack;
      pktForm(&synack, sock.localip, sock.destip, sock.localport, sock.destport, sock.localseq, sock.destseq, sock.localrwnd, true, false, true, false, 0, NULL);
      // packetForm(&synack, sock.localip, sock.destip, sock.localport, sock.destport, sock.localseq, sock.destseq, sock.localrwnd, true, false, true, false);
      // Packet synackc = synack.clone();
      sock.sndbuf[sock.localseq] = synack;
      socks[{sock.pid, sock.fd}] = sock;
      Socket* sck = &socks[{sock.pid, sock.fd}];
      if (!sck->timed){
        sck->timed = true;
        std::pair<Socket*, uint32_t> payload = {sck, sck->localseq};
        sck->timeuuid = addTimer(payload, ti(sck));
      }
      sck->sndtime[sck->localseq] = getCurrentTime();
      sck->localseq += 1;
      sndPkt(synack);
    }
  }
  else if (s->state == SYN_RCVD){ // Recv ACK
    // Push to accept queue
    if (ack && s->localseq == destacknum){

      s->state = ESTABLISHED;
      s->readseq = s->destseq;
      s->connected = true;
      if (s->timed){
        s->timed = false;
        s->sndbuf.erase(s->localseq-1);
        cancelTimer(s->timeuuid);
      }
      if (s->sndtime.count(s->localseq-1)){
        s->SampleRTT = getCurrentTime() - s->sndtime[s->localseq - 1];
        s->sndtime.erase(s->localseq - 1);
      }
      for (auto it = s->listen->queue.begin(); it != s->listen->queue.end(); ++it){
        if (s->pid == it->first && s->fd == it->second){
          s->listen->queue.erase(it);
          break;
        }
      }
      if (s->listen->accepted){
        s->listen->accepted = false;
        if (s->listen->addr){
          ((struct sockaddr_in *)s->listen->addr)->sin_family = AF_INET;
          ((struct sockaddr_in *)s->listen->addr)->sin_addr.s_addr = htonl(s->destip);
          ((struct sockaddr_in *)s->listen->addr)->sin_port = htons(s->destport);
        }
       returnSystemCall(s->listen->uuid, s->fd);
        return;
      }
      s->listen->accept.push_back({s->pid, s->fd});
    } else if (syn){ // Resend synack
      sndPkt(s->sndbuf[s->localseq-1]);
      if (s->timed){
        s->timed = false;
        cancelTimer(s->uuid);
      }
      s->timed = true;
      std::pair<Socket*, uint32_t> payload = {s, s->localseq-1};
      s->timeuuid = addTimer(payload, ti(s));
    }
  }
  else if (s->state == ESTABLISHED){
    // if (fin && destacknum == s->localseq){
    //   s->destseq += 1;
    //   // Packet ack(54);
    //   Pkt ack;
    //   pktForm(&ack, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, 0, NULL);
    //   // packetForm(&ack, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false);
    //   s->state = CLOSE_WAIT;
    //   // sendPacket("IPv4", std::move(ack));
    //   sndPkt(ack);
    // }
    if (fin && destseqnum == s->destseq){
      s->destseq += 1;
      Pkt ack;
      pktForm(&ack, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, 0, NULL);
      s->state = CLOSE_WAIT;
      sndPkt(ack);
    }
    else if (ack){ // data transfer
      if (size){ // recv data
        if (destseqnum == s->destseq){
          if (s->read) { // pending read
            if (s->readcnt >= size){
              packet.readData(54, s->readbuf, size);
              s->destseq += size;
              s->readseq = s->destseq;
              s->read = false;
              returnSystemCall(s->uuid, size);
            } else {
              packet.readData(54, s->readbuf, s->readcnt);
              s->readseq = s->destseq+s->readcnt;
              char* pktmem = (char *)malloc(size);
              packet.readData(54, pktmem, size);
              s->rcvbuf[s->destseq] = {size, pktmem};
              s->destseq += size;
              s->localrwnd = 51200 - (s->destseq - s->readseq);
              s->read = false;
              returnSystemCall(s->uuid, s->readcnt);
            }
          }
          else {
            char *pktmem = (char *)malloc(size);
            packet.readData(54, pktmem, size);
            s->rcvbuf[s->destseq] = {size, pktmem};
            s->destseq += size;
            s->localrwnd = 51200 - (s->destseq - s->readseq); 
          }
        }
        Pkt ack;
        std::cout<<s->destseq<<std::endl;
        pktForm(&ack, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, 0, NULL);
        sndPkt(ack);
      }
      else { // just ack => send data
        while (!s->sndbuf.empty()){
          auto it = s->sndbuf.begin(); // s->sndbuf == (seqnum --> pkt)
          if (destacknum > it->first){
            s->destrwnd += it->second.size; 
            if (s->timed){
              s->timed = false;
              cancelTimer(s->timeuuid);
              if (s->sndtime.count(it->first)){
                s->SampleRTT = getCurrentTime() - s->sndtime[it->first];
                s->sndtime.erase(it->first);
              }
            }
            s->sndbuf.erase(it->first);
          }
          else {
            break;
          }
        }
        if (!s->sndbuf.empty()){
          auto it = s->sndbuf.begin();
          if (!s->timed){
            s->timed = true;
            std::pair<Socket *, uint32_t> payload = {s, it->first};
            s->timeuuid = addTimer(payload, ti(s));
          }
        } else if (s->sndbuf.empty() && s->closed){
          if (s->timed){
            cancelTimer(s->timeuuid);
          }
          s->timed = false;
          s->timeuuid = 0;
          syscall_close(s->uuid, s->pid, s->fd);
        }
        if (s->write && s->destrwnd > 0){
          s->write = false;
          int curcnt = s->writecnt;
          char *bufp = s->writebuf;
          while (curcnt > 0 && s->destrwnd > 0){
            int pktsz = min(curcnt, min(s->destrwnd, 512));
            // Packet pkt(54 + pktsz);
            // pkt.writeData(54, bufp, pktsz);
            Pkt pkt;
            pktForm(&pkt, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, pktsz, bufp);
            s->sndbuf[s->localseq] = pkt;
            s->sndtime[s->localseq] = getCurrentTime();
            s->localseq += pktsz;
            curcnt -= pktsz;
            s->destrwnd -= pktsz;
            bufp += pktsz;
            sndPkt(pkt);
          }
          returnSystemCall(s->uuid, s->writecnt - curcnt);
        }
      }
    }
  }
  else if (s->state == LAST_ACK){
    if (ack && destacknum == s->localseq){
      removeFileDescriptor(s->pid, s->fd);
      UUID uuid = s->uuid;
      socks.erase({s->pid, s->fd});
      returnSystemCall(uuid, 0);
    }
  }
  else if (s->state == FIN_WAIT_1){
    if (ack && s->localseq == destacknum){
      s->state = FIN_WAIT_2;
    }
  }
  else if (s->state == FIN_WAIT_2){
    if (fin && s->localseq == destacknum){
      s->destseq += 1;
      Pkt ack;
      pktForm(&ack, s->localip, s->destip, s->localport, s->destport, s->localseq, s->destseq, s->localrwnd, true, false, false, false, 0, NULL);
      s->state = TIME_WAIT;
      s->state = CLOSED;
      removeFileDescriptor(s->pid, s->fd);
      UUID uuid = s->uuid;
      socks.erase({s->pid, s->fd});
      returnSystemCall(uuid, 0);
      sndPkt(ack);
    }
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  
  std::pair<Socket *, uint32_t> pl = std::any_cast<std::pair<Socket *, uint32_t>>(payload);
  Socket *s = pl.first;
  uint32_t seqnum = pl.second;
  sndPkt(s->sndbuf[seqnum]);
  s->timed = true;
  s->timeuuid = addTimer(pl, ti(s));
  if (s->sndtime.count(seqnum)){
    s->sndtime.erase(seqnum);
  }
}

// Helper functions

void packetForm(
  Packet* pkt, 
  uint32_t localip, uint32_t destip,
  uint16_t localport, uint16_t destport,
  uint32_t seqnum,
  uint32_t acknum,
  uint16_t rwnd,
  bool ack, bool rst, bool syn, bool fin
){
  uint32_t localip_n = htonl(localip);
  uint32_t destip_n = htonl(destip);
  uint16_t localport_n = htons(localport);
  uint16_t destport_n = htons(destport);
  uint32_t seqnum_n = htonl(seqnum);
  uint32_t acknum_n = htonl(acknum);
  uint8_t hdrlen = 0x50;
  uint8_t flag = 0;
  if (ack) flag += 0x10;
  if (rst) flag += 0x4;
  if (syn) flag += 0x2;
  if (fin) flag += 0x1;
  uint16_t wndsz = htons(rwnd);
  pkt->writeData(26, &localip_n, 4);
  pkt->writeData(30, &destip_n, 4);
  pkt->writeData(34, &localport_n, 2);
  pkt->writeData(36, &destport_n, 2);
  pkt->writeData(38, &seqnum_n, 4);
  pkt->writeData(42, &acknum_n, 4);
  pkt->writeData(46, &hdrlen, 1);
  pkt->writeData(47, &flag, 1);
  pkt->writeData(48, &wndsz, 2);
  // int size = pkt->getSize() - 54 + 20;
  // uint8_t *tcp_seg = (uint8_t *)malloc(size);
  // pkt->readData(34, tcp_seg, size);
  // uint16_t csum = ~NetworkUtil::tcp_sum(localip_n, destip_n, tcp_seg, size);
  // free(tcp_seg);
  // csum = htons(csum);
  // pkt->writeData(50, &csum, 2);
  return;
}

void pktForm(
  Pkt* pkt,
  uint32_t localip, uint32_t destip,
  uint16_t localport, uint16_t destport,
  uint32_t seqnum,
  uint32_t acknum,
  uint16_t rwnd,
  bool ack, bool rst, bool syn, bool fin,
  int size, void* srcmem
){
  pkt->localip = localip;
  pkt->destip = destip;
  pkt->localport = localport;
  pkt->destport = destport;
  pkt->seqnum = seqnum;
  pkt->acknum = acknum;
  pkt->wndw = rwnd;
  pkt->ack = ack;
  pkt->rst = rst;
  pkt->syn = syn;
  pkt->fin = fin;
  pkt->size = size;
  if (size > 0){
    pkt->data = malloc(size);
    memcpy(pkt->data, srcmem, size);
  } else {
    pkt->data = NULL;
  }
}

void TCPAssignment::sndPkt(Pkt pkt){
  Packet packet(54 + pkt.size);
  packetForm(&packet, pkt.localip, pkt.destip, pkt.localport, pkt.destport, pkt.seqnum, pkt.acknum, pkt.wndw, pkt.ack, pkt.rst, pkt.syn, pkt.fin);
  packet.writeData(54, pkt.data, pkt.size);
  uint8_t *tcp_seg = (uint8_t *)malloc(pkt.size + 20);
  packet.readData(34, tcp_seg, 20 + pkt.size);
  uint16_t csum = htons(~NetworkUtil::tcp_sum(htonl(pkt.localip), htonl(pkt.destip), tcp_seg, pkt.size + 20));
  free(tcp_seg);
  packet.writeData(50, &csum, 2);
  sendPacket("IPv4", std::move(packet));
}

int min(int a, int b){
  if (a > b){
    return b;
  }
  else {
    return a;
  }
}

uint64_t ti(Socket* s){
  s->EstimatedRTT = s->EstimatedRTT/8 + s->SampleRTT*7/8;
  s->DevRTT = 3*s->DevRTT/4 + abs(s->SampleRTT - s->EstimatedRTT)/4;
  return s->EstimatedRTT + 4*s->DevRTT;
}

} // namespace E
