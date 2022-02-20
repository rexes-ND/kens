/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

namespace E {
/* TCP states */
enum State { 
  CLOSED, 
  SYN_SENT,
  LSTN, 
  SYN_RCVD, 
  ESTABLISHED, 
  FIN_WAIT_1, 
  FIN_WAIT_2, 
  CLOSE_WAIT, 
  TIME_WAIT, 
  LAST_ACK, 
  CLOSING 
};
struct Pkt {
  uint32_t localip;
  uint32_t destip;
  uint16_t localport;
  uint16_t destport;
  uint32_t seqnum;
  uint32_t acknum;
  bool ack;
  bool rst;
  bool syn;
  bool fin;
  uint16_t wndw;
  void* data;
  int size;
};
/* Socket Class */
class Socket {
public:
  State state = CLOSED;
  bool bound = false, active = true, connected = false, accepted = false;
  int pid, fd;
  UUID uuid;
  uint32_t localip, destip;
  uint16_t localport, destport;
  uint32_t localseq, destseq;
  Socket* listen = NULL;
  struct sockaddr* addr = NULL;
  // queue - incoming syns
  // accept - fully established, ready to be accepted
  std::vector<std::pair<uint32_t, uint16_t>> queue, accept; // (destip, destport) (destseqnum) from server POV
  int backlog;
  uint16_t localrwnd = 51200, destrwnd;
  bool read = false, write = false;
  char *readbuf = NULL;
  uint32_t readcnt = 0;
  char *writebuf = NULL;
  uint32_t writecnt = 0;
  std::map<uint32_t, std::pair<uint32_t, char*>> rcvbuf; // seqnum -> (pkt length, pointer to location)
  std::map<uint32_t, Pkt> sndbuf;
  std::map<uint32_t, uint32_t> sndtime;
  uint32_t readseq;

  bool timed = false;
  UUID timeuuid = 0;
  uint32_t SampleRTT = 100000000;
  uint32_t EstimatedRTT = 100000000;
  uint32_t DevRTT = 0;

  bool closed = false;
};

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void sndPkt(Pkt);
  virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) final;
  virtual void syscall_socket(UUID uuid, int pid, int domain, int type);
  virtual void syscall_close(UUID uuid, int pid, int fd);
  virtual void syscall_bind(UUID uuid, int pid, int sockfd, struct sockaddr* addr, socklen_t addrlen);
  virtual void syscall_getsockname(UUID uuid, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrlen);
  virtual void syscall_connect(UUID uuid, int pid, int sockfd, struct sockaddr* addr, socklen_t addrlen);
  virtual void syscall_listen(UUID uuid, int pid, int sockfd, int backlog);
  virtual void syscall_accept(UUID uuid, int pid, int sockfd, struct sockaddr * addr, socklen_t* addrlen);
  virtual void syscall_getpeername(UUID uuid, int pid, int sockfd, struct sockaddr* addr, socklen_t * addrlen);
  virtual void syscall_read(UUID uuid, int pid, int sockfd, void* buf, int count);
  virtual void syscall_write(UUID uuid, int pid, int sockfd, void* buf, int count);
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

// Helper declaration
void pktForm(
  Pkt* pkt,
  uint32_t localip, uint32_t destip,
  uint16_t localport, uint16_t destport,
  uint32_t seqnum,
  uint32_t acknum,
  uint16_t rwnd,
  bool ack, bool rst, bool syn, bool fin,
  int, void*
);
void packetForm(
  Packet* pkt, 
  uint32_t localip, uint32_t destip,
  uint16_t localport, uint16_t destport,
  uint32_t seqnum,
  uint32_t acknum,
  uint16_t rwnd,
  bool ack, bool rst, bool syn, bool fin
);
int min(int, int);
uint64_t ti(Socket *);
} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
