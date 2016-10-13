/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <map>

#include <E/E_TimerModule.hpp>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:


private:
    virtual void timerCallback(void* payload) final;

public:
    TCPAssignment(Host* host);
    virtual void initialize();
    virtual void finalize();
    virtual ~TCPAssignment();

    enum class State 
    {
        // Add more states here
        CLOSED, LISTEN, SYN_SENT, SYN_RCVD, ESTABLISHED
    };

    class Context
    {
    public:
        unsigned long ip_address;
        unsigned short port;
        State state;
        bool isBound;
    };

    std::map<int, Context*> contextList;

    int syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused);
    int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
    int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int syscall_close(UUID syscallUUID, int pid, int fd);
    int syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
    int syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);


protected:
    virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
    virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
    TCPAssignmentProvider() {}
    ~TCPAssignmentProvider() {}
public:
    static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
