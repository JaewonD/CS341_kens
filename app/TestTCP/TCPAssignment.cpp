/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
        NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
        SystemCallInterface(AF_INET, IPPROTO_TCP, host),
        NetworkLog(host->getNetworkSystem()),
        TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
    int ret;
    switch(param.syscallNumber)
    {
    case SOCKET:
        ret = this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
        this->returnSystemCall(syscallUUID, ret);
        break;
    case CLOSE:
        ret = this->syscall_close(syscallUUID, pid, param.param1_int);
        this->returnSystemCall(syscallUUID, ret);
        break;
    case READ:
        //this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        break;
    case WRITE:
        //this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        break;
    case CONNECT:
        ret = this->syscall_connect(syscallUUID, pid, param.param1_int,
              static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
        break;
    case LISTEN:
        ret = this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
        break;
    case ACCEPT:
        ret = this->syscall_accept(syscallUUID, pid, param.param1_int,
              static_cast<struct sockaddr*>(param.param2_ptr),
              static_cast<socklen_t*>(param.param3_ptr));
        break;
    case BIND:
        ret = this->syscall_bind(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr *>(param.param2_ptr),
                (socklen_t) param.param3_int);
        this->returnSystemCall(syscallUUID, ret);
        break;
    case GETSOCKNAME:
        ret = this->syscall_getsockname(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr *>(param.param2_ptr),
                static_cast<socklen_t*>(param.param3_ptr));
        this->returnSystemCall(syscallUUID, ret);
        break;
    case GETPEERNAME:
        ret = this->syscall_getpeername(syscallUUID, pid, param.param1_int,
              static_cast<struct sockaddr *>(param.param2_ptr),
              static_cast<socklen_t*>(param.param3_ptr));
        break;
    default:
        assert(0);
    }
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused)
{
    int new_fd = SystemCallInterface::createFileDescriptor (pid);
    TCPAssignment::validfds.insert_fds(new_fd);
    return new_fd;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    TCPAssignment::bindlist.resizeBindList();

    unsigned long new_ip_address = ((struct sockaddr_in*)addr)->sin_addr.s_addr;
    unsigned short new_port = ((struct sockaddr_in*)addr)->sin_port;

    bool overlap_detected = false;

    /*Check for valid fd*/
    if(!TCPAssignment::validfds.search_fds(sockfd)) return -1;

    /* Check for overlapping data */
    for (int i=0; i<TCPAssignment::bindlist.capacity; i++)
    {
        BindData bd = TCPAssignment::bindlist.b[i];
        if (bd.in_use)
        {
            if (bd.port == new_port) 
            {
                if (bd.ip_address == new_ip_address || new_ip_address == htonl(INADDR_ANY) ||
                    bd.ip_address == htonl(INADDR_ANY))
                {
                    overlap_detected = true;
                    break;
                }
            }
            else if (sockfd == bd.fd)
            {
                overlap_detected = true;
                break;
            }
        }   
    }

    /* Overlap detected */
    if (overlap_detected)
    {
        return -1;
    }

    /* Overlap not detected, add new data into the list. */
    /* Check for empty spot */
    bool inserted = false;
    for (int i=0; i<TCPAssignment::bindlist.capacity; i++)
    {
        BindData* bd = &(TCPAssignment::bindlist.b[i]);
        if (!bd->in_use)
        {
            bd->in_use = true;
            bd->ip_address = new_ip_address;
            bd->port = new_port;
            bd->fd = sockfd;
            TCPAssignment::bindlist.size++;
            inserted = true;
            break;
        }
    }
    assert(inserted);

    //printdb();
    //printf("capacity:%d\n", TCPAssignment::bindlist.capacity);
    //for (int i=0; i<TCPAssignment::bindlist.capacity; i++)
    //{
    //  BindData* bd = &(TCPAssignment::bindlist.b[i]);
    //  printf("InUse: %d, IP: %lu, Port: %d, fd: %d\n", bd->in_use, bd->ip_address, bd->port, bd->fd);
    //}
    return 0;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int success = -1;
    for (int i=0; i<TCPAssignment::bindlist.capacity; i++)
    {
        BindData* bd = &(TCPAssignment::bindlist.b[i]);
        if (bd->in_use && bd->fd == sockfd)
        {
            struct sockaddr_in socket_name;
            memset(&socket_name, 0, sizeof socket_name);
            socket_name.sin_family = AF_INET;
            socket_name.sin_addr.s_addr = bd->ip_address;
            socket_name.sin_port = bd->port;
            int size_minimum = (sizeof(struct sockaddr_in) < *addrlen)? sizeof(struct sockaddr_in) : *addrlen;
            memcpy(addr, &socket_name, size_minimum);
            *addrlen = size_minimum;
            success = 0;
            break;
        }
    }
    return success;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
    TCPAssignment::validfds.remove_fds(fd);
    for (int i=0; i<TCPAssignment::bindlist.capacity; i++)
    {
        BindData* bd = &(TCPAssignment::bindlist.b[i]);
        if (bd->in_use && bd->fd == fd)
        {
            bd->in_use = false;
            TCPAssignment::bindlist.size--;
            break;
        }
    }
    SystemCallInterface::removeFileDescriptor(pid, fd);
    return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    return 0;
}

int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
    return 0;
}

int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}

int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    return 0;
}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
