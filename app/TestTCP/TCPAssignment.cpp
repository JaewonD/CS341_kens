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
        if (ret < 0) {
            this->returnSystemCall(syscallUUID, ret);
        }
        break;
    case LISTEN:
        ret = this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
        this->returnSystemCall(syscallUUID, ret);
        break;
    case ACCEPT:
        ret = this->syscall_accept(syscallUUID, pid, param.param1_int,
              static_cast<struct sockaddr*>(param.param2_ptr),
              static_cast<socklen_t*>(param.param3_ptr));
        if (ret != -2) {
            this->returnSystemCall(syscallUUID, ret);
        }
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
        this->returnSystemCall(syscallUUID, ret);
        break;
    default:
        assert(0);
    }
}

int TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused)
{
    int new_fd = SystemCallInterface::createFileDescriptor (pid);
    Context* context = (Context*) malloc (sizeof (Context));
    context->local_ip_address = 0;
    context->local_port = 0;
    context->isBound = false;
    context->state = TCPAssignment::State::CLOSED;
    context->seq_number = SEQ_NUMBER_START;
    context->backlog_size = 0;
    TCPAssignment::contextList[pid][new_fd] = context;
    //printf("Created socket - pid: %d, fd: %d\n", pid, new_fd);
    return new_fd;
}

int TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    unsigned int new_ip_address = ((struct sockaddr_in*)addr)->sin_addr.s_addr;
    unsigned short new_port = ((struct sockaddr_in*)addr)->sin_port;

    bool overlap_detected = false;

    /* Check for valid fd */
    if (TCPAssignment::contextList[pid][sockfd] == NULL) return -1;

    /* Check for overlaps */
    for (auto it : TCPAssignment::contextList[pid])
    {
        Context* c = it.second;
        if (c->isBound)
        {
            if (c->local_port == new_port)
            {
                if (c->local_ip_address == new_ip_address || new_ip_address == htonl(INADDR_ANY) ||
                    c->local_ip_address == htonl(INADDR_ANY))
                {
                    overlap_detected = true;
                    break;
                }
            }
            else if (sockfd == it.first)
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
    Context* bind_context = TCPAssignment::contextList[pid][sockfd];
    bind_context->local_ip_address = new_ip_address;
    bind_context->local_port = new_port;
    bind_context->isBound = true;

    return 0;
}

int TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int success = -1;
    Context* c = TCPAssignment::contextList[pid][sockfd];

    /* Check for valid fd */
    if (c == NULL) return -1;

    if (c->isBound)
    {
        struct sockaddr_in socket_name;
        memset(&socket_name, 0, sizeof socket_name);
        socket_name.sin_family = AF_INET;
        socket_name.sin_addr.s_addr = c->local_ip_address;
        socket_name.sin_port = c->local_port;
        int size_minimum = (sizeof(struct sockaddr_in) < *addrlen)? sizeof(struct sockaddr_in) : *addrlen;
        memcpy(addr, &socket_name, size_minimum);
        *addrlen = size_minimum;
        success = 0;
    }
    return success;
}

int TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd)
{
    Context* context = TCPAssignment::contextList[pid][fd];
    if (context == NULL) return -1; 
    //close called at valid state
    if (context->state == TCPAssignment::State::FIN_WAIT_1 ||
        context->state == TCPAssignment::State::FIN_WAIT_2 ||
        context->state == TCPAssignment::State::CLOSING ||
        context->state == TCPAssignment::State::LAST_ACK ||
        context->state == TCPAssignment::State::TIMED_WAIT) return -1;
    //Sending close signal
    if (context->state == TCPAssignment::State::SYN_SENT ||
        context->state == TCPAssignment::State::CLOSED ||
        context->state == TCPAssignment::State::LISTEN)
    {
        closeSocket(pid, fd);
        return 0;
    }
    Packet* finPacket = allocatePacket(SIZE_EMPTY_PACKET);
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned short src_port;
    unsigned short dest_port;

    src_ip = context->local_ip_address;
    src_port = context->local_port;
    dest_ip = context->remote_ip_address;
    dest_port = context->remote_port;

    char size = 5;
    char syn = FLAG_FIN;
    short window_size = htons(51200);
    unsigned int* seq_number = &(context->seq_number);
    TCPAssignment::fill_packet_header(finPacket, src_ip, dest_ip, src_port, dest_port, size, syn, window_size, *seq_number);
    TCPAssignment::packet_fill_checksum(finPacket);

    this->sendPacket("IPv4", finPacket);

    
    //updating contextList information
    context->syscall_hold_ID = syscallUUID;
    *seq_number = htonl(ntohl(*seq_number) + 1);
    if (context->state == TCPAssignment::State::ESTABLISHED || context->state == TCPAssignment::State::SYN_RCVD)
        context->state = TCPAssignment::State::FIN_WAIT_1;
    else if(context->state == TCPAssignment::State::CLOSE_WAIT)
        context->state = TCPAssignment::State::LAST_ACK;    
    /*if (context->backlog_size > 0)
    {
        free(context->backlog);
    }
    free(context);  
    for (auto aw : TCPAssignment::accept_waiting_lists[pid][fd])
    {
        free(aw);
    }
    for (auto blg : TCPAssignment::established_backlog_lists[pid][fd])
    {
        free(blg);
    }*/
    return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    /* Check for valid fd */
    if (TCPAssignment::contextList[pid][sockfd] == NULL) return -1;

    Packet* synPacket = allocatePacket(SIZE_EMPTY_PACKET);
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned short src_port;
    unsigned short dest_port;

    dest_ip = ((struct sockaddr_in*)addr)->sin_addr.s_addr;
    dest_port = ((struct sockaddr_in*)addr)->sin_port;
    bool success_retrive_src = false;
    /* If the local socket fd is already bound to some port, we don't need to do implicit bind. */
    if (TCPAssignment::contextList[pid][sockfd]->isBound)
    {
        src_ip = TCPAssignment::contextList[pid][sockfd]->local_ip_address;
        src_port = TCPAssignment::contextList[pid][sockfd]->local_port;
        success_retrive_src = true;
    }
    /* Otherwise, we assign random port number and bind implicitly. */
    while (!success_retrive_src)
    {
        src_port = htons(rand() % 40000 + 2000);
        int interface_number = HostModule::getHost()->getRoutingTable((const uint8_t *)&dest_ip);
        bool ip_retrived = HostModule::getHost()->getIPAddr((uint8_t*)&src_ip, interface_number);
        if (!ip_retrived) {
            break;
        }

        struct sockaddr_in socket_name;
        memset(&socket_name, 0, sizeof socket_name);
        socket_name.sin_family = AF_INET;
        socket_name.sin_addr.s_addr = src_ip;
        socket_name.sin_port = src_port;
        int success_bind = TCPAssignment::syscall_bind(syscallUUID, pid, sockfd, (struct sockaddr*)&socket_name, sizeof(socket_name));
        if (success_bind == 0)
        {
            success_retrive_src = true;
            break;
        }
    }
    /* Implicit bind fail - shouldn't happen */
    if (!success_retrive_src)
    {
        return -1;
    }

    Context* context = TCPAssignment::contextList[pid][sockfd];

    /* Setup header fields */
    char size = 5;
    char syn = FLAG_SYN;
    short window_size = htons(51200);
    unsigned int* seq_number = &(context->seq_number);
    /* Fill packet header and checksum */
    TCPAssignment::fill_packet_header(synPacket, src_ip, dest_ip, src_port, dest_port, size, syn, window_size, *seq_number);
    TCPAssignment::packet_fill_checksum(synPacket);
    /* This seq_number belongs to this context - so we increment it by 1. */
    *seq_number = htonl(ntohl(*seq_number) + 1);

    /* Store syscallUUID to return this system call after SYN/ACK arrives */
    context->syscall_hold_ID = syscallUUID;
    context->state = TCPAssignment::State::SYN_SENT;
    context->remote_ip_address = dest_ip;
    context->remote_port = dest_port;
	
    this->sendPacket("IPv4", synPacket);

    return 0;
}
int TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
    /* Check for valid fd */
    Context* context = TCPAssignment::contextList[pid][sockfd];
    if (context == NULL) return -1;
    if (context->state != TCPAssignment::State::CLOSED) return -2;

    context->backlog_size = backlog;
    context->backlog = (Backlog*) malloc (sizeof(Backlog) * backlog);
    //context->backlog_mutex.lock();

    for (int i=0; i<context->backlog_size; i++)
    {
        context->backlog[i].in_use = false;
    }

    std::list<AcceptWaiting*> awl;
    TCPAssignment::accept_waiting_lists[pid][sockfd] = awl;
    std::list<Backlog*> blgl;
    TCPAssignment::established_backlog_lists[pid][sockfd] = blgl;
    context->state = TCPAssignment::State::LISTEN;

    return 0;
}

int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    Context* c = TCPAssignment::contextList[pid][sockfd];
    if (c == NULL) return -1;
    if (c->state != TCPAssignment::State::LISTEN) return -1;

    // Find established backlog
    if (TCPAssignment::established_backlog_lists[pid][sockfd].empty())
    {
        AcceptWaiting* aw = (AcceptWaiting*) malloc (sizeof (AcceptWaiting));
        aw->syscallUUID = syscallUUID;
        aw->pid = pid;
        aw->sockfd = sockfd;
        aw->addr = addr;
        aw->addrlen = addrlen;
        TCPAssignment::accept_waiting_lists[pid][sockfd].push_back(aw);
        return -2;
    }

    Backlog* backlog = TCPAssignment::established_backlog_lists[pid][sockfd].front();
    TCPAssignment::established_backlog_lists[pid][sockfd].pop_front();

    return TCPAssignment::return_syscall_accept(syscallUUID, pid, sockfd, addr, addrlen, c, backlog);
    //return this->createFileDescriptor(pid);
}

int TCPAssignment::return_syscall_accept
(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen, Context* c, Backlog* b)
{
    int new_fd = this->createFileDescriptor(pid);
    Context* new_context = (Context*) malloc (sizeof(Context));
    new_context->local_ip_address = c->local_ip_address;
    new_context->local_port = c->local_port;
    new_context->remote_ip_address = b->remote_ip_address;
    new_context->remote_port = b->remote_port;
    new_context->seq_number = b->seq_number;
    new_context->state = TCPAssignment::State::ESTABLISHED;
    new_context->isBound = true;
    new_context->syscall_hold_ID = 0;
    new_context->backlog_size = 0;
    TCPAssignment::contextList[pid][new_fd] = new_context;

    int ret = TCPAssignment::syscall_getpeername(syscallUUID, pid, new_fd, addr, addrlen);
    if (ret < -1) // shouldn't happen
    {
        this->removeFileDescriptor(pid, new_fd);
        return -1;
    } 
    
    free(b);
    return new_fd;
}


int TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int success = -1;
    Context* c = TCPAssignment::contextList[pid][sockfd];
    if (c == NULL) return -1;
    if (c->isBound)
    {
        struct sockaddr_in socket_name;
        memset(&socket_name, 0, sizeof socket_name);
        socket_name.sin_family = AF_INET;
        socket_name.sin_addr.s_addr = c->remote_ip_address;
        socket_name.sin_port = c->remote_port;
        int size_minimum = (sizeof(struct sockaddr_in) < *addrlen)? sizeof(struct sockaddr_in) : *addrlen;
        memcpy(addr, &socket_name, size_minimum);
        *addrlen = size_minimum;
        success = 0;
    }
    return success;
}
/* Iterate through context list and find the context with given parameters. */
bool TCPAssignment::retrieve_fd_from_context(unsigned int local_ip_address, unsigned short local_port,
        unsigned int remote_ip_address, unsigned short remote_port, int* pid, int* fd)
{
    for (auto it : TCPAssignment::contextList)
    {
        for (auto it2 : it.second)
        {
            Context* c = it2.second;
            if ((c->remote_ip_address == remote_ip_address) &&
                (c->remote_port == remote_port) &&
                (c->local_ip_address == local_ip_address || c->local_ip_address == htonl(INADDR_ANY)) &&
                (c->local_port == local_port))
            {
                *pid = it.first;
                *fd = it2.first;
                return true;
            }
        }
    }
    return false;
}

/* Overloaded function with above - with less parameters */
bool TCPAssignment::retrieve_fd_from_context(unsigned int local_ip_address, unsigned short local_port,
    int* pid, int* fd)
{
    for (auto it : TCPAssignment::contextList)
    {
        for (auto it2 : it.second)
        {
            Context* c = it2.second;
            if ((c->local_ip_address == local_ip_address || c->local_ip_address == htonl(INADDR_ANY)) &&
                (c->local_port == local_port))
            {
                *pid = it.first;
                *fd = it2.first;
                return true;
            }
        }
    }
    return false;
}

void TCPAssignment::packet_fill_checksum(Packet* packet)
{
    int length = packet->getSize();
    short data_length = (short)(length - 34);

    unsigned short pseudo_header_checksum = data_length + 6;

    unsigned long sum = pseudo_header_checksum;
    int i;

    unsigned short word16 = 0;
    for (i = 0; i < length-1; i += 2) {
        packet->readData(i, &word16, 2);
        sum += ntohs(word16);
    }
    if (length & 1) {
        char word8 = 0;
        packet->readData(i, &word8, 1);
        sum += word8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }

    unsigned short checksum = (unsigned short) ~sum;
    checksum = htons(checksum);
    packet->writeData(PACKETLOC_CHKSUM, &checksum, 2);
}

void TCPAssignment::fill_packet_header(Packet* packet, unsigned int src_ip, unsigned int dest_ip,
        unsigned short src_port, unsigned short dest_port, char size, char syn, short window_size,
        unsigned int seq_number)
{
    packet->writeData(PACKETLOC_SRC_IP, &src_ip, 4);
    packet->writeData(PACKETLOC_DEST_IP, &dest_ip, 4);
    packet->writeData(PACKETLOC_SRC_PORT, &src_port, 2);
    packet->writeData(PACKETLOC_DEST_PORT, &dest_port, 2);

    /* Mark size field */
    size = size << 4;
    packet->writeData(PACKETLOC_TCP_HEADER_SIZE, &size, 1);
    /* Mark syn flag */
    packet->writeData(PACKETLOC_TCP_FLAGS, &syn, 1);
    /* Mark window size */
    packet->writeData(PACKETLOC_WINDOWSIZE, &window_size, 2);
    /* Mark seq number */
    packet->writeData(PACKETLOC_SEQNO, &seq_number, 4);
}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
    // Using packet header, find matching context's fd.
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned short src_port;
    unsigned short dest_port;
    packet->readData(PACKETLOC_SRC_IP, &src_ip, 4);
    packet->readData(PACKETLOC_DEST_IP, &dest_ip, 4);
    packet->readData(PACKETLOC_SRC_PORT, &src_port, 2);
    packet->readData(PACKETLOC_DEST_PORT, &dest_port, 2);

    char flag;
    packet->readData(PACKETLOC_TCP_FLAGS, &flag, 1);

    // 1. Return from connect (While we are client and in SYN_SENT state, received SYNACK packet)
    if (flag == FLAG_SYNACK)
    {
        int pid = -1;
        int fd = -1;
        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, src_ip, src_port, &pid, &fd);
        if (!suc)
        {
            freePacket(packet);
            return;
        }
        Context* c = TCPAssignment::contextList[pid][fd];
        if (c->state == TCPAssignment::State::SYN_SENT)
        {
            // Send ACK in response.
            Packet* newPacket = this->allocatePacket(54);
            unsigned int* seq_number = &(c->seq_number);
            TCPAssignment::fill_packet_header(newPacket, dest_ip, src_ip, dest_port, src_port,
                5, FLAG_ACK, htons(51200), *seq_number);
            //*seq_number = htonl(ntohl(*seq_number) + 1);
            /* Ack number is manually written on header */
            unsigned int ack_number;
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number = htonl(ntohl(ack_number) + 1);
            newPacket->writeData(PACKETLOC_ACKNO, &ack_number, 4);
            /* Make sure to fill checksum AFTER ack number is filled in. */
            TCPAssignment::packet_fill_checksum(newPacket);
            this->sendPacket("IPv4", newPacket);
            c->state = TCPAssignment::State::ESTABLISHED;
            this->returnSystemCall(c->syscall_hold_ID, 0);
        }
    }

    // 2. As a server, when we receive SYN, send SYN/ACK and change our state.
    else if (flag == FLAG_SYN)
    {
        int pid, fd;
        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, &pid, &fd);
        if (!suc) 
        {
            freePacket(packet);
            return;
        }
        Context* c = TCPAssignment::contextList[pid][fd];
        if (c->state == TCPAssignment::State::LISTEN)
        {
            // Find the empty backlog space
            int i;
            for (i=0; i<c->backlog_size; i++)
            {
                if (!c->backlog[i].in_use) break;
            }
            if (i != c->backlog_size)
            {
                // Empty spot is found (i), use this place.
                Backlog* backlog = &(c->backlog[i]);
                backlog->remote_ip_address = src_ip;
                backlog->remote_port = src_port;
                backlog->state = TCPAssignment::State::SYN_RCVD;
                backlog->in_use = true;

                // Send SYNACK in response.
                Packet* newPacket = this->allocatePacket(54);
                unsigned int seq_number = backlog->seq_number = SEQ_NUMBER_START;
                TCPAssignment::fill_packet_header(newPacket, dest_ip, src_ip, dest_port, src_port,
                    5, FLAG_SYNACK, htons(51200), seq_number);
                backlog->seq_number = htonl(ntohl(seq_number) + 1);
                /* Ack number is manually written on header */
                unsigned int ack_number;
                packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
                ack_number = htonl(ntohl(ack_number) + 1);
                newPacket->writeData(PACKETLOC_ACKNO, &ack_number, 4);
                /* Make sure to fill checksum AFTER ack number is filled in. */
                TCPAssignment::packet_fill_checksum(newPacket);
                this->sendPacket("IPv4", newPacket);
            }
        }
    }

    // 3. From the server, when we receive ACK while we are SYN_RCVD state, we are connected.
    // In 4-way handshaking, receiving ACK while in FIN_WAIT or CLOSING, we are closing connection
    else if (flag == FLAG_ACK)
    {
        int pid, fd;
        
        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, &pid, &fd);

        if (!suc)
        {
            freePacket(packet);
            return;
        }
        Context* c = TCPAssignment::contextList[pid][fd];
        if (c->state == TCPAssignment::State::LISTEN)
        {
            // Find the matching backlog space
            int i;
            for (i=0; i<c->backlog_size; i++)
            {
                if (c->backlog[i].in_use && c->backlog[i].remote_ip_address == src_ip &&
                    c->backlog[i].remote_port == src_port)
                {
                    break;
                }
            }
            if (i != c->backlog_size)
            {
                // Matching backlog is found. Check its state.
                Backlog* backlog = &(c->backlog[i]);
                if (backlog->state == TCPAssignment::State::SYN_RCVD)
                {
                    /* Move this backlog to established backlog. */
                    Backlog* estab_bg = (Backlog*) malloc (sizeof(Backlog));
                    estab_bg->remote_ip_address = backlog->remote_ip_address;
                    estab_bg->remote_port = backlog->remote_port;
                    estab_bg->seq_number = backlog->seq_number;
                    estab_bg->state = TCPAssignment::State::ESTABLISHED;
                    TCPAssignment::established_backlog_lists[pid][fd].push_back(estab_bg);
                    backlog->in_use = false;
                    /* If there's any waiting accepts, return this. */
                    if (!TCPAssignment::accept_waiting_lists[pid][fd].empty())
                    {
                        AcceptWaiting* aw = TCPAssignment::accept_waiting_lists[pid][fd].front();
                        UUID syscallUUID = aw->syscallUUID;
                        int waiting_pid = aw->pid;
                        int waiting_fd = aw->sockfd;
                        struct sockaddr *addr = aw->addr;
                        socklen_t *addrlen = aw->addrlen;
                        int new_fd = TCPAssignment::return_syscall_accept(syscallUUID, waiting_pid, waiting_fd, addr, addrlen, c, estab_bg);
                        if (new_fd != -2)
                        {
                            this->returnSystemCall(syscallUUID, new_fd);
                            TCPAssignment::established_backlog_lists[pid][fd].pop_front();
                            TCPAssignment::accept_waiting_lists[pid][fd].pop_front();
                        }
                        free(aw);
                    }
                }
            }
        }
        /*Get Ack in CLOSING State -> 4-way handshaking is done in starting host. We send ACK, and wait
        for 2*MSL*/
		else if (c->state == TCPAssignment::State::CLOSING)
        {
            //Sends ACK
            //State becomes TIMED_WAIT;
            Time msl = TimeUtil::makeTime(MSL, TimeUtil::TimeUnit::SEC);
            UUID timeUUID = TimerModule::addTimer((void* )packet, 2*msl);
            c->state = TCPAssignment::State::TIMED_WAIT;
            c->timer_ID=timeUUID;
        }
        //Get Ack in FIN_WAIT_1 state -> simply changes the state into FIN_WAIT_2
        else if (c->state == TCPAssignment::State::FIN_WAIT_1)
        {
            c->state=TCPAssignment::State::FIN_WAIT_2;
        }
        //Get Ack in LAST_ACK state -> Ends connection in passive side, remove backlog&established, but do not remove context
        else if (c->state == TCPAssignment::State::LAST_ACK)
        {
            TCPAssignment::closeSocket(pid, fd);
        }
    }

    // 4. Receiving FIN means we are in 4-way handshaking(Finishing Connection)
    else if (flag == FLAG_FIN)
    {
        //printf("I got FIN");
        int pid, fd;

        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, &pid, &fd);

        if (!suc)
        {
            //printf("Can't find pid/fd pair. try again\n");
            freePacket(packet);
            return;
        }
        Context* c = TCPAssignment::contextList[pid][fd];
        //Passive Closing. Send ACK, and wait for change State into CLOSE_WAIT
        if (c->state == TCPAssignment::State::ESTABLISHED)
        {
            //Sends ACK
            printf("Why do you close???");
            Packet* newPacket = this->allocatePacket(SIZE_EMPTY_PACKET);
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            TCPAssignment::fill_packet_header(newPacket, dest_ip, src_ip, dest_port, src_port, 5,
                FLAG_ACK, htons(51200), *seq_number);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);
            newPacket->writeData(PACKETLOC_ACKNO, &ack_number, 4);
            this->sendPacket("IPv4", newPacket);

            //Change the state into CLOSE_WAIT;
			c->state = TCPAssignment::State::CLOSE_WAIT;
        }
        //Simultaneous Closing. Send ACK, and change State into CLOSING 
        else if (c->state == TCPAssignment::State::FIN_WAIT_1)
        {
            //Sends ACK
            printf("Simultaneous close");
            Packet* newPacket = this->allocatePacket(SIZE_EMPTY_PACKET);
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            TCPAssignment::fill_packet_header(newPacket, dest_ip, src_ip, dest_port, src_port, 5,
                FLAG_ACK, htons(51200), *seq_number);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);
            newPacket->writeData(PACKETLOC_ACKNO, &ack_number, 4);
            this->sendPacket("IPv4", newPacket);

            //Change the state into CLOSING
            c->state = TCPAssignment::State::CLOSING;
        }
        //third handshake. Receiver sent all of its remaining packets. Change State into LAST_ACK
        else if (c->state == TCPAssignment::State::FIN_WAIT_2)
        {
            printf("Last Ack. No turning back");
            //Sending ACK packet
            Packet* newPacket = this->allocatePacket(SIZE_EMPTY_PACKET);
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            TCPAssignment::fill_packet_header(newPacket, dest_ip, src_ip, dest_port, src_port, 5,
                FLAG_ACK, htons(51200), *seq_number);
//            *seq_number = htonl(ntohl(*seq_number)+1);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);
            newPacket->writeData(PACKETLOC_ACKNO, &ack_number, 4);
            this->sendPacket("IPv4", newPacket);

            //Change the state into TIMED_WAIT;
            Time msl = TimeUtil::makeTime(MSL, TimeUtil::TimeUnit::SEC);
            UUID timeUUID = TimerModule::addTimer((void* )newPacket, 2*msl);
            c->state = TCPAssignment::State::TIMED_WAIT;
            c->timer_ID=timeUUID;
        }
    }
    // 5. As an active closing host, we can possibly get signal FIN/ACK
    else if (flag == FLAG_FINACK)
    {
        int pid, fd;
        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, &pid, &fd);
        if (!suc)
        {
            freePacket(packet);
            return;
        }
        Context* c = TCPAssignment::contextList[pid][fd];
        //Received FINACK in FIN_WAIT_1 state, then simultaneously ends connection. Send ACK
        if (c->state == TCPAssignment::State::FIN_WAIT_1)
        {
            //Sending ACK packet
            Packet* newPacket = this->allocatePacket(SIZE_EMPTY_PACKET);
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            TCPAssignment::fill_packet_header(newPacket, dest_ip, src_ip, dest_port, src_port, 5,
                FLAG_ACK, htons(51200), *seq_number);
  //          *seq_number = htonl(ntohl(*seq_number)+1);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);
            newPacket->writeData(PACKETLOC_ACKNO, &ack_number, 4);
            this->sendPacket("IPv4", newPacket);

            //Change the state into TIMED_WAIT;
            Time msl = TimeUtil::makeTime(MSL, TimeUtil::TimeUnit::SEC);
            UUID timeUUID = TimerModule::addTimer((void* )newPacket, 2*msl);
            c->state = TCPAssignment::State::TIMED_WAIT;
            c->timer_ID=timeUUID;
        }
    }
    freePacket(packet);
    return;
}

void TCPAssignment::closeSocket(unsigned int pid, unsigned int fd)
{
/*    Context* context = TCPAssignment::contextList[pid][fd];
    if (context->backlog_size > 0)
    {
        free(context->backlog);
    }
    for (auto aw : TCPAssignment::accept_waiting_lists[pid][fd])
    {
        free(aw);
    }
    for (auto blg : TCPAssignment::established_backlog_lists[pid][fd])
    {
        free(blg);
    }*/
    TCPAssignment::contextList[pid].erase(fd);
    TCPAssignment::accept_waiting_lists[pid].erase(fd);
    TCPAssignment::established_backlog_lists[pid].erase(fd);
    SystemCallInterface::removeFileDescriptor(pid, fd);
//    free(context);
}

void TCPAssignment::timerCallback(void* payload)
{
    //What should we do when alarm is triggered
    //When state == TIMED_WAIT -> Free fd, change context state into Closed
    //payload should be our packet itself
    //Extract fd and pid from our packet information
    Packet* packet = (Packet* )payload;
    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned short src_port;
    unsigned short dest_port;
    packet->readData(PACKETLOC_SRC_IP, &src_ip, 4);
    packet->readData(PACKETLOC_DEST_IP, &dest_ip, 4);
    packet->readData(PACKETLOC_SRC_PORT, &src_port, 2);
    packet->readData(PACKETLOC_DEST_PORT, &dest_port, 2);
    int pid, fd;
    bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, &pid, &fd);
    if (!suc)
    {
        freePacket(packet);
        return;
    }
    //After extracting informations, removing fd/pid pair from contextList/backlog/established
    TCPAssignment::closeSocket(pid, fd);
}


}
