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
        if (ret != -2) {
            this->returnSystemCall(syscallUUID, ret);
        }
        break;
    case READ:
        ret = this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        if (ret != -2) {
            this->returnSystemCall(syscallUUID, ret);
        }
        break;
    case WRITE:
        ret = this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        if (ret != -2) {
            this->returnSystemCall(syscallUUID, ret);
        }
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
    Context* context = TCPAssignment::create_new_context
            (0, 0, 0, 0, SEQ_NUMBER_START, 0, TCPAssignment::State::CLOSED, false, 0, 0, 0);
    TCPAssignment::contextList[pid][new_fd] = context;
    return new_fd;
}

TCPAssignment::Context* TCPAssignment::create_new_context
(unsigned int local_ip_address, unsigned short local_port, unsigned int remote_ip_address, unsigned short remote_port,
unsigned int seq_number, unsigned int ack_number, State state, bool isBound, UUID syscall_hold_ID, UUID timer_ID, 
int backlog_size)
{
    Context* new_context = (Context*) malloc (sizeof(Context));
    new_context->local_ip_address = local_ip_address;
    new_context->local_port = local_port;
    new_context->remote_ip_address = remote_ip_address;
    new_context->remote_port = remote_port;
    new_context->seq_number = seq_number;
    new_context->ack_number = ack_number;
    new_context->state = state;
    new_context->isBound = isBound;
    new_context->syscall_hold_ID = syscall_hold_ID;
    new_context->timer_ID = timer_ID;
    new_context->backlog_size = backlog_size;
    new_context->isClosing = false;
    new_context->send_buffer = new Buffer();
    new_context->recv_buffer = new Buffer();
    new_context->btsyscall = new BlockedTransferSyscall();
    new_context->rwnd = BUFFER_SIZE;

    new_context->cwnd = MAX_DATA_FIELD_SIZE;
    new_context->dup_ack_count = 0;
    new_context->ssthresh = 64000;
    new_context->congestion_state = CONG_SLOW_START;
    new_context->last_ack_number = 0;
    return new_context;
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
    Packet *FinPacket;
    Packet *copyPacket;
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

    unsigned int src_ip;
    unsigned int dest_ip;
    unsigned short src_port;
    unsigned short dest_port;

    src_ip = context->local_ip_address;
    if (src_ip == 0)
    {
        int interface_number = HostModule::getHost()->getRoutingTable((const uint8_t *)&dest_ip);
        bool ip_retrived = HostModule::getHost()->getIPAddr((uint8_t*)&src_ip, interface_number);
        if (!ip_retrived) {
            return -1;
        }
    }
    
    src_port = context->local_port;
    dest_ip = context->remote_ip_address;
    dest_port = context->remote_port;

    if (context->send_buffer->size + find_length_of_unacked_packets(pid, fd) > 0)
    {
        context->btsyscall->set_fields(TRANSFER_CLOSE, syscallUUID, NULL, 0);
        return -2;
    }

    unsigned int* seq_number = &(context->seq_number);
    FinPacket = TCPAssignment::sendNewPacket(src_ip, src_port, dest_ip, dest_port, *seq_number, 
        0, 5, FLAG_FIN, htons(51200), 0, NULL, true);
    copyPacket = this->clonePacket(FinPacket);
    Time msl = TimeUtil::makeTime(RTO, TimeUtil::TimeUnit::MSEC);
    UUID timeUUID = TimerModule::addTimer((void*)copyPacket, msl);
    context->timer_ID = timeUUID;
    context->isClosing = true;
    context->timer_on = true;
    this->sendPacket("IPv4", FinPacket);
    //printf("FIN packet reaaaaally ssent. (port: %d)\n", ntohs(context->remote_port));
    //updating contextList information
    context->syscall_hold_ID = syscallUUID;
    *seq_number = htonl(ntohl(*seq_number) + 1);
    if (context->state == TCPAssignment::State::ESTABLISHED || context->state == TCPAssignment::State::SYN_RCVD)
        context->state = TCPAssignment::State::FIN_WAIT_1;
    else if(context->state == TCPAssignment::State::CLOSE_WAIT)
        context->state = TCPAssignment::State::LAST_ACK;
    return 0;
}

int TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    /* Check for valid fd */
    if (TCPAssignment::contextList[pid][sockfd] == NULL) return -1;

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

    unsigned int* seq_number = &(context->seq_number);
    TCPAssignment::sendNewPacket(src_ip, src_port, dest_ip, dest_port, *seq_number, 
        0, 5, FLAG_SYN, htons(51200), 0, NULL, false);
    *seq_number = htonl(ntohl(*seq_number) + 1);

    /* Store syscallUUID to return this system call after SYN/ACK arrives */
    context->syscall_hold_ID = syscallUUID;
    context->state = TCPAssignment::State::SYN_SENT;
    context->remote_ip_address = dest_ip;
    context->remote_port = dest_port;

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
    Context* context = TCPAssignment::create_new_context
            (c->local_ip_address, c->local_port, b->remote_ip_address, b->remote_port, b->seq_number, b->ack_number,
            b->state, true, 0, 0, 0);
    TCPAssignment::contextList[pid][new_fd] = context;

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

TCPAssignment::Buffer::Buffer()
{
    this->bufptr = (char*) malloc (BUFFER_SIZE);
    this->start_index = this->end_index = 0;
    this->size = 0;
    this->capacity = BUFFER_SIZE;
}

int TCPAssignment::Buffer::write_buf(const char* srcbuf, size_t count)
{
    int srcbuf_index = 0;
    while ((this->capacity > this->size) && (srcbuf_index < count)) {
        this->bufptr[this->end_index] = srcbuf[srcbuf_index];
        this->end_index = (this->end_index + 1) % capacity;
        srcbuf_index++;
        (this->size)++;
    }
    return srcbuf_index;
}

int TCPAssignment::Buffer::read_buf(char* destbuf, size_t count)
{
    int destbuf_index = 0;
    while ((this->size > 0) && (destbuf_index < count)) {
        destbuf[destbuf_index] = this->bufptr[this->start_index];
        this->start_index = (this->start_index + 1) % capacity;
        destbuf_index++;
        (this->size)--;
    }
    return destbuf_index;
}

TCPAssignment::BlockedTransferSyscall::BlockedTransferSyscall()
{
    this->is_blocked = false;
    this->transfer_type = TRANSFER_WRITE;
    this->syscall_hold_ID = 0;
    this->buf = NULL;
    this->count = 0;
}

void TCPAssignment::BlockedTransferSyscall::set_fields(int ttype, UUID sID, char* buf, size_t count)
{
    this->is_blocked = true;
    this->transfer_type = ttype;
    this->syscall_hold_ID = sID;
    this->buf = buf;
    this->count = count;
}

void TCPAssignment::release_blocked_write(int pid, int fd)
{
    Context* c = TCPAssignment::contextList[pid][fd];
    if (c->btsyscall->is_blocked && c->btsyscall->transfer_type == TRANSFER_WRITE) {
        BlockedTransferSyscall* bts = c->btsyscall;
        int written_bytes = TCPAssignment::syscall_write(bts->syscall_hold_ID, pid, fd, bts->buf, bts->count);
        this->returnSystemCall(bts->syscall_hold_ID, written_bytes);
        bts->is_blocked = false;
    }
}

void TCPAssignment::retransmit_first_unacked_packet(int pid, int fd)
{    
    int count = 0;
    for (auto it : TCPAssignment::send_window_lists[pid][fd])
    {
        Packet* cloned = this->clonePacket(it->packet);
        unsigned int seq_number;
        cloned->readData(PACKETLOC_SEQNO, &seq_number, 4);
        this->sendPacket("IPv4", cloned);
        count++;
        //if (count > 15) break;
    }
}

int TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count)
{
    Context* c = TCPAssignment::contextList[pid][fd];
    if (c == NULL) return -1;

    Buffer* send_buffer = c->send_buffer;
    int buf_remaining_size = BUFFER_SIZE - send_buffer->size - find_length_of_unacked_packets(pid, fd);
    if (buf_remaining_size == 0) {
        c->btsyscall->set_fields(TRANSFER_WRITE, syscallUUID, (char*) buf, count);
        return -2;
    }

    int buf_can_be_written = (count < buf_remaining_size)? count : buf_remaining_size;
    int buf_written = send_buffer->write_buf((const char*) buf, buf_can_be_written);
    assert(buf_can_be_written == buf_written);
    create_data_packets_and_send(pid, fd);
    return buf_written;
}

int TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count)
{
    Context* c = TCPAssignment::contextList[pid][fd];
    if (c == NULL) return -1;

    Buffer* recv_buffer = c->recv_buffer;


    if (recv_buffer->size == 0) {
        if (c->state == TCPAssignment::State::CLOSE_WAIT) {
            return -1;
        }
        c->btsyscall->set_fields(TRANSFER_READ, syscallUUID, (char*) buf, count);
        return -2;
    }
    

    int buf_read = recv_buffer->read_buf((char*) buf, count);
    assert(buf_read <= count);

    return buf_read;
}

void TCPAssignment::create_data_packets_and_send(int pid, int fd)
{
    Context* c = TCPAssignment::contextList[pid][fd];
    if (c == NULL) return;

    Buffer* send_buffer = c->send_buffer;
    int unacked_data_length = find_length_of_unacked_packets(pid, fd);
    if (c->cwnd < MAX_DATA_FIELD_SIZE) c->cwnd = MAX_DATA_FIELD_SIZE;
    int window_size_limit = (c->rwnd < c->cwnd)? c->rwnd : c->cwnd;
    int remaining_window = window_size_limit - unacked_data_length;

    unsigned int src_ip = c->local_ip_address;
    unsigned int dest_ip = c->remote_ip_address;
    unsigned short src_port = c->local_port;
    unsigned short dest_port = c->remote_port;

    if (src_ip == 0)
    {
        int interface_number = HostModule::getHost()->getRoutingTable((const uint8_t *)&dest_ip);
        bool ip_retrived = HostModule::getHost()->getIPAddr((uint8_t*)&src_ip, interface_number);
        if (!ip_retrived) {
            return;
        }
    }

    while (remaining_window > 511 && send_buffer->size > 511)
    {
        int new_packet_data_length = MAX_DATA_FIELD_SIZE;

        char* payload = (char*) malloc (new_packet_data_length);
        send_buffer->read_buf(payload, new_packet_data_length);

        Packet* newPacket = TCPAssignment::sendNewPacket(src_ip, src_port, dest_ip, dest_port,
            c->seq_number, c->ack_number, 5, FLAG_ACK, htons(c->rwnd), new_packet_data_length, payload, true);
        free(payload);

        if (c->timer_on == false)
        {
            Packet* copyPacket = this->clonePacket(newPacket);
            Time msl = TimeUtil::makeTime(200, TimeUtil::TimeUnit::MSEC);
            UUID timeUUID = TimerModule::addTimer((void* )copyPacket, msl);
            c->timer_on = true;
            c->timer_ID=timeUUID;
        }

        Window* window = (Window*) malloc (sizeof(Window));
        window->currentTime = this->getHost()->getSystem()->getCurrentTime();
        window->packet = newPacket;
        TCPAssignment::send_window_lists[pid][fd].push_back(window);

        Packet* cloned = this->clonePacket(newPacket);
        this->sendPacket("IPv4", cloned);

        c->seq_number = htonl(ntohl(c->seq_number) + new_packet_data_length);
        remaining_window -= newPacket->getSize() - SIZE_EMPTY_PACKET;
    }
    return;
}

int TCPAssignment::find_length_of_unacked_packets(int pid, int fd)
{
    int sum_length = 0;
    for (auto it : TCPAssignment::send_window_lists[pid][fd])
    {
        sum_length += it->packet->getSize() - SIZE_EMPTY_PACKET;
    }
    return sum_length;
}

int TCPAssignment::find_length_of_out_of_order_packets(int pid, int fd)
{
    int sum_length = 0;
    for (auto it : TCPAssignment::recv_packet_lists[pid][fd])
    {
        sum_length += it->getSize() - SIZE_EMPTY_PACKET;
    }
    return sum_length;
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
                (c->local_port == local_port) &&
                (c->state == TCPAssignment::State::LISTEN))
            {
                *pid = it.first;
                *fd = it2.first;
                return true;
            }
        }
    }
    return false;
}

bool TCPAssignment::retrieve_backlog_when_FIN (unsigned int remote_ip_address, unsigned short remote_port, Backlog** bg)
{
    for (auto it : TCPAssignment::established_backlog_lists)
    {
        for (auto it2 : it.second)
        {
            std::list<Backlog*> c = it2.second;
            for (auto it3 : c)
            {
                if ((it3->remote_ip_address == remote_ip_address || it3->remote_ip_address == htonl(INADDR_ANY)) &&
                    (it3->remote_port == remote_port))
                {
                    *bg = it3;
                    return true;
                }
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

void TCPAssignment::fill_packet_header(Packet* packet, unsigned int src_ip, unsigned short src_port,
        unsigned int dest_ip, unsigned short dest_port, char size, char syn, short window_size,
        unsigned int seq_number, unsigned int ack_number)
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
    packet->writeData(PACKETLOC_ACKNO, &ack_number, 4);
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
            unsigned int* seq_number = &(c->seq_number);
            unsigned int ack_number;
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number = htonl(ntohl(ack_number) + 1);
            c->ack_number = ack_number;

            TCPAssignment::sendNewPacket(dest_ip, dest_port, src_ip, src_port, 
                *seq_number, ack_number, 5, FLAG_ACK, htons(51200), 0, NULL, false);

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
                unsigned int seq_number = backlog->seq_number = SEQ_NUMBER_START;
                backlog->seq_number = htonl(ntohl(seq_number) + 1);
                /* Ack number is manually written on header */
                unsigned int ack_number;
                packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
                ack_number = htonl(ntohl(ack_number) + 1);
                backlog->ack_number = ack_number;

                TCPAssignment::sendNewPacket(dest_ip, dest_port, src_ip, src_port, seq_number, ack_number,
                    5, FLAG_SYNACK, htons(51200), 0, NULL, false);
            }
        }
    }
    

    // 3. From the server, when we receive ACK while we are SYN_RCVD state, we are connected.
    // In 4-way handshaking, receiving ACK while in FIN_WAIT or CLOSING, we are closing connection
    else if (flag == FLAG_ACK)
    {
        int pid, fd;
        Context* c;
        
        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, src_ip, src_port, &pid, &fd);

        if (!suc)
        {
            bool suc2 = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, &pid, &fd);
            if (!suc2)
            {
                freePacket(packet);
                return;
            }
            c = TCPAssignment::contextList[pid][fd];
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
                        estab_bg->ack_number = backlog->ack_number;
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

            freePacket(packet);
            return;
        }

        c = TCPAssignment::contextList[pid][fd];
        unsigned int ack_number;
        packet->readData(PACKETLOC_ACKNO, &ack_number, 4);

        /*Get Ack in CLOSING State -> 4-way handshaking is done in starting host. We send ACK, and wait
        for 2*MSL*/
        if (c->state == TCPAssignment::State::CLOSING)
        {
            Packet* newPacket = this->allocatePacket(SIZE_EMPTY_PACKET);
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            
            //*seq_number = htonl(ntohl(*seq_number)+1);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);
            TCPAssignment::fill_packet_header(newPacket, dest_ip, dest_port, src_ip, src_port, 5,
                FLAG_ACK, htons(51200), *seq_number, ack_number);

            //Sends ACK
            //State becomes TIMED_WAIT;
            Time msl = TimeUtil::makeTime(MSL, TimeUtil::TimeUnit::SEC);
            UUID timeUUID = TimerModule::addTimer((void* )newPacket, 2*msl);
            c->state = TCPAssignment::State::TIMED_WAIT;
            c->timer_ID=timeUUID;
        }
        //Get Ack in FIN_WAIT_1 state -> simply changes the state into FIN_WAIT_2
        else if (c->state == TCPAssignment::State::FIN_WAIT_1 && ack_number == htonl(ntohl(c->last_ack_number) + 1))
        {
            c->state=TCPAssignment::State::FIN_WAIT_2;
            TimerModule::cancelTimer(c->timer_ID);
        }
        //Get Ack in LAST_ACK state -> Ends connection in passive side, remove backlog&established, but do not remove context
        else if (c->state == TCPAssignment::State::LAST_ACK)
        {
            TCPAssignment::closeSocket(pid, fd);
        }
        //Data transfer (send) - ACK received
        else if (c->state == TCPAssignment::State::ESTABLISHED && packet->getSize() - SIZE_EMPTY_PACKET == 0)
        {
            //ack_number=htonl(ntohl(ack_number)+1);

            while (true)
            {
                Window* window = TCPAssignment::send_window_lists[pid][fd].front();
                if (window == NULL) break;
                unsigned int seq_number;
                window->packet->readData(PACKETLOC_SEQNO, &seq_number, 4);
                if (ntohl(seq_number) < ntohl(ack_number)) {
                    TCPAssignment::send_window_lists[pid][fd].pop_front();
                    freePacket(window->packet);
                    free(window);
                }
                else {
                    break;
                }
            }

            short window_size;
            packet->readData(PACKETLOC_WINDOWSIZE, &window_size, 2);
            c->rwnd = ntohs(window_size);
            assert(ntohs(ack_number) >= ntohs(c->last_ack_number));
            // duplicate ack
            if (c->last_ack_number == ack_number)
            {
                if (c->congestion_state == CONG_RECOVERY)
                {
                    c->cwnd += MAX_DATA_FIELD_SIZE;
                    create_data_packets_and_send(pid, fd);
                }
                else
                {
                    c->dup_ack_count++;
                    if (c->dup_ack_count == 3)
                    {
                        c->ssthresh = c->cwnd / 2;
                        c->cwnd = c->ssthresh + 3;
                        c->congestion_state = CONG_RECOVERY;
                        retransmit_first_unacked_packet(pid, fd);
                    }
                }
            }
            // normal ack
            else
            {
                c->last_ack_number = ack_number;
                c->dup_ack_count = 0;
                if (c->congestion_state == CONG_SLOW_START)
                {
                    c->cwnd += MAX_DATA_FIELD_SIZE;
                    create_data_packets_and_send(pid, fd);
                    
                }
                else if (c->congestion_state == CONG_AVOIDANCE)
                {
                    c->cwnd += MAX_DATA_FIELD_SIZE * MAX_DATA_FIELD_SIZE / c->cwnd;
                    create_data_packets_and_send(pid, fd);
                    //retransmit_first_unacked_packet(pid, fd);
                }
                else // c->congestion_state == CONG_RECOVERY
                {
                    c->cwnd = c->ssthresh;
                    c->congestion_state = CONG_AVOIDANCE;
                    //create_data_packets_and_send(pid, fd);
                    //retransmit_first_unacked_packet(pid, fd);
                }

                if (find_length_of_unacked_packets(pid, fd) > 0)
                {
                    //printf("port number: %d timer reset\n", ntohs(c->remote_port));
                    TimerModule::cancelTimer(c->timer_ID);
                    Packet* copyPacket = this->clonePacket(TCPAssignment::send_window_lists[pid][fd].front()->packet);
                    Time msl = TimeUtil::makeTime(RTO, TimeUtil::TimeUnit::MSEC);
                    UUID timeUUID = TimerModule::addTimer((void* )copyPacket, msl);
                    c->timer_on = true;
                    c->timer_ID=timeUUID;
                }
                else
                {
                    //printf("port number: %d timer turned off - bufsize: %d, unacked: %d - cwnd: %d\n", ntohs(c->remote_port), 
                    //    c->send_buffer->size, find_length_of_unacked_packets(pid, fd), c->cwnd);
                    TimerModule::cancelTimer(c->timer_ID);
                    c->timer_on = false;
                    if (c->send_buffer->size > 0)
                    {
                        create_data_packets_and_send(pid, fd);
                    }
                }

                if (c->send_buffer->size + find_length_of_unacked_packets(pid, fd) == 0 &&
                    c->btsyscall->is_blocked && c->btsyscall->transfer_type == TRANSFER_CLOSE)
                {
                    //printf("Late close called, FIN sent. (port: %d)\n", ntohs(c->remote_port));
                    int ret = TCPAssignment::syscall_close(c->btsyscall->syscall_hold_ID, pid, fd);
                    returnSystemCall(c->btsyscall->syscall_hold_ID, ret);
                }
                
            }

            if (BUFFER_SIZE - c->send_buffer->size - find_length_of_unacked_packets(pid, fd) > 0)
            {
                release_blocked_write(pid, fd);
            }

            if (c->congestion_state == CONG_SLOW_START && c->cwnd > c->ssthresh)
            {
                c->congestion_state = CONG_AVOIDANCE;
            }
        }
        //Data transfer (receive)
        else if (c->state == TCPAssignment::State::ESTABLISHED && packet->getSize() - SIZE_EMPTY_PACKET > 0)
        {
            unsigned int seq_number;
            packet->readData(PACKETLOC_SEQNO, &seq_number, 4);
            if (seq_number == c->ack_number) {
                Buffer* recv_buffer = c->recv_buffer;

                int payload_size = packet->getSize() - SIZE_EMPTY_PACKET;
                char* data = (char*) malloc (payload_size);
                packet->readData(PACKETLOC_PAYLOAD, data, payload_size);
                recv_buffer->write_buf(data, payload_size);

                if (c->btsyscall->is_blocked && c->btsyscall->transfer_type == TRANSFER_READ)
                {
                    BlockedTransferSyscall* bts = c->btsyscall;
                    int read_bytes = TCPAssignment::syscall_read(bts->syscall_hold_ID, pid, fd, bts->buf, bts->count);
                    this->returnSystemCall(bts->syscall_hold_ID, read_bytes);
                    bts->is_blocked = false;
                }

                c->ack_number = htonl(ntohl(c->ack_number) + payload_size);
                int remaining_window = BUFFER_SIZE - find_length_of_out_of_order_packets(pid, fd) - recv_buffer->size;
                TCPAssignment::sendNewPacket(dest_ip, dest_port, src_ip, src_port, c->seq_number, c->ack_number,
                    5, FLAG_ACK, htons(remaining_window), 0, NULL, false);

                
            }
            else {
                //TODO: Out of order packet arrival
            }
        }
    }

    // 4. Receiving FIN means we are in 4-way handshaking(Finishing Connection)
    else if (flag == FLAG_FIN)
    {
        int pid, fd;
        Backlog* bggg;

        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, src_ip, src_port, &pid, &fd);

        if (!suc)
        {
            bool suc2 = TCPAssignment::retrieve_backlog_when_FIN(src_ip, src_port, &bggg);
            if (!suc2) 
            {
                freePacket(packet);
                return;
            }
            else
            {
                unsigned int* seq_number= &(bggg->seq_number);
                unsigned int ack_number;
                
                packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
                ack_number=htonl(ntohl(ack_number)+1);

                TCPAssignment::sendNewPacket(dest_ip, dest_port, src_ip, src_port, *seq_number, ack_number,
                    5, FLAG_ACK, htons(51200), 0, NULL, false);

                //Change the state into CLOSE_WAIT;
                bggg->state = TCPAssignment::State::CLOSE_WAIT;
            }

            freePacket(packet);
            return;
        }
        Context* c = TCPAssignment::contextList[pid][fd];

        //Passive Closing. Send ACK, and wait for change State into CLOSE_WAIT
        if (c->state == TCPAssignment::State::ESTABLISHED ||
            c->state == TCPAssignment::State::FIN_WAIT_1 ||
            c->state == TCPAssignment::State::FIN_WAIT_2 ||
            c->state == TCPAssignment::State::CLOSE_WAIT)
        {
            //Sends ACK
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            
            TimerModule::cancelTimer(c->timer_ID);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);

            TCPAssignment::sendNewPacket(dest_ip, dest_port, src_ip, src_port, *seq_number, ack_number,
                5, FLAG_ACK, htons(51200), 0, NULL, false);

            //Change the state into CLOSE_WAIT;
			if (c->state == TCPAssignment::State::ESTABLISHED)
            {
                c->state = TCPAssignment::State::CLOSE_WAIT;
                if (c->btsyscall->is_blocked && c->btsyscall->transfer_type == TRANSFER_READ)
                {
                    this->returnSystemCall(c->btsyscall->syscall_hold_ID, -1);
                }
            }
            else if (c->state == TCPAssignment::State::FIN_WAIT_1)//Simultaneous Closing. Send ACK, and change State into CLOSING 
            {
                c->state = TCPAssignment::State::CLOSING;
            }
            else if (c->state == TCPAssignment::State::FIN_WAIT_2)
            {
                Packet* copyPacket = this->clonePacket(packet);

                Time msl = TimeUtil::makeTime(MSL, TimeUtil::TimeUnit::SEC);
                UUID timeUUID = TimerModule::addTimer((void* )copyPacket, 2*msl);

                c->state = TCPAssignment::State::TIMED_WAIT;
                c->timer_ID=timeUUID;
            }
            else //State == CLOSE_WAIT. Multiple transmit of FIN packet due to pkt loss
            {
                 //do nothing
            }
        }
        
        
    }
    // 5. As an active closing host, we can possibly get signal FIN/ACK
    else if (flag == FLAG_FINACK)
    {
        int pid, fd;
        bool suc = TCPAssignment::retrieve_fd_from_context(dest_ip, dest_port, src_ip, src_port, &pid, &fd);
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
            unsigned int* seq_number= &(c->seq_number);
            unsigned int ack_number;
            
  //          *seq_number = htonl(ntohl(*seq_number)+1);
            packet->readData(PACKETLOC_SEQNO, &ack_number, 4);
            ack_number=htonl(ntohl(ack_number)+1);

            TCPAssignment::sendNewPacket(dest_ip, dest_port, src_ip, src_port, *seq_number, ack_number,
                5, FLAG_ACK, htons(51200), 0, NULL, false);

            Packet* copyPacket=this->clonePacket(packet);

            //Change the state into TIMED_WAIT;
            Time msl = TimeUtil::makeTime(MSL, TimeUtil::TimeUnit::SEC);
            UUID timeUUID = TimerModule::addTimer((void* )copyPacket, 2*msl);
            c->state = TCPAssignment::State::TIMED_WAIT;
            c->timer_ID=timeUUID;
        }
    }
    freePacket(packet);
    return;
}

void TCPAssignment::closeSocket(unsigned int pid, unsigned int fd)
{
    Context* context = TCPAssignment::contextList[pid][fd];
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
    }
    for (auto snd : TCPAssignment::send_window_lists[pid][fd])
    {
        free(snd);
    }
    for (auto rcv : TCPAssignment::recv_packet_lists[pid][fd])
    {
        free(rcv);
    }
    TCPAssignment::contextList[pid].erase(fd);
    TCPAssignment::accept_waiting_lists[pid].erase(fd);
    TCPAssignment::established_backlog_lists[pid].erase(fd);
    SystemCallInterface::removeFileDescriptor(pid, fd);
    delete context->send_buffer;
    delete context->recv_buffer;
    delete context->btsyscall;
    free(context);
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
    bool suc = TCPAssignment::retrieve_fd_from_context(src_ip, src_port, dest_ip, dest_port, &pid, &fd);
    if (!suc)
    {
        freePacket(packet);
        return;
    }
    Context* c = TCPAssignment::contextList[pid][fd];
    if (c->timer_on && c->state == TCPAssignment::State::ESTABLISHED && !c->isClosing)
    {        

        //printf("port number: %d timer ring\n", ntohs(c->remote_port));
        Packet* copyPacket = this->clonePacket(packet);
        this->sendPacket("IPv4", packet);
        Time msl = TimeUtil::makeTime(RTO, TimeUtil::TimeUnit::MSEC);
        UUID timeUUID = TimerModule::addTimer((void* )copyPacket, msl);
        c->timer_on = true;
        c->timer_ID=timeUUID;
        
        c->ssthresh = c->cwnd / 2;
        c->cwnd = MAX_DATA_FIELD_SIZE;
        c->dup_ack_count = 0;
        c->congestion_state = CONG_SLOW_START;
        if (c->congestion_state == CONG_SLOW_START && c->cwnd > c->ssthresh)
        {
            c->congestion_state = CONG_AVOIDANCE;
        }
    }
    else if (c->timer_on && c->state == TCPAssignment::State::FIN_WAIT_1 && c->isClosing)
    {
        Packet* copyPacket = this->clonePacket(packet);
        this->sendPacket("IPv4", packet);
        //printf("Fin timeout - fin resend, port: (port: %d)\n", c->remote_port);
        Time msl = TimeUtil::makeTime(RTO, TimeUtil::TimeUnit::MSEC);
        UUID timeUUID = TimerModule::addTimer((void* )copyPacket, msl);
        c->timer_on = true;
        c->timer_ID=timeUUID;
    }
    else
    {
        //After extracting informations, removing fd/pid pair from contextList/backlog/established
        TCPAssignment::closeSocket(pid, fd);
        freePacket(packet);
    }
    return;
}

Packet* TCPAssignment::sendNewPacket(unsigned int src_ip, unsigned short src_port, unsigned int dest_ip, unsigned short dest_port,
    unsigned int seq_number, unsigned int ack_number, int header_offset, char flag, short window_size,
    unsigned int payload_size, char* payload, bool noSend)
{
    Packet* newPacket = this->allocatePacket(SIZE_EMPTY_PACKET + payload_size);
    TCPAssignment::fill_packet_header(newPacket, src_ip, src_port, dest_ip, dest_port, header_offset, 
        flag, window_size, seq_number, ack_number);
    if (payload_size > 0) {
        newPacket->writeData(PACKETLOC_PAYLOAD, payload, payload_size);
    }
    TCPAssignment::packet_fill_checksum(newPacket);
    if (noSend) {
        return newPacket;
    }
    this->sendPacket("IPv4", newPacket);
    return NULL;
}

}
