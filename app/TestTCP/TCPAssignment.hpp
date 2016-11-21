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
#include <list>

#include <E/E_TimerModule.hpp>
#include <E/E_TimeUtil.hpp>

#define PACKETLOC_SRC_IP 26
#define PACKETLOC_SRC_PORT 34
#define PACKETLOC_DEST_IP 30
#define PACKETLOC_DEST_PORT 36
#define PACKETLOC_TCP_HEADER_SIZE 46
#define PACKETLOC_TCP_FLAGS 47
#define PACKETLOC_SEQNO 38
#define PACKETLOC_ACKNO 42
#define PACKETLOC_CHKSUM 50
#define PACKETLOC_WINDOWSIZE 48
#define PACKETLOC_PAYLOAD 54

#define FLAG_SYN 2
#define FLAG_SYNACK 18
#define FLAG_ACK 16
#define FLAG_FIN 1
#define FLAG_RST 4
#define FLAG_FINACK 17

#define SEQ_NUMBER_START 0xaaafafaa

#define SIZE_EMPTY_PACKET 54
#define BUFFER_SIZE 51200
#define MAX_DATA_FIELD_SIZE 512

#define TRANSFER_WRITE 1
#define TRANSFER_READ 0
#define TRANSFER_CLOSE 2

#define CONG_SLOW_START 0
#define CONG_AVOIDANCE 1
#define CONG_RECOVERY 2

#define MSL 60
#define RTO 150
#define INITRTT 20
#define INITDEV 10
#define INITRTO 60

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
        CLOSED, LISTEN, SYN_SENT, SYN_RCVD, ESTABLISHED, CLOSING, FIN_WAIT_1, FIN_WAIT_2, TIMED_WAIT, CLOSE_WAIT, LAST_ACK
    };

    class AcceptWaiting
    {
    public:
        UUID syscallUUID;
        int pid;
        int sockfd;
        struct sockaddr *addr;
        socklen_t *addrlen;
    };

    class Backlog
    {
    public:
        bool in_use;
        unsigned int remote_ip_address;
        unsigned short remote_port;
        unsigned int seq_number;
        unsigned int ack_number;
        State state;
    };

    class Buffer
    {
    public:
        char* bufptr;
        unsigned int start_index;
        unsigned int end_index;
        unsigned int size;
        unsigned int capacity;

        Buffer();
        int write_buf(const char* srcbuf, size_t count);
        int read_buf(char* destbuf, size_t count);
    };

    class BlockedTransferSyscall
    {
    public:
        bool is_blocked;
        int transfer_type;
        UUID syscall_hold_ID;
        char* buf;
        size_t count;

        BlockedTransferSyscall();
        void set_fields(int ttype, UUID sID, char* buf, size_t count);
    };

    class Context
    {
    public:
        unsigned int local_ip_address;
        unsigned short local_port;
        unsigned int remote_ip_address;
        unsigned short remote_port;
        unsigned int seq_number;
        unsigned int ack_number;
        State state;
        bool isBound;
        bool isClosing;
        UUID syscall_hold_ID;
        BlockedTransferSyscall* btsyscall;
        UUID timer_ID;
        int backlog_size;
        Backlog* backlog;
        Buffer* send_buffer;
        Buffer* recv_buffer;
        int rwnd;
        int cwnd;
        int dup_ack_count;
        int ssthresh;
        int congestion_state;
        int estimateRTT;
        int devRTT;
        int timeRTO;
        unsigned int last_ack_number;
        bool timer_on;
    };

    class Window
    {
    public:
        Time currentTime;
        Packet* packet;
    };

    std::map<int, std::map<int, Context*>> contextList;
    std::map<int, std::map<int, std::list<AcceptWaiting*>>> accept_waiting_lists;
    std::map<int, std::map<int, std::list<Backlog*>>> established_backlog_lists;
    std::map<int, std::map<int, std::list<Window*>>> send_window_lists;
    std::map<int, std::map<int, std::list<Packet*>>> recv_packet_lists;

    int syscall_socket(UUID syscallUUID, int pid, int domain, int type__unused);
    int syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrlen);
    int syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int syscall_close(UUID syscallUUID, int pid, int fd);
    int syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
    int syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int return_syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen, Context* context, Backlog* backlog);
    int syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);

    int syscall_write(UUID syscallUUID, int pid, int fd, const void *buf, size_t count);
    int syscall_read(UUID syscallUUID, int pid, int fd, void *buf, size_t count);

    void release_blocked_write(int pid, int fd);
    void retransmit_first_unacked_packet(int pid, int fd);

    void create_data_packets_and_send(int pid, int fd);
    int find_length_of_unacked_packets(int pid, int fd);
    int find_length_of_out_of_order_packets(int pid, int fd);

    bool retrieve_fd_from_context(unsigned int local_ip_address, unsigned short local_port,
        unsigned int remote_ip_address, unsigned short remote_port, int* pid, int* fd);
    bool retrieve_fd_from_context(unsigned int local_ip_address, unsigned short local_port, int* pid, int* fd);
    bool retrieve_backlog_when_FIN (unsigned int remote_ip_address, unsigned short remote_port, Backlog** bg);
   
    void packet_fill_checksum(Packet* packet);
    void fill_packet_header(Packet* packet, unsigned int src_ip, unsigned short src_port,
        unsigned int dest_ip, unsigned short dest_port, char size, char syn, short window_size,
        unsigned int seq_number, unsigned int ack_number);
    void closeSocket(unsigned int pid, unsigned int fd);
    Time minTime(Time time1, Time time2);
    Time absTime(Time time1, Time time2);
    Window* window_from_acknum(unsigned int ack_number, unsigned int pid, unsigned int fd);
    Context* create_new_context(unsigned int local_ip_address, unsigned short local_port, unsigned int remote_ip_address, 
        unsigned short remote_port, unsigned int seq_number, unsigned int ack_number, State state, bool isBound, 
        UUID syscall_hold_ID, UUID timer_ID, int backlog_size);
    Packet* find_pkt_by_seq(unsigned int target_number, unsigned int pid, unsigned int fd);
    void remove_pkt_by_seq(unsigned int target_number, unsigned int pid, unsigned int fd);
    Packet* sendNewPacket(unsigned int src_ip, unsigned short src_port, unsigned int dest_ip, unsigned short dest_port,
    unsigned int seq_number, unsigned int ack_number, int header_offset, char flag, short window_size,
    unsigned int payload_size, char* payload, bool noSend);

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
