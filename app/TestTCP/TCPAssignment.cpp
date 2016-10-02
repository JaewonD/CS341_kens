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

TCPAssignment::BindList::BindList()
{
	int initial_capacity = 10;
	this->b = (BindData*) calloc (initial_capacity, sizeof(BindData));
	this->size = 0;
	this->capacity = initial_capacity;
}
  
void TCPAssignment::BindList::resizeBindList ()
{
	if (this->size == this->capacity)
	{
		int old_capacity = this->capacity;
		int new_capacity = this->capacity * 3 / 2;
		realloc (this->b, new_capacity);
		memset(this->b + old_capacity, 0, sizeof(BindData)*(new_capacity - old_capacity));
		this->capacity = new_capacity;
	}
}
TCPAssignment::Fds_list::Fds_list()
{
        this->head=NULL;
	this->length=0;
}
void TCPAssignment::Fds_list::insert_fds(int fd){
	Fds_node* newnode=(Fds_node* )calloc(1, sizeof(Fds_node));
	newnode->validfds=fd;
	if(this->length==0)
	{
		this->head=newnode;
		this->length++;
	}
	else
	{
		Fds_node* endnode=this->head;
	  	while(1)
	    	{
			if(endnode->validfds==fd) break;

			else if(endnode->next==NULL)
			{
				endnode->next=newnode;
				this->length++;
				break;
			}

			else endnode=endnode->next;
		}
	}
}
void TCPAssignment::Fds_list::remove_fds(int fd){
	Fds_node* first=this->head;
	if(first==NULL) return;
	if(first->validfds==fd)
	{
		this->head=first->next;
		this->length--;
		return;
	}
	Fds_node* second=first->next;
	while(second!=NULL)
	{
		if(second->validfds==fd)
		{
			first->next=second->next;
			this->length--;
			free(second);
			break;
		}
		first=second;
		second=second->next;
	}
}
bool TCPAssignment::Fds_list::search_fds(int fd){
	Fds_node* search=this->head;
	while(search!=NULL)
	{
		if(search->validfds==fd) return true;
		search=search->next;
	}
	return false;
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
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
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
	//	BindData* bd = &(TCPAssignment::bindlist.b[i]);
	//	printf("InUse: %d, IP: %lu, Port: %d, fd: %d\n", bd->in_use, bd->ip_address, bd->port, bd->fd);
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

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
