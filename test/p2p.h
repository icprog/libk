#pragma once

#define REG_MSG(msg,cb)\
	krbtree_insert(msgmap, (void *)msg, (void *)cb);

enum client_msg
{
	CLIENT_LOCAL_ADDR		=	1000,

	CLIENT_QUERY_USERLIST	=	1001,

	CLIENT_APPLY_P2P		=	1002,

	CLIENT_P2P_OK			=	1003,
	
};

 
enum server_msg
{
	SERVER_SELF_ADDR		=	1000,

	SERVER_USERLIST			=	1001,

	SERVER_APPLY_P2P		=	1002,

	SERVER_P2P_OK			=	1003,

};