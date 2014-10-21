
//khttp

#define URL_MAX_LEN		1024


typedef struct khttp_request khttp_request, *khttp_request_t;

typedef struct khttp_response khttp_response, *khttp_response_t;

typedef struct khttp_connection khttp_connection, *khttp_connection_t;

struct khttp_request 
{
	khttp_connection_t conn;

	unsigned char method;
	unsigned short http_major;
	unsigned short http_minor;
	char file[URL_MAX_LEN];
	char url[URL_MAX_LEN];
	char header_field[URL_MAX_LEN];
	char header_value[URL_MAX_LEN];

	krbtree_t heads;
	krbtree_t params;

	void *data;						/*user data*/
};

K_EXPORT int khttp_request_init(khttp_request_t *preq);

K_EXPORT int khttp_request_uninit(khttp_request_t req);

struct khttp_response 
{
	int response_code;

	khttp_connection_t conn;

	unsigned short status_code;

	void *data;						/*user data*/
};


K_EXPORT int khttp_response_init(khttp_response_t *pres);

K_EXPORT int khttp_response_error(khttp_response_t res, int http_errno);

K_EXPORT int khttp_response_file(khttp_response_t res, const char *file);

K_EXPORT int khttp_response_uninit(khttp_response_t res);


struct khttp_connection 
{
	khttp_request_t req;
	khttp_response_t res;
	ktcp_session_t session;

	unsigned char type : 2;
	unsigned char flags : 6;		/* F_* values from 'flags' enum; semi-public */
	unsigned char state;
	unsigned char header_state;
	unsigned char index;

	unsigned nread;
	unsigned content_length;

	/** READ-ONLY **/
	unsigned short status_code;		/* responses only */

	unsigned char http_errno : 7;

	/* 1 = Upgrade header was present and the parser has exited because of that.
	* 0 = No upgrade header present.
	* Should be checked when http_parser_execute() returns in addition to
	* error checking.
	*/
	unsigned char upgrade : 1;


	void *data;				/*user data*/
};


//khttp_server

#define DIR_PATH_MAX_LEN	512

typedef int (*khttp_request_cb)(khttp_request_t req, khttp_response_t res);

typedef struct khttp_server khttp_server, *khttp_server_t;

struct khttp_server
{
	ktcp_t tcp;
	char *root_dir;
	
	khttp_request_cb request_cb;

	void *data;				/*user data*/
};

K_EXPORT int khttp_server_init(khttp_server_t *pserver);

K_EXPORT int khttp_server_set_request_cb(khttp_server_t server, khttp_request_cb cb);

K_EXPORT int khttp_server_start(khttp_server_t server, int port, char *root);

K_EXPORT int khttp_server_uninit(khttp_server_t server);







//khttp
/************************************************************************/
/*				khttp                                                   */
/************************************************************************/

static int 
cmp(void *left_key, void *right_key)
{
	int left = (int)left_key;
	int right = (int)right_key;
	if (left < right)
	{
		return 1;
	}
	else if (left > right)
	{
		return 1;
	}
	else 
	{
		assert (left == right);
		return 0;
	}
}

int 
khttp_request_init(khttp_request_t *preq)
{
	*preq = k_malloc_t(khttp_request);
	if (NULL == *preq)
	{
		return 1;
	}
	(*preq)->conn = NULL;
	memset((*preq)->file, 0, sizeof((*preq)->file));
	(*preq)->http_major = 0;
	(*preq)->http_minor = 0;
	(*preq)->method = 0;
	(*preq)->data = NULL;
	krbtree_init(&(*preq)->heads, cmp);
	krbtree_init(&(*preq)->params, cmp);
	return 0;
}

static void
khttp_request_clear(void *key, void *val)
{
	k_free(key);
	k_free(val);
}

int 
khttp_request_uninit(khttp_request_t req)
{
	krbtree_foreach(req->heads, khttp_request_clear);
	krbtree_foreach(req->params, khttp_request_clear);
	krbtree_uninit(req->heads);
	krbtree_uninit(req->params);
	k_free(req);
	return 0;
}

int 
khttp_response_init(khttp_response_t *pres)
{
	*pres = k_malloc_t(khttp_response);
	if (NULL == *pres)
	{
		return 1;
	}
	(*pres)->conn = NULL;
	return 0;
}

int 
khttp_response_error(khttp_response_t res, int http_errno)
{
	int content_len = 0;
	char buf[URL_MAX_LEN] = "";
	char body[URL_MAX_LEN] = "";
	char fmt[URL_MAX_LEN] = "<HTML>\r\n<HEAD>\r\n<TITLE>%d %s</TITLE>\r\n</HEAD>\r\n<BODY>\r\n<H1>%d %s</H1>\r\n%s<P>\r\n</BODY>\r\n</HTML>\r\n";
	ktcp_t tcp = (ktcp_t)res->conn->data;
	
	sprintf(body, fmt, http_errno, "err", http_errno, "err", "err");
	content_len = strlen(body);
	sprintf(buf, "HTTP/1.1 %d %s\r\nServer: klhttpd/0.1.0\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", http_errno, "err", content_len, body);

	printf("%s\n", buf);
	ktcp_send(tcp, res->conn->session, buf, strlen(buf) + 1);
	return 1;
}

int
khttp_response_file(khttp_response_t res, const char *file)
{
	int content_len = 0;
	char buf[URL_MAX_LEN * 10] = "";
	char *body = NULL;
	ktcp_t tcp = (ktcp_t)res->conn->data;
	FILE *fp = fopen(file, "rb");
	if (NULL == fp)
	{
		printf("can not fopen file:%s\n", file);
		return 1;
	}
	fseek( fp, 0, SEEK_END );
	content_len = ftell( fp );
	fseek( fp, 0, SEEK_SET );
	body = (char*)k_malloc(content_len + 1);
	fread(body, content_len, 1, fp);
	body[content_len] = '\0'; 

	content_len = strlen(body);
	sprintf(buf, "HTTP/1.1 %d %s\r\nServer: khttpd/0.1.0\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", 200, "err", content_len, body);
	k_free(body);
	fclose(fp);

	printf("%s\n", buf);
	ktcp_send(tcp, res->conn->session, buf, strlen(buf) + 1);

	return 0;
}

int 
khttp_response_uninit(khttp_response_t res)
{

	k_free(res);
	return 0;
}

//khttp_request_parse

static const char tokens[256] =
{
	/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
	' ',      '!',     '"',     '#',     '$',     '%',     '&',    '\'',
	/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
	0,       0,      '*',     '+',      0,      '-',     '.',     '/',
	/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
	'0',     '1',     '2',     '3',     '4',     '5',     '6',     '7',
	/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
	'8',     '9',      0,       0,       0,       0,       0,       0,
	/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
	0,      'a',     'b',     'c',     'd',     'e',     'f',     'g',
	/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
	'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
	/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
	'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
	/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
	'x',     'y',     'z',      0,       0,       0,      '^',     '_',
	/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
	'`',     'a',     'b',     'c',     'd',     'e',     'f',     'g',
	/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
	'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
	/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
	'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
	/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
	'x',     'y',     'z',      0,      '|',     '}',     '~',       0
};


static const char unhex[256] =
{
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
	,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
	,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};


static const unsigned char normal_url_char[256] = 
{
	/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
	0,       0,       0,       0,       0,       0,       0,       0,
	/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
	0,       1,       1,       0,       1,       1,       1,       1,
	/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
	1,       1,       1,       1,       1,       1,       1,       0,
	/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
	1,       1,       1,       1,       1,       1,       1,       1,
	/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
	1,       1,       1,       1,       1,       1,       1,       0, 
};


enum state
{
	s_dead = 1 /* important that this is > 0 */

	, s_start_req_or_res
	, s_res_or_resp_H
	, s_start_res
	, s_res_H
	, s_res_HT
	, s_res_HTT
	, s_res_HTTP
	, s_res_first_http_major
	, s_res_http_major
	, s_res_first_http_minor
	, s_res_http_minor
	, s_res_first_status_code
	, s_res_status_code
	, s_res_status
	, s_res_line_almost_done

	, s_start_req

	, s_req_method
	, s_req_spaces_before_url
	, s_req_schema
	, s_req_schema_slash
	, s_req_schema_slash_slash
	, s_req_host
	, s_req_port
	, s_req_path
	, s_req_query_string_start
	, s_req_query_string
	, s_req_fragment_start
	, s_req_fragment
	, s_req_http_start
	, s_req_http_H
	, s_req_http_HT
	, s_req_http_HTT
	, s_req_http_HTTP
	, s_req_first_http_major
	, s_req_http_major
	, s_req_first_http_minor
	, s_req_http_minor
	, s_req_line_almost_done

	, s_header_field_start
	, s_header_field
	, s_header_value_start
	, s_header_value
	, s_header_value_lws
	, s_header_almost_done

	, s_chunk_size_start
	, s_chunk_size
	, s_chunk_parameters
	, s_chunk_size_almost_done  

	, s_headers_almost_done

	, s_chunk_data
	, s_chunk_data_almost_done
	, s_chunk_data_done

	, s_body_identity
	, s_body_identity_eof
};

enum header_states
{
	h_general = 0
	, h_C
	, h_CO
	, h_CON

	, h_matching_connection
	, h_matching_proxy_connection
	, h_matching_content_length
	, h_matching_transfer_encoding
	, h_matching_upgrade

	, h_connection
	, h_content_length
	, h_transfer_encoding
	, h_upgrade

	, h_matching_transfer_encoding_chunked
	, h_matching_connection_keep_alive
	, h_matching_connection_close

	, h_transfer_encoding_chunked
	, h_connection_keep_alive
	, h_connection_close
};

enum khttp_method
{
	HTTP_DELETE,
	HTTP_GET,
	HTTP_HEAD,
	HTTP_POST,
	HTTP_PUT,
	/* pathological */
	HTTP_CONNECT,
	HTTP_OPTIONS,
	HTTP_TRACE,
	/* webdav */
	HTTP_COPY,
	HTTP_LOCK,
	HTTP_MKCOL,
	HTTP_MOVE,
	HTTP_PROPFIND,
	HTTP_PROPPATCH,
	HTTP_UNLOCK,
	/* subversion */
	HTTP_REPORT,
	HTTP_MKACTIVITY,
	HTTP_CHECKOUT,
	HTTP_MERGE,
	/* upnp */
	HTTP_MSEARCH,
	HTTP_NOTIFY,
	HTTP_SUBSCRIBE,
	HTTP_UNSUBSCRIBE,
	/* RFC-5789 */
	HTTP_PATCH,
};

static const char *method_strings[] =
{
	"DELETE"
	, "GET"
	, "HEAD"
	, "POST"
	, "PUT"
	, "CONNECT"
	, "OPTIONS"
	, "TRACE"
	, "COPY"
	, "LOCK"
	, "MKCOL"
	, "MOVE"
	, "PROPFIND"
	, "PROPPATCH"
	, "UNLOCK"
	, "REPORT"
	, "MKACTIVITY"
	, "CHECKOUT"
	, "MERGE"
	, "M-SEARCH"
	, "NOTIFY"
	, "SUBSCRIBE"
	, "UNSUBSCRIBE"
	, "PATCH"
};

enum http_parser_type 
{
	HTTP_REQUEST,
	HTTP_RESPONSE, HTTP_BOTH 
};

enum flags
{
	F_CHUNKED					= 1 << 0
	, F_CONNECTION_KEEP_ALIVE	= 1 << 1
	, F_CONNECTION_CLOSE		= 1 << 2
	, F_TRAILING				= 1 << 3
	, F_UPGRADE					= 1 << 4
	, F_SKIPBODY				= 1 << 5
};

#define HTTP_ERRNO_MAP(XX)											\
	/* No error */													\
	XX(OK, "success")												\
	\
	/* CALL-related errors */									\
	XX(CB_message_begin, "the on_message_begin CALL failed")	\
	XX(CB_path, "the on_path CALL failed")						\
	XX(CB_query_string, "the on_query_string CALL failed")		\
	XX(CB_url, "the on_url CALL failed")						\
	XX(CB_fragment, "the on_fragment CALL failed")				\
	XX(CB_header_field, "the on_header_field CALL failed")		\
	XX(CB_header_value, "the on_header_value CALL failed")		\
	XX(CB_headers_complete, "the on_headers_complete CALL failed")	\
	XX(CB_body, "the on_body CALL failed")							\
	XX(CB_message_complete, "the on_message_complete CALL failed")	\
	\
	/* Parsing-related errors */										\
	XX(INVALID_EOF_STATE, "stream ended at an unexpected time")			\
	XX(HEADER_OVERFLOW,	"too many header bytes seen; overflow detected")\
	XX(CLOSED_CONNECTION,"data received after completed connection: close message")      \
	XX(INVALID_VERSION, "invalid HTTP version")                        \
	XX(INVALID_STATUS, "invalid HTTP status code")                     \
	XX(INVALID_METHOD, "invalid HTTP method")                          \
	XX(INVALID_URL, "invalid URL")                                     \
	XX(INVALID_HOST, "invalid host")                                   \
	XX(INVALID_PORT, "invalid port")                                   \
	XX(INVALID_PATH, "invalid path")                                   \
	XX(INVALID_QUERY_STRING, "invalid query string")                   \
	XX(INVALID_FRAGMENT, "invalid fragment")                           \
	XX(LF_EXPECTED, "LF character expected")                           \
	XX(INVALID_HEADER_TOKEN, "invalid character in header")            \
	XX(INVALID_CONTENT_LENGTH,                                         \
	"invalid character in content-length header")                   \
	XX(INVALID_CHUNK_SIZE,                                             \
	"invalid character in chunk size header")                       \
	XX(INVALID_CONSTANT, "invalid constant string")                    \
	XX(INVALID_INTERNAL_STATE, "encountered unexpected internal state")\
	XX(STRICT, "strict mode assertion failed")                         \
	XX(UNKNOWN, "an unknown error occurred")

#define PROXY_CONNECTION		"proxy-connection"
#define CONNECTION				"connection"
#define CONTENT_LENGTH			"content-length"
#define TRANSFER_ENCODING		"transfer-encoding"
#define UPGRADE					"upgrade"
#define CHUNKED					"chunked"
#define KEEP_ALIVE				"keep-alive"
#define CLOSE					"close"


#define CR						'\r'
#define LF						'\n'
#define LOWER(c)				(unsigned char)(c | 0x20)
#define TOKEN(c)				(tokens[(unsigned char)c])
#define IS_ALPHA(c)				(LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)				((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)			(IS_ALPHA(c) || IS_NUM(c))
#define MIN(a,b)				((a) < (b) ? (a) : (b))
#define HTTP_PARSER_ERRNO(p)	((enum http_errno) (p)->http_errno)
#define SET_ERRNO(e)			conn->http_errno = (e);
#define PARSING_HEADER(state)	(state <= s_headers_almost_done)
#define STRICT_CHECK(cond)
#define NEW_MESSAGE()			start_state
#define IS_HOST_CHAR(c)			(IS_ALPHANUM(c) || (c) == '.' || (c) == '-' || (c) == '_')
#define IS_URL_CHAR(c)			(normal_url_char[(unsigned char) (c)] || ((c) & 0x80))
#define HTTP_MAX_HEADER_SIZE	(80*1024)
#define start_state				(conn->type == HTTP_REQUEST ? s_start_req : s_start_res)


#define MARK(FOR)\
	do {\
	FOR##_mark = p;\
	} while(0)


#define CALL(a)\
	strncpy(req->a, a##_mark, p-a##_mark);\
	req->a[p-a##_mark] = '\0';


#define CALL2(a)\
	{\
		char *key = k_malloc(strlen(req->header_field) + 1);\
		char *val = k_malloc(strlen(req->header_value) + 1);\
		strcpy(key, req->header_field);\
		strcpy(val, req->header_value);\
		krbtree_insert(req->heads, key, val);\
	}

/* Define HPE_* values for each errno value above */
#define HTTP_ERRNO_GEN(n, s) HPE_##n,
enum http_errno {
	HTTP_ERRNO_MAP(HTTP_ERRNO_GEN)
};
#undef HTTP_ERRNO_GEN


static int
http_should_keep_alive (khttp_connection_t conn)
{
	if (conn->req->http_major > 0 && conn->req->http_minor > 0) 
	{
		/* HTTP/1.1 */
		if (conn->flags & F_CONNECTION_CLOSE) 
		{
			return 0;
		}
		else 
		{
			return 1;
		}
	}
	else 
	{
		/* HTTP/1.0 or earlier */
		if (conn->flags & F_CONNECTION_KEEP_ALIVE) 
		{
			return 1;
		} 
		else 
		{
			return 0;
		}
	}
}

static int
khttp_request_parse(khttp_connection_t conn, khttp_request_t req, char *data, int len)
{
	char c, ch;
	char unhex_val;
	const char *p = data, *pe, *token;
	int to_read;
	enum state state;
	enum header_states header_state;
	unsigned index = conn->index;
	unsigned nread = conn->nread;

	/* technically we could combine all of these (except for url_mark) into one
	variable, saving stack space, but it seems more clear to have them
	separated. */
	const char *header_field_mark = 0;
	const char *header_value_mark = 0;
	const char *url_mark = 0;

	conn->type = HTTP_REQUEST;
	conn->state = s_start_req;
	conn->http_errno = HPE_OK;

	/* We're in an error state. Don't bother doing anything. */
	if (HTTP_PARSER_ERRNO(conn) != HPE_OK)
	{
		return 0;
	}

	state = (enum state) conn->state;
	header_state = (enum header_states) conn->header_state;

	if (len == 0) 
	{
		switch (state) 
		{
		case s_body_identity_eof:
			//CALL2(message_complete);
			return 0;

		case s_dead:
		case s_start_req_or_res:
		case s_start_res:
		case s_start_req:
			return 0;

		default:
			SET_ERRNO(HPE_INVALID_EOF_STATE);
			return 1;
		}
	}

	if (state == s_header_field)
	{
		header_field_mark = data;
	}
	if (state == s_header_value)
	{
		header_value_mark = data;
	}
	if (state == s_req_path || state == s_req_schema || state == s_req_schema_slash
		|| state == s_req_schema_slash_slash || state == s_req_port
		|| state == s_req_query_string_start || state == s_req_query_string
		|| state == s_req_host
		|| state == s_req_fragment_start || state == s_req_fragment)
	{
		url_mark = data;
	}
	for (p = data, pe = data + len; p != pe; p++) 
	{
		ch = *p;
		if (PARSING_HEADER(state)) 
		{
			++nread;
			/* Buffer overflow attack */
			if (nread > HTTP_MAX_HEADER_SIZE) 
			{
				SET_ERRNO(HPE_HEADER_OVERFLOW);
				goto error;
			}
		}

		switch (state) 
		{
		case s_dead:
			/* this state is used after a 'Connection: close' message
			* the parser will error out if it reads another message
			*/
			SET_ERRNO(HPE_CLOSED_CONNECTION);
			goto error;
		case s_start_req_or_res:
			{
				if (ch == CR || ch == LF)
					break;
				conn->flags = 0;
				conn->content_length = -1;

				//CALL2(message_begin);

				if (ch == 'H')
					state = s_res_or_resp_H;
				else 
				{
					conn->type = HTTP_REQUEST;
					goto start_req_method_assign;
				}
				break;
			}

		case s_res_or_resp_H:
			if (ch == 'T') 
			{
				conn->type = HTTP_RESPONSE;
				state = s_res_HT;
			}
			else 
			{
				if (ch != 'E') 
				{
					SET_ERRNO(HPE_INVALID_CONSTANT);
					goto error;
				}
				conn->type = HTTP_REQUEST;
				req->method = HTTP_HEAD;
				index = 2;
				state = s_req_method;
			}
			break;

		case s_start_res:
			{
				conn->flags = 0;
				conn->content_length = -1;

				//CALL2(message_begin);

				switch (ch) 
				{
				case 'H':
					state = s_res_H;
					break;

				case CR:
				case LF:
					break;

				default:
					SET_ERRNO(HPE_INVALID_CONSTANT);
					goto error;
				}
				break;
			}

		case s_res_H:
			STRICT_CHECK(ch != 'T');
			state = s_res_HT;
			break;

		case s_res_HT:
			STRICT_CHECK(ch != 'T');
			state = s_res_HTT;
			break;

		case s_res_HTT:
			STRICT_CHECK(ch != 'P');
			state = s_res_HTTP;
			break;

		case s_res_HTTP:
			STRICT_CHECK(ch != '/');
			state = s_res_first_http_major;
			break;

		case s_res_first_http_major:
			if (ch < '0' || ch > '9') 
			{
				SET_ERRNO(HPE_INVALID_VERSION);
				goto error;
			}

			req->http_major = ch - '0';
			state = s_res_http_major;
			break;

			/* major HTTP version or dot */
		case s_res_http_major:
			{
				if (ch == '.') 
				{
					state = s_res_first_http_minor;
					break;
				}

				if (!IS_NUM(ch))
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				req->http_major *= 10;
				req->http_major += ch - '0';

				if (req->http_major > 999) 
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				break;
			}

			/* first digit of minor HTTP version */
		case s_res_first_http_minor:
			if (!IS_NUM(ch)) 
			{
				SET_ERRNO(HPE_INVALID_VERSION);
				goto error;
			}

			req->http_minor = ch - '0';
			state = s_res_http_minor;
			break;

			/* minor HTTP version or end of request line */
		case s_res_http_minor:
			{
				if (ch == ' ') 
				{
					state = s_res_first_status_code;
					break;
				}

				if (!IS_NUM(ch)) 
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				req->http_minor *= 10;
				req->http_minor += ch - '0';

				if (req->http_minor > 999) 
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				break;
			}

		case s_res_first_status_code:
			{
				if (!IS_NUM(ch)) 
				{
					if (ch == ' ') 
					{
						break;
					}

					SET_ERRNO(HPE_INVALID_STATUS);
					goto error;
				}
				conn->status_code = ch - '0';
				state = s_res_status_code;
				break;
			}

		case s_res_status_code:
			{
				if (!IS_NUM(ch)) 
				{
					switch (ch) 
					{
					case ' ':
						state = s_res_status;
						break;
					case CR:
						state = s_res_line_almost_done;
						break;
					case LF:
						state = s_header_field_start;
						break;
					default:
						SET_ERRNO(HPE_INVALID_STATUS);
						goto error;
					}
					break;
				}

				conn->status_code *= 10;
				conn->status_code += ch - '0';

				if (conn->status_code > 999) 
				{
					SET_ERRNO(HPE_INVALID_STATUS);
					goto error;
				}

				break;
			}

		case s_res_status:
			/* the human readable status. e.g. "NOT FOUND"
			* we are not humans so just ignore this */
			if (ch == CR) 
			{
				state = s_res_line_almost_done;
				break;
			}

			if (ch == LF) 
			{
				state = s_header_field_start;
				break;
			}
			break;

		case s_res_line_almost_done:
			STRICT_CHECK(ch != LF);
			state = s_header_field_start;
			break;

		case s_start_req:
			{
				if (ch == CR || ch == LF)
					break;
				conn->flags = 0;
				conn->content_length = -1;

				//CALL2(message_begin);

				if (!IS_ALPHA(ch))
				{
					SET_ERRNO(HPE_INVALID_METHOD);
					goto error;
				}

start_req_method_assign:
				req->method = (enum khttp_method) 0;
				index = 1;
				switch (ch) 
				{
				case 'C': req->method = HTTP_CONNECT; /* or COPY, CHECKOUT */ break;
				case 'D': req->method = HTTP_DELETE; break;
				case 'G': req->method = HTTP_GET; break;
				case 'H': req->method = HTTP_HEAD; break;
				case 'L': req->method = HTTP_LOCK; break;
				case 'M': req->method = HTTP_MKCOL; /* or MOVE, MKACTIVITY, MERGE, M-SEARCH */ break;
				case 'N': req->method = HTTP_NOTIFY; break;
				case 'O': req->method = HTTP_OPTIONS; break;
				case 'P': req->method = HTTP_POST;
					/* or PROPFIND or PROPPATCH or PUT or PATCH */
					break;
				case 'R': req->method = HTTP_REPORT; break;
				case 'S': req->method = HTTP_SUBSCRIBE; break;
				case 'T': req->method = HTTP_TRACE; break;
				case 'U': req->method = HTTP_UNLOCK; /* or UNSUBSCRIBE */ break;
				default:
					SET_ERRNO(HPE_INVALID_METHOD);
					goto error;
				}
				state = s_req_method;
				break;
			}

		case s_req_method:
			{
				const char *matcher;
				if (ch == '\0') 
				{
					SET_ERRNO(HPE_INVALID_METHOD);
					goto error;
				}

				matcher = method_strings[req->method];
				if (ch == ' ' && matcher[index] == '\0')
				{
					state = s_req_spaces_before_url;
				} 
				else if (ch == matcher[index]) 
				{
					; /* nada */
				}
				else if (req->method == HTTP_CONNECT)
				{
					if (index == 1 && ch == 'H') 
					{
						req->method = HTTP_CHECKOUT;
					} 
					else if (index == 2  && ch == 'P')
					{
						req->method = HTTP_COPY;
					} 
					else
					{
						goto error;
					}
				} 
				else if (req->method == HTTP_MKCOL) 
				{
					if (index == 1 && ch == 'O')
					{
						req->method = HTTP_MOVE;
					} 
					else if (index == 1 && ch == 'E') 
					{
						req->method = HTTP_MERGE;
					} 
					else if (index == 1 && ch == '-') 
					{
						req->method = HTTP_MSEARCH;
					} 
					else if (index == 2 && ch == 'A')
					{
						req->method = HTTP_MKACTIVITY;
					} 
					else 
					{
						goto error;
					}
				}
				else if (index == 1 && req->method == HTTP_POST)
				{
					if (ch == 'R') 
					{
						req->method = HTTP_PROPFIND; /* or HTTP_PROPPATCH */
					}
					else if (ch == 'U')
					{
						req->method = HTTP_PUT;
					}
					else if (ch == 'A') 
					{
						req->method = HTTP_PATCH;
					} 
					else 
					{
						goto error;
					}
				}
				else if (index == 2 && req->method == HTTP_UNLOCK && ch == 'S')
				{
					req->method = HTTP_UNSUBSCRIBE;
				} 
				else if (index == 4 && req->method == HTTP_PROPFIND && ch == 'P')
				{
					req->method = HTTP_PROPPATCH;
				} 
				else 
				{
					SET_ERRNO(HPE_INVALID_METHOD);
					goto error;
				}

				++index;
				break;
			}
		case s_req_spaces_before_url:
			{
				if (ch == ' ') 
				{
					break;
				}

				if (ch == '/' || ch == '*')
				{
					MARK(url);
					state = s_req_path;
					break;
				}

				/* Proxied requests are followed by scheme of an absolute URI (alpha).
				* CONNECT is followed by a hostname, which begins with alphanum.
				* All other methods are followed by '/' or '*' (handled above).
				*/
				if (IS_ALPHA(ch) || (req->method == HTTP_CONNECT && IS_NUM(ch))) 
				{
					MARK(url);
					state = (req->method == HTTP_CONNECT) ? s_req_host : s_req_schema;
					break;
				}

				SET_ERRNO(HPE_INVALID_URL);
				goto error;
			}

		case s_req_schema:
			{
				if (IS_ALPHA(ch)) 
				{
					break;
				}

				if (ch == ':') 
				{
					state = s_req_schema_slash;
					break;
				}

				SET_ERRNO(HPE_INVALID_URL);
				goto error;
			}

		case s_req_schema_slash:
			STRICT_CHECK(ch != '/');
			state = s_req_schema_slash_slash;
			break;

		case s_req_schema_slash_slash:
			STRICT_CHECK(ch != '/');
			state = s_req_host;
			break;

		case s_req_host:
			{
				if (IS_HOST_CHAR(ch))
				{
					break;
				}
				switch (ch) 
				{
				case ':':
					state = s_req_port;
					break;
				case '/':
					state = s_req_path;
					break;
				case ' ':
					/* The request line looks like:
					*   "GET http://foo.bar.com HTTP/1.1"
					* That is, there is no path.
					*/
					CALL(url);
					state = s_req_http_start;
					break;
				case '?':
					state = s_req_query_string_start;
					break;
				default:
					SET_ERRNO(HPE_INVALID_HOST);
					goto error;
				}
				break;
			}

		case s_req_port:
			{
				if (IS_NUM(ch)) break;
				switch (ch)
				{
				case '/':
					state = s_req_path;
					break;
				case ' ':
					/* The request line looks like:
					*   "GET http://foo.bar.com:1234 HTTP/1.1"
					* That is, there is no path.
					*/
					CALL(url);
					state = s_req_http_start;
					break;
				case '?':
					state = s_req_query_string_start;
					break;
				default:
					SET_ERRNO(HPE_INVALID_PORT);
					goto error;
				}
				break;
			}

		case s_req_path:
			{
				if (IS_URL_CHAR(ch))
				{
					break;
				}

				switch (ch)
				{
				case ' ':
					CALL(url);
					state = s_req_http_start;
					break;
				case CR:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_req_line_almost_done;
					break;
				case LF:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_header_field_start;
					break;
				case '?':
					state = s_req_query_string_start;
					break;
				case '#':
					state = s_req_fragment_start;
					break;
				default:
					SET_ERRNO(HPE_INVALID_PATH);
					goto error;
				}
				break;
			}

		case s_req_query_string_start:
			{
				if (IS_URL_CHAR(ch))
				{
					state = s_req_query_string;
					break;
				}

				switch (ch) 
				{
				case '?':
					break; /* XXX ignore extra '?' ... is this right? */
				case ' ':
					CALL(url);
					state = s_req_http_start;
					break;
				case CR:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_req_line_almost_done;
					break;
				case LF:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_header_field_start;
					break;
				case '#':
					state = s_req_fragment_start;
					break;
				default:
					SET_ERRNO(HPE_INVALID_QUERY_STRING);
					goto error;
				}
				break;
			}

		case s_req_query_string:
			{
				if (IS_URL_CHAR(ch)) 
				{
					break;
				}

				switch (ch) 
				{
				case '?':
					/* allow extra '?' in query string */
					break;
				case ' ':
					CALL(url);
					state = s_req_http_start;
					break;
				case CR:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_req_line_almost_done;
					break;
				case LF:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_header_field_start;
					break;
				case '#':
					state = s_req_fragment_start;
					break;
				default:
					SET_ERRNO(HPE_INVALID_QUERY_STRING);
					goto error;
				}
				break;
			}

		case s_req_fragment_start:
			{
				if (IS_URL_CHAR(ch)) 
				{
					state = s_req_fragment;
					break;
				}

				switch (ch) 
				{
				case ' ':
					CALL(url);
					state = s_req_http_start;
					break;
				case CR:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_req_line_almost_done;
					break;
				case LF:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_header_field_start;
					break;
				case '?':
					state = s_req_fragment;
					break;
				case '#':
					break;
				default:
					SET_ERRNO(HPE_INVALID_FRAGMENT);
					goto error;
				}
				break;
			}

		case s_req_fragment:
			{
				if (IS_URL_CHAR(ch)) 
				{
					break;
				}

				switch (ch) 
				{
				case ' ':
					CALL(url);
					state = s_req_http_start;
					break;
				case CR:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_req_line_almost_done;
					break;
				case LF:
					CALL(url);
					req->http_major = 0;
					req->http_minor = 9;
					state = s_header_field_start;
					break;
				case '?':
				case '#':
					break;
				default:
					SET_ERRNO(HPE_INVALID_FRAGMENT);
					goto error;
				}
				break;
			}

		case s_req_http_start:
			switch (ch) 
			{
			case 'H':
				state = s_req_http_H;
				break;
			case ' ':
				break;
			default:
				SET_ERRNO(HPE_INVALID_CONSTANT);
				goto error;
			}
			break;

		case s_req_http_H:
			STRICT_CHECK(ch != 'T');
			state = s_req_http_HT;
			break;

		case s_req_http_HT:
			STRICT_CHECK(ch != 'T');
			state = s_req_http_HTT;
			break;

		case s_req_http_HTT:
			STRICT_CHECK(ch != 'P');
			state = s_req_http_HTTP;
			break;

		case s_req_http_HTTP:
			STRICT_CHECK(ch != '/');
			state = s_req_first_http_major;
			break;

			/* first digit of major HTTP version */
		case s_req_first_http_major:
			if (ch < '1' || ch > '9')
			{
				SET_ERRNO(HPE_INVALID_VERSION);
				goto error;
			}

			req->http_major = ch - '0';
			state = s_req_http_major;
			break;

			/* major HTTP version or dot */
		case s_req_http_major:
			{
				if (ch == '.') 
				{
					state = s_req_first_http_minor;
					break;
				}

				if (!IS_NUM(ch))
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				req->http_major *= 10;
				req->http_major += ch - '0';

				if (req->http_major > 999)
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				break;
			}

			/* first digit of minor HTTP version */
		case s_req_first_http_minor:
			if (!IS_NUM(ch)) 
			{
				SET_ERRNO(HPE_INVALID_VERSION);
				goto error;
			}

			req->http_minor = ch - '0';
			state = s_req_http_minor;
			break;

			/* minor HTTP version or end of request line */
		case s_req_http_minor:
			{
				if (ch == CR)
				{
					state = s_req_line_almost_done;
					break;
				}

				if (ch == LF)
				{
					state = s_header_field_start;
					break;
				}

				/* XXX allow spaces after digit? */

				if (!IS_NUM(ch)) 
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				req->http_minor *= 10;
				req->http_minor += ch - '0';

				if (req->http_minor > 999) 
				{
					SET_ERRNO(HPE_INVALID_VERSION);
					goto error;
				}

				break;
			}

			/* end of request line */
		case s_req_line_almost_done:
			{
				if (ch != LF) 
				{
					SET_ERRNO(HPE_LF_EXPECTED);
					goto error;
				}

				state = s_header_field_start;
				break;
			}

		case s_header_field_start:
header_field_start:
			{
				if (ch == CR)
				{
					state = s_headers_almost_done;
					break;
				}

				if (ch == LF) 
				{
					/* they might be just sending \n instead of \r\n so this would be
					* the second \n to denote the end of headers*/
					state = s_headers_almost_done;
					goto headers_almost_done;
				}

				c = TOKEN(ch);

				if (!c) 
				{
					SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
					goto error;
				}

				MARK(header_field);

				index = 0;
				state = s_header_field;

				switch (c) 
				{
				case 'c':
					header_state = h_C;
					break;

				case 'p':
					header_state = h_matching_proxy_connection;
					break;

				case 't':
					header_state = h_matching_transfer_encoding;
					break;

				case 'u':
					header_state = h_matching_upgrade;
					break;

				default:
					header_state = h_general;
					break;
				}
				break;
			}

		case s_header_field:
			{
				c = TOKEN(ch);

				if (c)
				{
					switch (header_state)
					{
					case h_general:
						break;

					case h_C:
						index++;
						header_state = (c == 'o' ? h_CO : h_general);
						break;

					case h_CO:
						index++;
						header_state = (c == 'n' ? h_CON : h_general);
						break;

					case h_CON:
						index++;
						switch (c) 
						{
						case 'n':
							header_state = h_matching_connection;
							break;
						case 't':
							header_state = h_matching_content_length;
							break;
						default:
							header_state = h_general;
							break;
						}
						break;

						/* connection */

					case h_matching_connection:
						index++;
						if (index > sizeof(CONNECTION)-1 || c != CONNECTION[index]) 
						{
							header_state = h_general;
						}
						else if (index == sizeof(CONNECTION)-2) 
						{
							header_state = h_connection;
						}
						break;

						/* proxy-connection */

					case h_matching_proxy_connection:
						index++;
						if (index > sizeof(PROXY_CONNECTION)-1 || c != PROXY_CONNECTION[index])
						{
							header_state = h_general;
						} 
						else if (index == sizeof(PROXY_CONNECTION)-2)
						{
							header_state = h_connection;
						}
						break;

						/* content-length */

					case h_matching_content_length:
						index++;
						if (index > sizeof(CONTENT_LENGTH)-1 || c != CONTENT_LENGTH[index])
						{
							header_state = h_general;
						}
						else if (index == sizeof(CONTENT_LENGTH)-2) 
						{
							header_state = h_content_length;
						}
						break;

						/* transfer-encoding */

					case h_matching_transfer_encoding:
						index++;
						if (index > sizeof(TRANSFER_ENCODING)-1 || c != TRANSFER_ENCODING[index]) 
						{
							header_state = h_general;
						} 
						else if (index == sizeof(TRANSFER_ENCODING)-2) 
						{
							header_state = h_transfer_encoding;
						}
						break;

						/* upgrade */

					case h_matching_upgrade:
						index++;
						if (index > sizeof(UPGRADE)-1 || c != UPGRADE[index]) 
						{
							header_state = h_general;
						}
						else if (index == sizeof(UPGRADE)-2) 
						{
							header_state = h_upgrade;
						}
						break;

					case h_connection:
					case h_content_length:
					case h_transfer_encoding:
					case h_upgrade:
						if (ch != ' ')
						{
							header_state = h_general;
						}
						break;

					default:
						assert(0 && "Unknown header_state");
						break;
					}
					break;
				}

				if (ch == ':') 
				{
					CALL(header_field);
					state = s_header_value_start;
					break;
				}

				if (ch == CR) 
				{
					state = s_header_almost_done;
					CALL(header_field);
					break;
				}

				if (ch == LF) 
				{
					CALL(header_field);
					state = s_header_field_start;
					break;
				}

				SET_ERRNO(HPE_INVALID_HEADER_TOKEN);
				goto error;
			}

		case s_header_value_start:
			{
				if (ch == ' ' || ch == '\t') break;

				MARK(header_value);

				state = s_header_value;
				index = 0;

				if (ch == CR) 
				{
					CALL(header_value);
					CALL2(header_value);
					header_state = h_general;
					state = s_header_almost_done;
					break;
				}

				if (ch == LF) 
				{
					CALL(header_value);
					CALL2(header_value);
					state = s_header_field_start;
					break;
				}

				c = LOWER(ch);

				switch (header_state) 
				{
				case h_upgrade:
					conn->flags |= F_UPGRADE;
					header_state = h_general;
					break;

				case h_transfer_encoding:
					/* looking for 'Transfer-Encoding: chunked' */
					if ('c' == c) 
					{
						header_state = h_matching_transfer_encoding_chunked;
					} 
					else 
					{
						header_state = h_general;
					}
					break;

				case h_content_length:
					if (!IS_NUM(ch)) 
					{
						SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
						goto error;
					}

					conn->content_length = ch - '0';
					break;

				case h_connection:
					/* looking for 'Connection: keep-alive' */
					if (c == 'k')
					{
						header_state = h_matching_connection_keep_alive;
						/* looking for 'Connection: close' */
					}
					else if (c == 'c') 
					{
						header_state = h_matching_connection_close;
					} 
					else 
					{
						header_state = h_general;
					}
					break;

				default:
					header_state = h_general;
					break;
				}
				break;
			}

		case s_header_value:
			{

				if (ch == CR)
				{
					CALL(header_value);
					CALL2(header_value);
					state = s_header_almost_done;
					break;
				}

				if (ch == LF) 
				{
					CALL(header_value);
					CALL2(header_value);
					goto header_almost_done;
				}

				c = LOWER(ch);

				switch (header_state) 
				{
				case h_general:
					break;

				case h_connection:
				case h_transfer_encoding:
					assert(0 && "Shouldn't get here.");
					break;

				case h_content_length:
					if (ch == ' ')
					{
						break;
					}
					if (!IS_NUM(ch)) 
					{
						SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);
						goto error;
					}

					conn->content_length *= 10;
					conn->content_length += ch - '0';
					break;

					/* Transfer-Encoding: chunked */
				case h_matching_transfer_encoding_chunked:
					index++;
					if (index > sizeof(CHUNKED)-1 || c != CHUNKED[index]) 
					{
						header_state = h_general;
					} 
					else if (index == sizeof(CHUNKED)-2) 
					{
						header_state = h_transfer_encoding_chunked;
					}
					break;

					/* looking for 'Connection: keep-alive' */
				case h_matching_connection_keep_alive:
					index++;
					if (index > sizeof(KEEP_ALIVE)-1 || c != KEEP_ALIVE[index]) 
					{
						header_state = h_general;
					}
					else if (index == sizeof(KEEP_ALIVE)-2) 
					{
						header_state = h_connection_keep_alive;
					}
					break;

					/* looking for 'Connection: close' */
				case h_matching_connection_close:
					index++;
					if (index > sizeof(CLOSE)-1 || c != CLOSE[index]) 
					{
						header_state = h_general;
					} 
					else if (index == sizeof(CLOSE)-2) 
					{
						header_state = h_connection_close;
					}
					break;

				case h_transfer_encoding_chunked:
				case h_connection_keep_alive:
				case h_connection_close:
					if (ch != ' ') 
					{
						header_state = h_general;
					}
					break;

				default:
					state = s_header_value;
					header_state = h_general;
					break;
				}
				break;
			}

		case s_header_almost_done:
header_almost_done:
			{
				STRICT_CHECK(ch != LF);

				state = s_header_value_lws;

				switch (header_state) 
				{
				case h_connection_keep_alive:
					conn->flags |= F_CONNECTION_KEEP_ALIVE;
					break;
				case h_connection_close:
					conn->flags |= F_CONNECTION_CLOSE;
					break;
				case h_transfer_encoding_chunked:
					conn->flags |= F_CHUNKED;
					break;
				default:
					break;
				}
				break;
			}

		case s_header_value_lws:
			{
				if (ch == ' ' || ch == '\t')
				{
					state = s_header_value_start;
				}
				else
				{
					state = s_header_field_start;
					goto header_field_start;
				}
				break;
			}

		case s_headers_almost_done:
headers_almost_done:
			{
				STRICT_CHECK(ch != LF);

				if (conn->flags & F_TRAILING) 
				{
					/* End of a chunked request */
					//CALL2(message_complete);
					state = NEW_MESSAGE();
					break;
				}

				nread = 0;

				if (conn->flags & F_UPGRADE || req->method == HTTP_CONNECT) 
				{
					conn->upgrade = 1;
				}

				/* Here we call the headers_complete CALL. This is somewhat
				* different than other CALLs because if the user returns 1, we
				* will interpret that as saying that this message has no body. This
				* is needed for the annoying case of recieving a response to a HEAD
				* request.
				*/
				//if (settings->on_headers_complete)
				//{
				//	switch (settings->on_headers_complete(conn))
				//	{
				//	case 0:
				//		break;

				//	case 1:
				//		conn->flags |= F_SKIPBODY;
				//		break;

				//	default:
				//		conn->state = state;
				//		SET_ERRNO(HPE_CB_headers_complete);
				//		return p - data; /* Error */
				//	}
				//}

				/* Exit, the rest of the connect is in a different protocol. */
				if (conn->upgrade)
				{
					//CALL2(message_complete);
					return (p - data) + 1;
				}

				if (conn->flags & F_SKIPBODY)
				{
					//CALL2(message_complete);
					state = NEW_MESSAGE();
				} else if (conn->flags & F_CHUNKED)
				{
					/* chunked encoding - ignore Content-Length header */
					state = s_chunk_size_start;
				}
				else
				{
					if (conn->content_length == 0) 
					{
						/* Content-Length header given but zero: Content-Length: 0\r\n */
						//CALL2(message_complete);
						state = NEW_MESSAGE();
					} 
					else if (conn->content_length > 0) 
					{
						/* Content-Length header given and non-zero */
						state = s_body_identity;
					}
					else 
					{
						if (conn->type == HTTP_REQUEST || http_should_keep_alive(conn)) 
						{
							/* Assume content-length 0 - read the next */
							//CALL2(message_complete);
							state = NEW_MESSAGE();
						} 
						else 
						{
							/* Read body until EOF */
							state = s_body_identity_eof;
						}
					}
				}

				break;
			}

		case s_body_identity:
			to_read = MIN(pe - p, (int)conn->content_length);
			if (to_read > 0)
			{
				//if (settings->on_body)
				//{
				//	settings->on_body(conn, p, to_read);
				//}
				p += to_read - 1;
				conn->content_length -= to_read;
				if (conn->content_length == 0) 
				{
					//CALL2(message_complete);
					state = NEW_MESSAGE();
				}
			}
			break;

			/* read until EOF */
		case s_body_identity_eof:
			to_read = pe - p;
			if (to_read > 0) 
			{
				//if (settings->on_body)
				//{
				//	settings->on_body(conn, p, to_read);
				//}
				p += to_read - 1;
			}
			break;

		case s_chunk_size_start:
			{
				assert(nread == 1);
				assert(conn->flags & F_CHUNKED);

				unhex_val = unhex[(unsigned char)ch];
				if (unhex_val == -1) 
				{
					SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
					goto error;
				}

				conn->content_length = unhex_val;
				state = s_chunk_size;
				break;
			}

		case s_chunk_size:
			{
				assert(conn->flags & F_CHUNKED);

				if (ch == CR) 
				{
					state = s_chunk_size_almost_done;
					break;
				}

				unhex_val = unhex[(unsigned char)ch];

				if (unhex_val == -1) 
				{
					if (ch == ';' || ch == ' ')
					{
						state = s_chunk_parameters;
						break;
					}

					SET_ERRNO(HPE_INVALID_CHUNK_SIZE);
					goto error;
				}

				conn->content_length *= 16;
				conn->content_length += unhex_val;
				break;
			}

		case s_chunk_parameters:
			{
				assert(conn->flags & F_CHUNKED);
				/* just ignore this shit. TODO check for overflow */
				if (ch == CR) 
				{
					state = s_chunk_size_almost_done;
					break;
				}
				break;
			}

		case s_chunk_size_almost_done:
			{
				assert(conn->flags & F_CHUNKED);
				STRICT_CHECK(ch != LF);

				nread = 0;

				if (conn->content_length == 0) 
				{
					conn->flags |= F_TRAILING;
					state = s_header_field_start;
				}
				else 
				{
					state = s_chunk_data;
				}
				break;
			}

		case s_chunk_data:
			{
				assert(conn->flags & F_CHUNKED);

				to_read = MIN(pe - p, (int)(conn->content_length));

				if (to_read > 0)
				{
					//if (settings->on_body)
					//{
					//	settings->on_body(conn, p, to_read);
					//}
					p += to_read - 1;
				}

				if (to_read == conn->content_length) 
				{
					state = s_chunk_data_almost_done;
				}

				conn->content_length -= to_read;
				break;
			}

		case s_chunk_data_almost_done:
			assert(conn->flags & F_CHUNKED);
			STRICT_CHECK(ch != CR);
			state = s_chunk_data_done;
			break;

		case s_chunk_data_done:
			assert(conn->flags & F_CHUNKED);
			STRICT_CHECK(ch != LF);
			state = s_chunk_size_start;
			break;

		default:
			assert(0 && "unhandled state");
			SET_ERRNO(HPE_INVALID_INTERNAL_STATE);
			goto error;
		}
	}

	if (0 >= strlen(req->url))
	{
		return 0;
	}
	token = strtok(req->url, "?");
	strcpy(req->file, ".");
	strcat(req->file, token);
	do 
	{
		char *paramkey = NULL;
		char *paramval = NULL;
		char *key = strtok(NULL, "=");
		char *val = strtok(NULL, "&");
		if (NULL == key || NULL == val)
		{
			break;
		}
		paramkey = k_malloc(strlen(key)+1);
		paramval = k_malloc(strlen(val)+1);
		strcpy(paramkey, key);
		strcpy(paramval, val);
		krbtree_insert(req->params, paramkey, paramval);
	} while (1);

	conn->state = state;
	conn->header_state = header_state;
	conn->index = index;
	conn->nread = nread;

	return 0;

error:
	if (HTTP_PARSER_ERRNO(conn) == HPE_OK) 
	{
		SET_ERRNO(HPE_UNKNOWN);
	}
	return 1;
}


static void
khttp_connected_cb(ktcp_t tcp, ktcp_session_t session)
{
	khttp_connection_t conn = (khttp_connection_t)session->data;
	if (conn)
	{
		k_free(conn);
	}
	conn = k_malloc_t(khttp_connection);
	if (NULL == conn)
	{
		return;
	}
	khttp_request_init(&conn->req);
	khttp_response_init(&conn->res);
	if (NULL == conn->req || NULL == conn->res)
	{
		khttp_request_uninit(conn->req);
		khttp_response_uninit(conn->res);
		k_free(conn);
	}
	conn->req->conn = conn;
	conn->res->conn = conn;
	conn->session = session;
	conn->data = tcp;
	session->data = conn;
	printf("http client connected fd:%d\n", session->fd);
}

static void
khttp_disconnected_cb(ktcp_t tcp, ktcp_session_t session)
{
	khttp_connection_t conn = (khttp_connection_t)session->data;
	if (NULL != conn)
	{
		khttp_request_uninit(conn->req);
		khttp_response_uninit(conn->res);
		k_free(conn);
	}
	session->data = NULL;
	printf("http client disconnected fd:%d\n", session->fd);
}

static void
khttp_read_cb(ktcp_t tcp, ktcp_session_t session)
{
	khttp_connection_t conn = (khttp_connection_t)session->data;
	khttp_server_t server = (khttp_server_t)tcp->data;
	int len = kbuffer_readable(session->recv_buffer);
	char *data = kbuffer_read(session->recv_buffer, &len);
	if (NULL == conn || NULL == conn->req || NULL == conn->res)
	{
		return;
	}
	printf("%s\n", data);
	if (0 != khttp_request_parse(conn, conn->req, data, len))
	{
		return;
	}
	kbuffer_shift(session->recv_buffer, len);
	if (server && server->request_cb)
	{
		server->request_cb(conn->req, conn->res);
	}
	krbtree_clear(conn->req->heads);
	krbtree_clear(conn->req->params);
}


/************************************************************************/
/*				khttp_server                                            */
/************************************************************************/

int 
khttp_server_init(khttp_server_t *pserver)
{
	*pserver = k_malloc_t(khttp_server);
	if (NULL == *pserver)
	{
		return 1;
	}
	(*pserver)->request_cb = NULL;
	ktcp_init(&(*pserver)->tcp, 4);
	ktcp_set_data((*pserver)->tcp, *pserver);
	ktcp_set_connectedcb((*pserver)->tcp, khttp_connected_cb);
	ktcp_set_disconnectedcb((*pserver)->tcp, khttp_disconnected_cb);
	ktcp_set_readcb((*pserver)->tcp, khttp_read_cb);
	return 0;
}

int 
khttp_server_set_request_cb(khttp_server_t server, khttp_request_cb cb)
{
	if (NULL == server)
	{
		return 1;
	}
	server->request_cb = cb;
	return 0;
}

int 
khttp_server_start(khttp_server_t server, int port, char *root)
{
	server->root_dir = root;
	ktcp_start(server->tcp);
	ktcp_listen(server->tcp, port);
	return 0;
}


int 
khttp_server_uninit(khttp_server_t server)
{


	ktcp_uninit(server->tcp);
	k_free(server);
	return 0;
}

