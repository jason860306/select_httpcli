// cli.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <sstream>

#ifdef WIN32
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include "uriparser.h"
#include "json.h"

#define HTTP_URL "http://182.18.58.2:8095/stream//output/989C7F2B44312693A5530C7F02C04033_263947_1080P_optimizateProcess.bhd"
#define FILE_PATH "bf.bhd"
#define READ_BUF 524288

enum STATUS_TYPE
{
	STATUS_OK = 0,
	STATUS_ERR_SYS = 98,
	STATUS_ERR_REQ_METHOD = 99,
	STATUS_ERR_INVALID_TOKEN = 100,
	STATUS_ERR_LIVE_CHANNEL_CREATE = 101,
};

#ifdef WIN32
typedef SOCKET sock_fd_t;
#define INVALID_SOCK_FD INVALID_SOCKET
#define SOCK_ERR SOCKET_ERROR
#define HOST404 WSAHOST_NOT_FOUND
#define HOST_NO_DATA WSANO_DATA
#define ERR_INPROGRESS WSAEWOULDBLOCK
#else
typedef int32_t sock_fd_t;
#define INVALID_SOCK_FD (-1)
#define SOCK_ERR (-1)
#define HOST404 HOST_NOT_FOUND
#define HOST_NO_DATA NO_DATA
#define ERR_INPROGRESS EINPROGRESS
#endif

#ifdef WIN32
int32_t init_winsock();
int32_t uninit_winsock();
#endif

int32_t set_nonblock(sock_fd_t fd);
void close_sock_fd(sock_fd_t fd);
int32_t get_last_err();

int32_t vscprintf(const char *fmt, va_list args);

void format_string_v(std::string& result, const char *format, va_list arg_list);
std::string format_string(const char *format, ...);
std::string get_loctime_str(time_t t = time(NULL));
int get_sock_spec_err(sock_fd_t sock);
std::string gen_http_head(const std::string &url, size_t body_len);
std::string gen_http_body(const std::string &token);

void parse_http_body(const std::string &http_body);
void parse_http_response(const std::string &http_response);

#define CHANNELUTIL_LOG(fmt, ...)	    				\
	do                                              	\
	{                                               	\
		fprintf(stdout, "[%s] >> %s[%d]: " fmt "\n",	\
			get_loctime_str().c_str(), __FUNCTION__,	\
			__LINE__, ##__VA_ARGS__);					\
	} while (0)

int main(int argc, char* argv[])
{
	if (argc > 2)
	{
		CHANNELUTIL_LOG("usage: %s url", argv[0]);
		return -1;
	}

#ifdef WIN32
	struct __init_sock
	{
		__init_sock() { init_winsock(); }
		~__init_sock() { uninit_winsock(); }
	} init_sock;
#endif

	int32_t ret = -1;

	char rd_buf[READ_BUF] = { 0 };
	const char *url = (argc == 1 ? HTTP_URL : argv[1]), *token = NULL;
	uint16_t port = 0;
	struct sockaddr_in srv_addr;
	struct hostent *rmt_host = NULL;
	CUriParser uri_parser(url);
	std::string http_req_head, http_req_body, http_req_buf, http_res_buf;
	size_t rd_pos = 0, content_len = 0, total_len = 0;
	fd_set fd_read, fd_write, fd_error;

	FILE *down_file = NULL;

	port = uri_parser.getPort();

	if (NULL == (rmt_host = gethostbyname(uri_parser.getHost().c_str())))
	{
		CHANNELUTIL_LOG("fetch ip from url(: %s) failed", url);
		int32_t err = get_last_err();
		if (err != 0)
		{
			if (err == HOST404)
			{
				CHANNELUTIL_LOG("host not found");
				return (ret = -1);
			}
			else if (err == HOST_NO_DATA)
			{
				CHANNELUTIL_LOG("no token record found");
				return (ret = -1);
			}
			else
			{
				CHANNELUTIL_LOG("function failed with error: %d", err);
				return (ret = -1);
			}
		}
		return (ret = -1);
	}

	CHANNELUTIL_LOG("function returned:");
	CHANNELUTIL_LOG("\toffic_name: %s", rmt_host->h_name);
	for (char **alias = rmt_host->h_aliases; *alias != 0; alias++)
	{
		CHANNELUTIL_LOG("\talter_name: %s", *alias);
	}
	CHANNELUTIL_LOG("\taddr_len: %d", rmt_host->h_length);

	srv_addr.sin_family = rmt_host->h_addrtype;
	srv_addr.sin_port = htons(port);
	srv_addr.sin_addr = *(struct in_addr *) rmt_host->h_addr_list[0];
	CHANNELUTIL_LOG("\tip_addr: %s", inet_ntoa(srv_addr.sin_addr));

	int32_t sock_err = SOCK_ERR;
	sock_fd_t sock_fd = ::socket(rmt_host->h_addrtype, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCK_FD == sock_fd)
	{
		CHANNELUTIL_LOG("create socket_imp failed: %d", get_last_err());
		goto Exit;
	}

	if (::connect(sock_fd, (struct sockaddr *)&srv_addr,
		sizeof(srv_addr)) == SOCK_ERR)
	{
		CHANNELUTIL_LOG("connect server failed: %d", sock_err);
		goto Exit;
	}

	if (0 != set_nonblock(sock_fd))
	{
		goto Exit;
	}

	if (NULL == (down_file = fopen(FILE_PATH, "wb+")))
	{
		goto Exit;
	}

	//	http_req_body = gen_http_body(token);
	http_req_head = gen_http_head(url, http_req_body.size());
	http_req_buf.assign(http_req_head).append(http_req_body);

	while (true)
	{
		FD_ZERO(&fd_read);
		FD_ZERO(&fd_write);
		FD_ZERO(&fd_error);

		FD_CLR(sock_fd, &fd_read);
		FD_CLR(sock_fd, &fd_write);
		FD_CLR(sock_fd, &fd_error);

		FD_SET(sock_fd, &fd_read);
		if (!http_req_buf.empty())
		{
			FD_SET(sock_fd, &fd_write);
		}
		FD_SET(sock_fd, &fd_error);

		struct timeval tv;
		tv.tv_sec = 2;
		tv.tv_usec = 0;

		int32_t fd_num = 0;
		if ((fd_num = ::select(sock_fd + 1, &fd_read, &fd_write,
			&fd_error, &tv) == SOCK_ERR))
		{
			CHANNELUTIL_LOG("select failed: %d", get_last_err());
			goto Exit;
		}

		if (FD_ISSET(sock_fd, &fd_write))
		{
			if (http_req_buf.empty())
			{
				continue;
			}
			if (get_sock_spec_err(sock_fd) < 0)
			{
				CHANNELUTIL_LOG("socket_imp error: ");
				goto Exit;
			}
			if (::send(sock_fd, http_req_buf.data(),
					   http_req_buf.size(), 0) == SOCK_ERR)
			{
				if (ERR_INPROGRESS != (sock_err = get_last_err()))
				{
					CHANNELUTIL_LOG("send token failed: %d", sock_err);
					goto Exit;
				}
			}
			CHANNELUTIL_LOG("send http request: \r\n%s", http_req_buf.c_str());
			http_req_head.clear();
			http_req_body.clear();
			http_req_buf.clear();
		}

		if (FD_ISSET(sock_fd, &fd_read))
		{
			size_t buf_len = 0, rd_size = 0, has_size = 0, remain_size = 0;
			char *buf = NULL;
			has_size = rd_pos % READ_BUF;
			buf = rd_buf + has_size;
			buf_len = READ_BUF - has_size;
			if (0 != total_len)
			{
				remain_size = total_len - http_res_buf.size();
				buf_len = remain_size < buf_len ? remain_size : buf_len;
			}
			if (get_sock_spec_err(sock_fd) < 0)
			{
				CHANNELUTIL_LOG("socket_imp error: ");
				goto Exit;
			}
			if ((int32_t)(rd_size = ::recv(sock_fd, buf, buf_len, 0)) == SOCK_ERR)
			{
				if (ERR_INPROGRESS != (sock_err = get_last_err()))
				{
					CHANNELUTIL_LOG("receive http response failed: %d", sock_err);
					goto Exit;
				}
			}
			else if (rd_size == 0)
			{
				CHANNELUTIL_LOG("socket_imp is closed");
				goto Exit;
			}
			rd_pos += rd_size;

			if (0 == content_len)
			{
				http_res_buf.append(buf, rd_size);

				const char *tmp_buf = NULL, *data = NULL, *content_beg = NULL, *content_end = NULL;
				tmp_buf = strstr(http_res_buf.c_str(), "\r\n\r\n");
				if (NULL == tmp_buf)
				{
					continue;
				}
				if (NULL == (content_beg = strstr(http_res_buf.c_str(),
												  "Content-Length:")))
				{
					continue;
				}
				content_beg += sizeof("Content-Length:");
				if (NULL == (content_end = strstr(content_beg, "\r\n")))
				{
					continue;
				}
				content_len = strtoul(content_beg, NULL, 10);

				data = tmp_buf + sizeof("\r\n\r\n");
				size_t hdr_size = (data - 1 - http_res_buf.c_str());
				total_len = hdr_size + content_len;

				uint64_t data_len = http_res_buf.size() - hdr_size;
				if (0 != data_len)
				{
					fwrite(data, data_len, 1, down_file);
				}

				if (http_res_buf.size() == total_len)
				{
					CHANNELUTIL_LOG("recv http response finish: \r\n%s", http_res_buf.c_str());
					break;
				}

				CHANNELUTIL_LOG("recv http response: %s", http_res_buf.c_str());
			}
			else
			{
				fwrite(buf, rd_size, 1, down_file);
			}
		}

		if (FD_ISSET(sock_fd, &fd_error))
		{
			CHANNELUTIL_LOG("server is ESTABLISHED: %d", get_last_err());
			goto Exit;
		}
	}
	// parse_http_response(http_res_buf);

Exit:
	if (NULL != down_file)
	{
		fflush(down_file);
		fclose(down_file);
	}
	close_sock_fd(sock_fd);
	return ret;
}

void format_string_v(std::string& result, const char *format,
	va_list arg_list)
{
	result.clear();
	int size = vscprintf(format, arg_list);
	char *buffer = (char *)malloc(size + 1);
	if (buffer)
	{
		vsprintf(buffer, format, arg_list);
		result = buffer;
		free(buffer);
	}
}

std::string format_string(const char *format, ...)
{
	std::string result;

	va_list arg_list;
	va_start(arg_list, format);
	format_string_v(result, format, arg_list);
	va_end(arg_list);

	return result;
}

std::string get_loctime_str(time_t t)
{
	int32_t year, month, day, hour, minute, second;
	struct tm tm;
#ifdef WIN32
	localtime_s(&tm, &t);
#else
	localtime_r(&t, &tm);
#endif
	year = tm.tm_year + 1900;
	month = tm.tm_mon + 1;
	day = tm.tm_mday;
	hour = tm.tm_hour;
	minute = tm.tm_min;
	second = tm.tm_sec;
	return ::format_string("%04d-%02d-%02d %02d:%02d:%02d",
		year, month, day, hour, minute, second);
}

#ifdef WIN32
int32_t init_winsock()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int status;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	status = WSAStartup(wVersionRequested, &wsaData);
	if (status != 0)
	{
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
		CHANNELUTIL_LOG("WSAStartup failed with error: %d\n", status);
		return -1;
	}

	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		CHANNELUTIL_LOG("Could not find a usable version of Winsock.dll\n");
		uninit_winsock();
		return -1;
	}

	return 0;
}

int32_t uninit_winsock()
{
	/* then call WSACleanup when done using the Winsock dll */

	WSACleanup();
	return 0;
}

#endif

int32_t set_nonblock(sock_fd_t fd)
{
#ifdef WIN32
	unsigned long non_block = 1;
	if (::ioctlsocket(fd, FIONBIO, &non_block) == SOCK_ERR)
	{
		CHANNELUTIL_LOG("set socket_imp to non-block failed: %d", WSAGetLastError());
		return -1;
	}
#else
	int flag;
	if ((flag = fcntl(fd, F_GETFL, 0)) < 0)
	{
		CHANNELUTIL_LOG("get flag");
	}
	flag |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flag) < 0)
	{
		CHANNELUTIL_LOG("set socket_imp to non-block failed: %d", errno);
		return -1;
	}
#endif
	return 0;
}

void close_sock_fd(sock_fd_t fd)
{
#ifdef WIN32
	::closesocket(fd);
#else
	::close(fd);
#endif
}

int32_t get_last_err()
{
#ifdef WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

int32_t vscprintf(const char *fmt, va_list args)
{
#ifdef WIN32
	return _vscprintf(fmt, args);
#else
	int retval;
	va_list argcopy;
	va_copy(argcopy, args);
	retval = vsnprintf(NULL, 0, fmt, argcopy);
	va_end(argcopy);
	return retval;
#endif
}

//When using select() multiple sockets may have errors
//This function will give us the socket_imp specific error
//WSAGetLastError() can't be relied upon
int get_sock_spec_err(sock_fd_t sock)
{
	int opt_val;
	int opt_val_len = sizeof(opt_val);
	//Get error code specific to this socket_imp
	getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&opt_val,
			   (socklen_t *)&opt_val_len);
	return opt_val;
}

std::string gen_http_head(const std::string &url, size_t /*body_len*/)
{
	CUriParser uri_parser(url);

	std::ostringstream ostrm;
	ostrm << "GET " << uri_parser.getPathEtc() << " HTTP/1.1\r\n"
		   << "HOST: " << uri_parser.getHost() << "\r\n"
		   << "Connection: Close\r\n\r\n";

	return ostrm.str();
}

std::string gen_http_body(const std::string &token)
{
	return "";
}

void parse_http_body(const std::string &http_body)
{
	if (http_body.empty())
	{
		return;
	}
	int32_t status = 0;
	std::string channel_id, gcid, url;

	cJSON *json_root = NULL, *json_status = NULL, *json_url = NULL;
	cJSON *json_channel_id = NULL, *json_gcid = NULL;
	if (NULL == (json_root = cJSON_Parse(http_body.c_str())))
	{
		CHANNELUTIL_LOG("cJSON_Parse failed!");
		goto Exit;
	}
	if (NULL == (json_status = cJSON_GetObjectItem(json_root, "status")))
	{
		CHANNELUTIL_LOG("cJSON_GetObjectItem(: status) failed!");
		goto Exit;
	}
	status = static_cast<char>(json_status->valueint);
	if (status != STATUS_OK)
	{
		switch (status)
		{
		case STATUS_ERR_SYS:
			CHANNELUTIL_LOG("status: %d - ϵͳ����", status);
			break;
		case STATUS_ERR_REQ_METHOD:
			CHANNELUTIL_LOG("status: %d - ����ķ�����֧��", status);
			break;
		case STATUS_ERR_INVALID_TOKEN:
			CHANNELUTIL_LOG("status: %d - token��Ч", status);
			break;
		case STATUS_ERR_LIVE_CHANNEL_CREATE:
			CHANNELUTIL_LOG("status: %d - ����ֱ��Ƶ��ʧ��", status);
			break;
		default:
			break;
		}
		goto Exit;
	}
	CHANNELUTIL_LOG("status: %d - ����ֱ��Ƶ���ɹ�", status);
	if (NULL == (json_channel_id = cJSON_GetObjectItem(json_root, "channelid")))
	{
		CHANNELUTIL_LOG("cJSON_GetObjectItem(: channelid) failed!");
		goto Exit;
	}
	channel_id = json_channel_id->valuestring;
	CHANNELUTIL_LOG("channel_id: %s", channel_id.c_str());
	if (NULL == (json_gcid = cJSON_GetObjectItem(json_root, "gcid")))
	{
		CHANNELUTIL_LOG("cJSON_GetObjectItem(: gcid) failed!");
		goto Exit;
	}
	gcid = json_gcid->valuestring;
	CHANNELUTIL_LOG("gcid: %s", gcid.c_str());
	if (NULL == (json_url = cJSON_GetObjectItem(json_root, "url")))
	{
		CHANNELUTIL_LOG("cJSON_GetObjectItem(: url) failed!");
		goto Exit;
	}
	url = json_url->valuestring;
	CHANNELUTIL_LOG("url: %s", url.c_str());

Exit:
	if (NULL != json_root)
	{
		cJSON_Delete(json_root);
		json_root = NULL;
	}
}

void parse_http_response(const std::string &http_response)
{
	if (http_response.empty())
	{
		return;
	}
	int32_t http_status = 0;
	std::string::size_type status_pos = std::string::npos;
	if (std::string::npos == (status_pos = http_response.find("HTTP/1.1")))
	{
		CHANNELUTIL_LOG("invalid http response head");
		return;
	}
	status_pos += sizeof("HTTP/1.1");
	http_status = atoi(http_response.c_str() + status_pos);
	CHANNELUTIL_LOG("http status: %u", http_status);

	std::string::size_type body_pos = std::string::npos;
	if (std::string::npos == (body_pos = http_response.find(
								  "\r\n\r\n", status_pos)))
	{
		CHANNELUTIL_LOG("invalid http response body");
		return;
	}
	body_pos += sizeof("\r\n\r\n") - 1;
	parse_http_body(http_response.substr(body_pos));
}
