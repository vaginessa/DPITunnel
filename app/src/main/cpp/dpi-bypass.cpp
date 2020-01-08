#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <regex>
#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <unistd.h>

#include <curl/curl.h>

#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <jni.h>
#include <android/log.h>

#include "base64.h"

#define  log_debug(...)  __android_log_print(ANDROID_LOG_DEBUG, __VA_ARGS__)
#define  log_error(...)  __android_log_print(ANDROID_LOG_ERROR, __VA_ARGS__)

std::string CONNECTION_ESTABLISHED_RESPONSE("HTTP/1.1 200 Connection established\r\n\r\n");
rapidjson::Document hostlist_document;
std::string app_dir;

struct
{
	struct
	{
		bool is_use_split = false;
		int split_position = 2;
		bool is_use_socks5 = true;
	} https;

	struct
	{
		bool is_use_split = false;
		int split_position = 2;
		bool is_change_host_header = false;
		std::string host_header = "hOsT";
		bool is_add_dot_after_host = false;
		bool is_add_tab_after_host = false;
		bool is_remove_space_after_host = false;
		bool is_add_space_after_method = false;
		bool is_add_newline_before_method = false;
		bool is_use_unix_newline = false;
		bool is_use_socks5 = true;
	} http;

	struct
	{
		bool is_use_doh = true;
		bool is_use_doh_only_for_site_in_hostlist = true;
		std::string dns_server = "https://cloudflare-dns.com";
	} dns;

	bool is_use_hostlist = true;
	std::string socks5_server = "5.133.198.165:8000";
	int bind_port;
} Options;

int find_in_hostlist(std::string host)
{
	for(const auto & host_in_list : hostlist_document.GetArray())
	{
		if(host_in_list.GetString() == host) return 1;
	}
	return 0;
}

int recv_string(int socket, std::string & message)
{
	std::string buffer(1024, ' ');
	ssize_t read_size;
	size_t message_offset = 0;

	// Set receive timeout on socket
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 300;
	if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
	{
		std::cerr << "Can't setsockopt on socket" << std::endl;
		return -1;
	}

	while(true)
	{
	    read_size = recv(socket, &buffer[0], buffer.size(), 0);
	    if(read_size < 0)
	    {
	        if(errno == EWOULDBLOCK)	break;
			if(errno == EINTR)      continue; // All is good. This is just interrrupt.
			else
			{
			    std::cerr << "There is critical read error. Can't process client. Errno: " << std::strerror(errno) << std::endl;
			    return -1;
			}
	    }
		else if(read_size == 0)	return -1;

		if(message_offset + read_size >= message.size()) // If there isn't any space in message string - just increase it
		{
			message.resize(message_offset + read_size + 1024);
		}

		message.insert(message.begin() + message_offset, buffer.begin(), buffer.begin() + read_size);
		message_offset += read_size;
        }

	message.resize(message_offset);

	return 0;
}

int send_string(int socket, std::string string_to_send)
{
    std::string log_tag = "CPP/send_string";

	size_t offset = 0;

	// Set send timeout on socket
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 300;
	if(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
	{
		log_error(log_tag.c_str(), "Can't setsockopt on socket");
		return -1;
	}

	while(string_to_send.size() - offset != 0)
        {
                ssize_t send_size = send(socket, string_to_send.c_str() + offset, string_to_send.size() - offset, 0);
                if(send_size < 0)
                {
                        if(errno == EINTR)      continue; // All is good. This is just interrrupt.
                        else
                        {
                            log_error(log_tag.c_str(), "There is critical send error. Can't process client. Errno: %s", std::strerror(errno));
                            return -1;
                        }
                }
		if(send_size == 0)
		{
			return -1;
		}
                offset += send_size;
        }

	return 0;
}

int send_string_with_split(int socket, std::string string_to_send, unsigned int split_position)
{
    std::string log_tag = "CPP/send_string_with_split";

	FILE *write_socket = fdopen(socket, "w+");
	size_t offset = 0;

	// Set send timeout on socket
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 300;
	if(setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0)
	{
		log_error(log_tag.c_str(), "Can't setsockopt on socket");
		return -1;
	}

	while(string_to_send.size() - offset != 0)
	{
		ssize_t send_size = send(socket, string_to_send.c_str() + offset, string_to_send.size() - offset < split_position ? string_to_send.size() - offset < split_position : split_position, 0);
		if(send_size < 0)
		{
			if(errno == EINTR)	continue; // All is good. This is just interrrupt.
			else
			{
				log_error(log_tag.c_str(), "There is critical send error. Can't process client. Errno: %s", std::strerror(errno));
				fclose(write_socket);
				return -1;
			}
		}
		if(send_size == 0)
		{
			fclose(write_socket);
			return -1;
		}
		fflush(write_socket); // Flush send buffer
		offset += send_size;
	}

	return 0;
}

size_t curlwrite_callback(void *contents, size_t size, size_t nmemb, std::string *s)
{
	size_t newLength = size*nmemb;
	try
	{
		s->append((char *) contents, newLength);
	}
	catch(std::bad_alloc &e)
	{
		return 0;
	}
	return newLength;
}

int resolve_host_over_doh(std::string host, std::string & ip)
{
    std::string log_tag = "CPP/resolve_host_over_doh";

	// Send request to DoH JSON server
	CURL *curl;
	CURLcode response;

	// Init cURL
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if(!curl)
	{
		log_error(log_tag.c_str(), "cURL init failed");
		return -1;
	}

	std::string response_string;

	// Set options
	curl_easy_setopt(curl, CURLOPT_URL, std::string(Options.dns.dns_server + "/dns-query?name=" + host + "&type=A").c_str());

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlwrite_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);

	// Enable ssl
    curl_easy_setopt(curl, CURLOPT_CAINFO, (app_dir + "cacert.pem").c_str());
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

	// Set header
	struct curl_slist *chunk = NULL;
	chunk = curl_slist_append(chunk, std::string("accept: application/dns-json").c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

	// Process request
	response = curl_easy_perform(curl);

	if(response != CURLE_OK)
	{
		log_error(log_tag.c_str(), "Perform request to DoH failed. cURL error: %d", response);
		curl_easy_cleanup(curl);
		curl_global_cleanup();
		return -1;
	}

	// Cleanup cURL
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	// Parse recieved response with rapidjson
	rapidjson::Document response_string_json;
        if(response_string_json.Parse(response_string.c_str()).HasParseError())
        {
            log_error(log_tag.c_str(), "Failed to parse DoH response");
            return -1;
        }

	auto answers_array = response_string_json["Answer"].GetArray();
	ip = answers_array[answers_array.Size() - 1]["data"].GetString();

	return 0;
}

int resolve_host_over_dns(std::string host, std::string & ip)
{
    std::string log_tag = "CPP/resolve_host_over_dns";

	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if(getaddrinfo(host.c_str(), NULL, &hints, &res) != 0)
	{
		log_error(log_tag.c_str(), "Failed to get host address");
		return -1;
	}

	while(res)
	{
		char addrstr[100];
		inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, sizeof(addrstr));
		if(res->ai_family == AF_INET) // If current address is ipv4 address
		{
			void *ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			inet_ntop(res->ai_family, ptr, &ip[0], ip.size());

			size_t first_zero_char = ip.find(' ');
			ip = ip.substr(0, first_zero_char);
			return 0;
		}
		res = res->ai_next;
	}

	return -1;
}

int resolve_host(std::string host, std::string & ip)
{
	if(Options.dns.is_use_doh && (Options.is_use_hostlist ? (Options.dns.is_use_doh_only_for_site_in_hostlist ? find_in_hostlist(host) : true) : true))
	{
		return resolve_host_over_doh(host, ip);
	}
	else
	{
		return resolve_host_over_dns(host, ip);
	}
}

int parse_request(std::string request, std::string & method, std::string & host, int & port)
{
	// Extract method
	size_t method_end_position = request.find(" ");
	if(method_end_position == std::string::npos)
	{
		return -1;
	}
	method = request.substr(0, method_end_position);

	// Extract hostname an port if exists
	std::string regex_string = "[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[-a-z0-9]{2,16}(:[0-9]{1,5})?";
	std::regex url_find_regex(regex_string);
	std::smatch match;

	if(std::regex_search(request, match, url_find_regex) == 0)
	{
		return -1;
	}

	// Get string from regex output
	std::string found_url = match.str(0);

	// Remove "www." if exists
	size_t www = found_url.find("www.");
	if(www != std::string::npos)
	{
		found_url.erase(www, 4);
	}

	// Check if port exists
	size_t port_start_position = found_url.find(":");
	if(port_start_position == std::string::npos)
	{
		// If no set deafult port
		if(method == "CONNECT")	port = 443;
		else port = 80;
		host = found_url;
	}
	else
	{
		// If yes extract port
		port = std::stoi(found_url.substr(port_start_position + 1, found_url.size() - port_start_position));
		host = found_url.substr(0, port_start_position);
	}

	return 0;
}

int init_remote_server_socket(int & remote_server_socket, std::string remote_server_host, int remote_server_port, bool is_https)
{
    std::string log_tag = "CPP/init_remote_server_socket";

	// First task is host resolving
	std::string remote_server_ip(50, ' ');
	if(resolve_host(remote_server_host, remote_server_ip) == -1)
	{
		return -1;
	}

	// Init remote server socker
	struct sockaddr_in remote_server_address;

	if((remote_server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		 log_error(log_tag.c_str(), "Can't create remote server socket");
		return -1;
	}

	// Check if socks5 is need
	if((Options.is_use_hostlist ? find_in_hostlist(remote_server_host) : true) && ((Options.https.is_use_socks5 && is_https) || (Options.http.is_use_socks5 && !is_https)))
	{
		// Parse socks5 server string
		size_t splitter_position = Options.socks5_server.find(':');
		if(splitter_position == std::string::npos)
		{
			log_error(log_tag.c_str(), "Failed to parse SOKCS5 server");
		}
		std::string proxy_ip = Options.socks5_server.substr(0, splitter_position);
		std::string proxy_port = Options.socks5_server.substr(splitter_position + 1, Options.socks5_server.size() - splitter_position - 1);

		// Add port and address
		remote_server_address.sin_family = AF_INET;
		remote_server_address.sin_port = htons(atoi(proxy_port.c_str()));

		if(inet_pton(AF_INET, proxy_ip.c_str(), &remote_server_address.sin_addr) <= 0)
		{
			log_error(log_tag.c_str(), "Invalid proxy server ip address");
			return -1;
		}

		// Connect to remote server
		if(connect(remote_server_socket, (struct sockaddr *) &remote_server_address, sizeof(remote_server_address)) < 0)
		{
			log_error(log_tag.c_str(), "Can't connect to proxy server. Errno: %s", strerror(errno));
			return -1;
		}

		std::string proxy_message_buffer(" ", 3);
		// Send hello packet to proxy server
		proxy_message_buffer[0] = 0x05; // set socks protocol version
		proxy_message_buffer[1] = 0x01; // set number of auth methods
		proxy_message_buffer[2] = 0x00; // set noauth method

		if(send_string(remote_server_socket, proxy_message_buffer) == -1)
		{
			log_error(log_tag.c_str(), "Failed to send hello packet to SOCKS5 proxy server");
			return -1;
		}

		// Receive response from proxy server
		proxy_message_buffer.resize(0);
		do
		{
			if(recv_string(remote_server_socket, proxy_message_buffer) == -1)
			{
				log_error(log_tag.c_str(), "Failed to receive response from proxy server");
				return -1;
			}
		} while(proxy_message_buffer.empty());

		// Check auth method selected by proxy server
		if(proxy_message_buffer[1] != 0x00)
		{
			log_error(log_tag.c_str(), "Proxy server don't support noauth method");
			return -1;
		}

		// Ask proxy server to connect to remote server ip with command packet
		proxy_message_buffer.resize(10);
		proxy_message_buffer[0] = 0x05; // set socks protocol version
		proxy_message_buffer[1] = 0x01; // set tcp protocol
		proxy_message_buffer[2] = 0x00; // reserved field always must be zero
		proxy_message_buffer[3] = 0x01; // ask proxy server to connect to ipv4 address

		// Convert server ip string to int
		uint32_t remote_server_ip_bits = inet_addr(remote_server_ip.c_str());

		// Set remote server ip by 8 bits
		proxy_message_buffer[4] = remote_server_ip_bits & 0xFF;
		proxy_message_buffer[5] = (remote_server_ip_bits & 0xFF00) >> 8;
		proxy_message_buffer[6] = (remote_server_ip_bits & 0xFF0000) >> 16;
		proxy_message_buffer[7] = (remote_server_ip_bits & 0xFF000000) >> 24;

		// Set remote server port by 8 bits
		proxy_message_buffer[8] = remote_server_port >> 8;
		proxy_message_buffer[9] = remote_server_port & 0xFF;

		// Send command packet to proxy server
		if(send_string(remote_server_socket, proxy_message_buffer) == -1)
		{
			log_error(log_tag.c_str(), "Failed to send command packet to proxy server");
			return -1;
		}

		// Receive response from proxy server
		proxy_message_buffer.resize(0);
		do
		{
			if(recv_string(remote_server_socket, proxy_message_buffer) == -1)
			{
				log_error(log_tag.c_str(), "Failed to receive response from proxy server");
				return -1;
			}
		} while(proxy_message_buffer.empty());

		// Check response code
		if(proxy_message_buffer[1] != 0x00)
		{
			log_error(log_tag.c_str(), "Proxy server returned bad response code");
			return -1;
		}
	}
	else
	{
		// Add port and address
		remote_server_address.sin_family = AF_INET;
		remote_server_address.sin_port = htons(remote_server_port);

		if(inet_pton(AF_INET, remote_server_ip.c_str(), &remote_server_address.sin_addr) <= 0)
		{
			log_error(log_tag.c_str(), "Invalid remote server ip address");
			return -1;
		}

		// Connect to remote server
		if(connect(remote_server_socket, (struct sockaddr *) &remote_server_address, sizeof(remote_server_address)) < 0)
		{
			log_error(log_tag.c_str(), "Can't connect to remote server. Errno: %s", strerror(errno));
			return -1;
		}
	}

	return 0;
}

void proxy_https(int client_socket, std::string host, int port)
{
	int remote_server_socket;

	if(init_remote_server_socket(remote_server_socket, host, port, true) == -1)
	{
		return;
	}

	// Search in host list one time to save cpu time
	bool hostlist_condition = Options.is_use_hostlist ? find_in_hostlist(host) : true;

	// Split only first https packet, what contains unencrypted sni
	bool is_clienthello_request = true;

	while(true)
	{
		std::string request(8192, ' ');
		std::string response(8192, ' ');

		if(recv_string(client_socket, request) == -1) // Receive request from client
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}

		// Check if split is need
		if(hostlist_condition && Options.https.is_use_split && is_clienthello_request)
		{
			if(send_string_with_split(remote_server_socket, request, Options.https.split_position) == -1) // Send request to server
			{
				close(remote_server_socket);
				close(client_socket);
				return;
			}
			is_clienthello_request = false;
		}
		else
		{
			if(send_string(remote_server_socket, request) == -1) // Send request to server
			{
				close(remote_server_socket);
				close(client_socket);
				return;
			}
		}

		if(recv_string(remote_server_socket, response) == -1) // Receive response from server
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}

		if(send_string(client_socket, response) == -1) // Send response to client
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}
        }
}

void modify_http_request(std::string & request, bool hostlist_condition)
{
    std::string log_tag = "CPP/modify_http_request";

	if(request.empty()) return;

	// First of all remove url in first string of request
	std::string regex_string = "(https?://)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[-a-z0-9]{2,16}(:[0-9]{1,5})?";
	std::regex url_find_regex(regex_string);
	std::smatch match;
	if(std::regex_search(request, match, url_find_regex) == 0)
	{
		log_error(log_tag.c_str(), "Failed to remove url, while modifying request");
		return;
	}

	// Get string from regex output
	std::string found_url = match.str(0);
	request.replace(request.find(found_url), found_url.size(), "");

	size_t host_header_position = request.find("Host:");
	if(host_header_position == std::string::npos)
	{
		log_error(log_tag.c_str(), "Failed to find Host: header");
		return;
	}

	// Change host spell if need
	if(hostlist_condition && Options.http.is_change_host_header)
	{
		request.replace(host_header_position, Options.http.host_header.size(), Options.http.host_header);
	}

	// Add dot after hostname if need
	if(hostlist_condition && Options.http.is_add_dot_after_host)
	{
		size_t host_header_end = request.find(std::string("\r\n"), host_header_position);
		if(host_header_end != std::string::npos)
		{
			request.insert(host_header_end, ".");
		}
		else
		{
			log_error(log_tag.c_str(), "Failed to add dot after hostname");
		}
	}

	// Add tab after hostname if need
	if(hostlist_condition && Options.http.is_add_tab_after_host)
	{
		size_t host_header_end = request.find(std::string("\r\n"), host_header_position);
		if(host_header_end != std::string::npos)
		{
			request.insert(host_header_end, "\t");
		}
		else
		{
			log_error(log_tag.c_str(), "Failed to add tab after hostname");
		}
	}

	// Remove space after host header if need
	if(hostlist_condition && Options.http.is_remove_space_after_host)
	{
		request.erase(host_header_position + 5, 1);
	}

	size_t method_end_position = request.find(" ");

	// Add space after method if need
	if(hostlist_condition && Options.http.is_add_space_after_method)
	{
		request.insert(method_end_position, " ");
	}

	// Add newline symbol before method if need
	if(hostlist_condition && Options.http.is_add_newline_before_method)
	{
		request.insert(0, "\r\n");
	}

	// Replace all dos newlines(\r\n) with unix style newlines(\n)
	if(hostlist_condition && Options.http.is_use_unix_newline)
	{
		size_t current_dos_newline = 0;
		while(true)
		{
			current_dos_newline = request.find(std::string("\r\n"), current_dos_newline);
			if(current_dos_newline == std::string::npos) break;
			request.erase(current_dos_newline + 1, 1);
		}
	}
}

void proxy_http(int client_socket, std::string host, int port, std::string first_request)
{
	int remote_server_socket;

	if(init_remote_server_socket(remote_server_socket, host, port, false) == -1)
	{
		return;
	}

	// Process first request
	std::string first_response(8192, ' ');

	// Search in host list one time to save cpu time
	bool hostlist_condition = Options.is_use_hostlist ? find_in_hostlist(host) : true;

	// Modify http request to bypass dpi
	modify_http_request(first_request, hostlist_condition);

	// Check if split is need
	if(hostlist_condition && Options.http.is_use_split)
	{
		if(send_string_with_split(remote_server_socket, first_request, Options.http.split_position) == -1) // Send request to serv$
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}
	}
	else
	{
		if(send_string(remote_server_socket, first_request) == -1) // Send request to server
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}
	}

	if(recv_string(remote_server_socket, first_response) == -1) // Receive response from server
	{
		close(remote_server_socket);
		close(client_socket);
		return;
	}

	if(send_string(client_socket, first_response) == -1) // Send response to client
	{
		close(remote_server_socket);
		close(client_socket);
		return;
	}

	while(true)
	{
		std::string request(8192, ' ');
		std::string response(8192, ' ');

		if(recv_string(client_socket, request) == -1) // Receive request from client
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}

		// Modify http request to bypass dpi
		modify_http_request(request, hostlist_condition);

		// Check if split is need
		if(hostlist_condition && Options.http.is_use_split)
		{
			if(send_string_with_split(remote_server_socket, request, Options.http.split_position) == -1) // Send request to serv$
			{
				close(remote_server_socket);
				close(client_socket);
				return;
			}
		}
		else
		{
			if(send_string(remote_server_socket, request) == -1) // Send request to server
			{
				close(remote_server_socket);
				close(client_socket);
				return;
			}
		}

		if(recv_string(remote_server_socket, response) == -1) // Receive response from server
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}

		if(send_string(client_socket, response) == -1) // Send response to client
		{
			close(remote_server_socket);
			close(client_socket);
			return;
		}
	}
}

void process_client(int client_socket)
{
    std::string log_tag = "CPP/process_client";

	std::string request(2048, ' ');

	if(recv_string(client_socket, request) == -1)
	{
		close(client_socket);
		return;
	}

	std::string method;
	std::string host;
	int port;
	if(parse_request(request, method, host, port) == -1)
	{
		log_error(log_tag.c_str(), "Can't parse first http request, so can't process client");
		close(client_socket);
		return;
	}

	if(method == "CONNECT")
	{
		if(send_string(client_socket, CONNECTION_ESTABLISHED_RESPONSE) == -1)
		{
			close(client_socket);
			return;
		}

		proxy_https(client_socket, host, port);
	}
	else
	{
		proxy_http(client_socket, host, port, request);
	}

	close(client_socket);
}

int parse_hostlist()
{
    std::string log_tag = "CPP/parse_hostlist";

	// Open hostlist file
	std::ifstream hostlist_file;
	hostlist_file.open(app_dir + "hostlist.txt");
	if(!hostlist_file)
	{
		log_error(log_tag.c_str(), "Failed to open hostlist file");
		return -1;
	}

	// Create string object from hostlist file
	std::stringstream hostlist_stream;
	hostlist_stream << hostlist_file.rdbuf();
	std::string hostlist_json = hostlist_stream.str();

	// Parse json object with rapidjson
	if(hostlist_document.Parse(hostlist_json.c_str()).HasParseError())
	{
		log_error(log_tag.c_str(), "Failed to parse hostlist file");
		return -1;
	}

	return 0;
}

extern "C" JNIEXPORT void JNICALL Java_ru_evgeniy_dpitunnel_NativeService_setApplicationDirectory(JNIEnv* env, jobject obj, jstring ApplicationDirectory)
{
    if(!ApplicationDirectory) return;

    const char* app_dir_c = env->GetStringUTFChars(ApplicationDirectory, NULL);
    if (!app_dir_c) return;
    const jsize len = env->GetStringUTFLength(ApplicationDirectory);
    app_dir = std::string(app_dir_c, len);

    env->ReleaseStringUTFChars(ApplicationDirectory, app_dir_c);
}

int server_socket;

extern "C" JNIEXPORT jint JNICALL Java_ru_evgeniy_dpitunnel_NativeService_init(JNIEnv* env, jobject obj, jobject prefs_object)
{
    std::string log_tag = "CPP/init";

    jclass prefs_class = env->FindClass("android/content/SharedPreferences");
    if(prefs_class == NULL)
    {
        log_error(log_tag.c_str(), "Failed to find SharedPreferences class");
        return -1;
    }

    jmethodID prefs_getInt = env->GetMethodID(prefs_class, "getInt", "(Ljava/lang/String;I)I");
    if(prefs_getInt == NULL)
    {
        log_error(log_tag.c_str(), "Failed to find getInt method");
        return -1;
    }



	// Parse hostlist if need
	if(Options.is_use_hostlist)
	{
		if(parse_hostlist() == -1)
		{
			return -1;
		}
	}

	// Create socket
	if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		log_error(log_tag.c_str(), "Can't create server socket");
		return -1;
	}

	// Set options for socket
	int opt = 1;
	if(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)))
	{
        log_error(log_tag.c_str(), "Can't setsockopt on server socket. Errno: %s", strerror(errno));
		return -1;
	}
	// Server address options
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = INADDR_ANY;
	server_address.sin_port = htons(env->CallIntMethod(prefs_object, prefs_getInt, env->NewStringUTF("bind_port"), 8080));

	// Bind socket
	if(bind(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0)
	{
		log_error(log_tag.c_str(), "Can't bind server socket. Errno: %s", strerror(errno));
		return -1;
	}

	// Listen to socket
	if(listen(server_socket, 10) < 0)
	{
		log_error(log_tag.c_str(), "Can't listen to server socket");
		return -1;
	}

	return 0;
}

extern "C" JNIEXPORT void Java_ru_evgeniy_dpitunnel_NativeService_acceptClient(JNIEnv* env, jobject obj)
{
    std::string log_tag = "CPP/acceptClient";

    //Accept client
    int client_socket;
    struct sockaddr_in client_address;
    socklen_t client_address_size = sizeof(client_address);
    if((client_socket = accept(server_socket, (sockaddr *) &client_address, &client_address_size)) < 0)
    {
        log_error(log_tag.c_str(), "Can't accept client socket. Error: %s", std::strerror(errno));
        return;
    }

    // Process client
    if(fork() == 0)
    {
        process_client(client_socket);
        exit(0);
    }
}

extern "C" JNIEXPORT void Java_ru_evgeniy_dpitunnel_NativeService_deInit(JNIEnv* env, jobject obj)
{
    std::string log_tag = "CPP/deInit";

    if(shutdown(server_socket, SHUT_RDWR) == -1)
    {
        log_error(log_tag.c_str(), "Can't shutdown server socket. Errno: %s", strerror(errno));
    }
    if(close(server_socket) == -1)
    {
        log_error(log_tag.c_str(), "Can't close server socket. Errno: %s", strerror(errno));
    }
}