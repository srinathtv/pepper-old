#ifndef CODE_PEPPER_COMMON_CURL_UTIL_H_  
#define CODE_PEPPER_COMMON_CURL_UTIL_H_  

#include <curl/curl.h>

#define HEADER_DISABLE_EXPECT "Expect:"

class CurlUtil {
  private:
    CURL *curl;
    CURLcode res;
    struct curl_httppost *formpost;
    struct curl_httppost *lastptr;
    struct curl_slist *headerlist;

    void clean_up();
    
  public:
    CurlUtil();
    void send_file(char *full_file_name, char *upload_url);
    void recv_file(char *full_file_name, char *download_url);
    void get(char *url);
};

#endif  // CODE_PEPPER_COMMON_CURL_UTIL_H_
