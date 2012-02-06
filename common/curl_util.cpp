#include <common/curl_util.h>

CurlUtil::CurlUtil()
{
  curl = NULL;
  formpost = NULL;
  headerlist = NULL;
  curl_global_init(CURL_GLOBAL_ALL);
  headerlist = curl_slist_append(headerlist, HEADER_DISABLE_EXPECT);
}

void CurlUtil::send_file(char *full_file_name, char *upload_url)
{
  curl = curl_easy_init();

  // some of this code is from example code in libcurl
  formpost = NULL; lastptr = NULL;

  curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file",
      CURLFORM_FILE, full_file_name, CURLFORM_END);

  curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "submit",
      CURLFORM_COPYCONTENTS, "send", CURLFORM_END);

  if (curl) 
  {
    curl_easy_setopt(curl, CURLOPT_URL, upload_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    //curl_easy_setopt(curl, CURLOPT_HEADER, 1);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    res = curl_easy_perform(curl);
  }
  if (formpost != NULL)
    curl_formfree(formpost);

  clean_up();
}

void CurlUtil::recv_file(char *file_name, char *download_url)
{
  curl = curl_easy_init();
  FILE *fp = fopen(file_name, "wb");
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_FILE, fp);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, download_url);
    //curl_easy_setopt(curl, CURLOPT_HEADER, 1);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    res = curl_easy_perform(curl);
  }
  fclose(fp);

  clean_up();
}

void CurlUtil::get(char *url)
{
  curl = curl_easy_init();
  // do a curl GET (blocking) 
  if (curl)
  {
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    //curl_easy_setopt(curl, CURLOPT_HEADER, 1);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    res = curl_easy_perform(curl);
  }

  clean_up();
}

void CurlUtil::clean_up()
{
  if (curl != NULL)
    curl_easy_cleanup(curl);
}
