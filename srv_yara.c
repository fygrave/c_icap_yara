#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "body.h"
#include "simple_api.h"
#include "lookup_table.h"
#include "debug.h"
#include "access.h"
#include "acl.h"
#include "../../common.h"
#include "commands.h"
#include "ci_threads.h"
#include <yara.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>


#define LOG_URL_SIZE 1024
#define YARA_MAX_RESULT_LENGTH 65536

YARA_CONTEXT* yara_context = NULL;
static ci_off_t MAX_OBJECT_SIZE = 5*1024*1024;
static ci_thread_mutex_t yara_scan_mutex;

int yara_init_service (ci_service_xdata_t * srv_xdata,
                       struct ci_server_conf *server_conf);
void *yara_init_request_data (ci_request_t * req);
void yara_release_data (void *data);

int yara_process (ci_request_t *);
int yara_preview (char *preview_data, int preview_data_len, ci_request_t *);
int yara_io (char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
             ci_request_t * req);
void yara_close_service ();
/* misc */

void print_hex_string(char* rez, unsigned int rez_size, char* buffer, unsigned int buffer_size, unsigned int offset, unsigned int length);
void print_string(char* rez, unsigned int rez_size, char* buffer, unsigned int buffer_size, unsigned int offset, unsigned int length, int unicode);



/* config */
int yara_cfg_load_path (char *directive, char **argv, void *setdata);

static struct ci_conf_entry conf_variables[] = {
  {"YARAPath", NULL, yara_cfg_load_path, NULL},
  {"MaxObjectSize", &MAX_OBJECT_SIZE, ci_cfg_size_off, NULL},
/* {"YaraMaxObjectSize", &MAX_OBJECT_SIZE, ci_cfg_size_off, NULL}, */
};

CI_DECLARE_MOD_DATA ci_service_module_t service = {
  "srv_yara",
  "Yara pattern match and forensics",
  ICAP_RESPMOD,
  yara_init_service,            /* init_service */
  NULL,                         /*post_init_service */
  yara_close_service,           /*close_Service */
  yara_init_request_data,       /* init_request_data */
  yara_release_data,            /*Release request data */
  yara_preview,
  yara_process,                 /* processing */
  yara_io,
  conf_variables,
  NULL
};


typedef struct _IDENTIFIER
{
	char*			name;
	struct _IDENTIFIER*	next;

} IDENTIFIER;


typedef struct yara_data
{
  ci_simple_file_t *body;
  ci_request_t *req;
  char *match_name;
  ci_membuf_t *ident;
  int ident_len;
  ci_membuf_t *error_page;
  char url_log[LOG_URL_SIZE];
  int matched;
} yara_data_t;

int YARA_DATA_POOL = -1;


/* misc functions */
void yara_error_page (yara_data_t * data, ci_request_t * req);
void yara_report_error(const char* file_name, int line_number, const char* error_message);
int yara_callback(RULE* rule, unsigned char* buffer, unsigned int buffer_size, void* data);
int yara_initialize_context();
char *yara_get_matches(IDENTIFIER *base, int len);


int
yara_init_service (ci_service_xdata_t * srv_xdata,
                   struct ci_server_conf *server_conf)
{
  ci_debug_printf (2, "Initializing yara module ..\n");
  ci_service_set_preview (srv_xdata, 0);
  ci_service_enable_204 (srv_xdata);
  YARA_DATA_POOL =
    ci_object_pool_register ("yara_data", sizeof (yara_data_t));
  /* initialize yara api */
  if (yara_context == NULL)
      yara_initialize_context();
  ci_thread_mutex_init(&yara_scan_mutex);
  //yara_context->fast_match = TRUE;
  /* load yara patterns here */
  ci_debug_printf (2, "Loading Yara patterns..\n");
  if (YARA_DATA_POOL < 0)
    return CI_ERROR;
  return CI_OK;

}

void
yara_close_service ()
{
  ci_object_pool_unregister (YARA_DATA_POOL);
  //ci_thread_mutex_destoy(&yara_scan_mutex);
  yr_destroy_context(yara_context);
  return;
}

void *
yara_init_request_data (ci_request_t * req)
{
  yara_data_t *uc = ci_object_pool_alloc (YARA_DATA_POOL);
  uc->body = NULL;
  uc->match_name = NULL;
  uc->error_page = NULL;
  uc->matched = 0;
  uc->ident = NULL;
  uc->ident_len = 0;
  uc->req = req;

  if (req->args)
    {
      ci_debug_printf (5, "service arguments:%s\n", req->args);
    }
  return uc;
}

void
yara_release_data (void *data)
{
  yara_data_t *uc = data;
  IDENTIFIER *id, *next_id;

  ci_debug_printf (5, "Yara release data\n");
  if (uc)
    {
      if (uc->body)
        ci_simple_file_destroy (uc->body);

      if (uc->error_page)
        ci_membuf_free (uc->error_page);
      if (uc->match_name)
        ci_buffer_free (uc->match_name);
      id = (IDENTIFIER *)uc->ident;
      while (id != NULL) {
        next_id = id->next;
        if (id->name != NULL)
            ci_buffer_free(id->name);
        ci_membuf_free((ci_membuf_t *)id);
        id = next_id;
      }
      ci_object_pool_free (uc);
    }
}

int
yara_preview (char *preview_data, int preview_data_len, ci_request_t * req)
{

  yara_data_t *uc = ci_service_data (req);
  ci_debug_printf (5, "Yara preview handler\n");
  ci_http_request_url (req, uc->url_log, LOG_URL_SIZE);

/*
	if (uc->args.sizelimit && MAX_OBJECT_SIZE
              && ci_http_content_length(req) > MAX_OBJECT_SIZE) {
               ci_debug_printf(1,
                               "Object size is %" PRINTF_OFF_T " ."
                               " Bigger than max scannable file size (%"
                               PRINTF_OFF_T "). Allow it.... \n",
			       (CAST_OFF_T) ci_http_content_length(req),
                               (CAST_OFF_T) MAX_OBJECT_SIZE);
               return CI_MOD_ALLOW204;
          }
*/
  int clen = ci_http_content_length (req) + 100;
  ci_debug_printf(2, "Data len %i\n", clen);
  uc->body = ci_simple_file_new (MAX_OBJECT_SIZE);


  if (!uc->body)
    return CI_ERROR;
  if (preview_data_len)
    {
      if (ci_simple_file_write (uc->body, preview_data, preview_data_len,
                                ci_req_hasalldata (req)) == CI_ERROR)
        return CI_ERROR;
    }

  /*We are going to proceed scanning this object log its url */
  ci_http_request_url (req, uc->url_log, LOG_URL_SIZE);
  return CI_MOD_CONTINUE;

}

int
yara_read_from_net (char *buf, int len, int iseof, ci_request_t * req)
{

  yara_data_t *data = ci_service_data (req);
  if (!data)
    return CI_ERROR;
  if (!data->body)
    return len;
  return ci_simple_file_write (data->body, buf, len, iseof);
}

int
yara_write_to_net (char *buf, int len, ci_request_t * req)
{
  int bytes = 0;
  yara_data_t *data = ci_service_data (req);
  if (!data)
    return CI_ERROR;
  if (data->match_name && data->error_page)
    return ci_membuf_read (data->error_page, buf, len);
  if (data->body)
    bytes = ci_simple_file_read (data->body, buf, len);
  else
    bytes = 0;
  return bytes;
}


int
yara_io (char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
         ci_request_t * req)
{
  int ret = CI_OK;
  if (rbuf && rlen)
    {
      *rlen = yara_read_from_net (rbuf, *rlen, iseof, req);
      if (*rlen == CI_ERROR)
        return CI_ERROR;
      else if (*rlen < 0)
        ret = CI_OK;
    }
  else if (iseof)
    {
      if (yara_read_from_net (NULL, 0, iseof, req) == CI_ERROR)
        return CI_ERROR;
    }

  if (wbuf && wlen)
    {
      *wlen = yara_write_to_net (wbuf, *wlen, req);
    }
  return CI_OK;
}

int
yara_process (ci_request_t * req)
{
  yara_data_t *data = ci_service_data (req);
  ci_simple_file_t *body;

  if (!data || !data->body)
    return CI_MOD_DONE;
  body = data->body;
  ci_debug_printf (2, "Scan from file\n");
  ci_debug_printf (2, "file %s\n", body->filename);
  ci_debug_printf (5, "URL %s\n", data->url_log);

/* yara matching done here */

  ci_thread_mutex_lock(&yara_scan_mutex);
  yr_scan_file(body->filename, yara_context, yara_callback, (void*) req);
  ci_thread_mutex_unlock(&yara_scan_mutex);

  ci_debug_printf (2, "Matching done\n");
  if (data->matched > 0)
    {
      data->match_name = yara_get_matches((IDENTIFIER *)data->ident, data->ident_len);

      ci_debug_printf (2, "Matched! generating error page: %i\n", data->matched);
      if (!req)
        ci_debug_printf (2, "Req is NULL!\n");
      if (!ci_req_sent_data (req))
        {
          yara_error_page (data, req);
        }
      else
        return CI_MOD_DONE;
    }
  else
    {

      if (!ci_req_sent_data (req))
        {
          ci_debug_printf (2, "yara module: Respond with allow 204\n");
          return CI_MOD_ALLOW204;
        }

      ci_simple_file_unlock_all (body); /*Unlock all data to continue send them..... */
      ci_debug_printf (2,
                       "file unlocked, flags :%d (unlocked:%" PRINTF_OFF_T
                       ")\n", body->flags, (CAST_OFF_T) body->unlocked);
      return CI_MOD_DONE;



    }

 return CI_MOD_DONE;
}

/* helper functions */


static const char *yara_error_message =
  "<html>\n"
  "<head>\n"
  "<!--C-ICAP/" VERSION " YARA module -->\n"
  "</head>\n"
  "<body>\n"
  "<H1>YARA CONTENT MATCHED</H1>\n\n"
  "You try to access file that matches yara rules<br>\n \nX-YARA-Data: Type=0; Resolution=2; Threat=[";
static const char *yara_tail_message =
  "];\r\n<p>This message generated by C-ICAP/" VERSION " YARA module\n"
  "</body>\n" "</html>\n";

void
yara_error_page (yara_data_t * data, ci_request_t * req)
{

  ci_debug_printf (2, "Building error page\n");
  int new_size = 0;
  ci_membuf_t *error_page;
  char buf[1024];
  ci_debug_printf (2, "Building error page\n");

  snprintf (buf, 1024, "X-YARA-Match: Type=0; Resolution=2; Threat=Match;");
  buf[1023] = '\0';
  ci_icap_add_xheader (req, buf);
  new_size =
    strlen (yara_error_message) + strlen (yara_tail_message) +
    strlen (data->match_name) + 10;
  if (ci_http_response_headers (req))
    ci_http_response_reset_headers (req);
  else
    ci_http_response_create (req, 1, 1);
  ci_http_response_add_header (req, "HTTP/1.0 403 Forbidden");
  ci_http_response_add_header (req, "Server: C-ICAP");
  ci_http_response_add_header (req, "Connection: close");
  ci_http_response_add_header (req, "Content-Type: text/html");
  ci_http_response_add_header (req, "Content-Language: en");


  error_page = ci_membuf_new_sized (new_size);
  ((yara_data_t *) data)->error_page = error_page;

  ci_membuf_write (error_page, (char *) yara_error_message,
                   strlen (yara_error_message), 0);
  ci_membuf_write (error_page, (char *) data->match_name,
                   strlen (data->match_name), 0);
  ci_membuf_write (error_page, (char *) yara_tail_message, strlen (yara_tail_message), 1);      /*And here is the eof.... */
}


int
yara_cfg_load_path (char *directive, char **argv, void *setdata)
{
  int i,errors;
  FILE* rule_file;
  if (yara_context == NULL)
      yara_initialize_context();
  if (argv == NULL || argv[0] == NULL)
    {
      ci_debug_printf (1, "Missing arguments to directive %s\n", directive);
      return 0;
    }
  for (i = 0; argv[i] != NULL; i++) {
    if (access (argv[i], R_OK) == 0) {
        rule_file = fopen(argv[i], "r");

        if (rule_file != NULL) {
            ci_debug_printf(2, "Opening %s\n", argv[i]);
            yr_push_file_name(yara_context, argv[i]);
            errors = yr_compile_file(rule_file, yara_context);
            ci_debug_printf(2, "Done\n");
            if (errors !=0)
                ci_debug_printf(2, "Parsing errors: %s (%i)\n", argv[i], errors);
            fclose(rule_file);
        }

    } else {
        ci_debug_printf(1, "Can't access %s\n", argv[i]);
    }
  }

  return 1;
}


void yara_report_error(const char* file_name, int line_number, const char* error_message)
{
    ci_debug_printf(1, "YARA ERROR: %s:%d: %s\n", file_name, line_number, error_message);
}

char *yara_get_matches(IDENTIFIER *base, int len) {
    char *ret = ci_buffer_alloc (len + 1);
    ret[0]='\0';
    while (base != NULL) {
        strcat(ret, base->name);
        base = base->next;
    }
    if (strlen(ret)> 0)
        ret[strlen(ret) - 1] = 0; // truncate trailing comma

 return ret;
}

/* we use this awesome function to extract anything interesting from yara rule match results
 * and dump it into final result array in json-ish format */

void yara_get_result_string(RULE *rule, char *rez, unsigned int res_size, char *buffer, unsigned int buffer_size) {

    META* meta;
	STRING* string;
	MATCH* match;
    int match_counter;
    int string_found;
    char buf[YARA_MAX_RESULT_LENGTH + 1];
    char tmp[YARA_MAX_RESULT_LENGTH + 2]; // extra space reserved for ,

    bzero(buf, YARA_MAX_RESULT_LENGTH +1 );

    strcat(buf, "\"payload\":{");
    meta = rule->meta_list_head;
    if (meta  == NULL)
        strcat(buf, "\"ref\":\"\""); // if empy
    while (meta != NULL) {
            bzero(tmp, YARA_MAX_RESULT_LENGTH + 2);
            if (meta->type == META_TYPE_INTEGER)
            {
                snprintf(tmp, YARA_MAX_RESULT_LENGTH, "\"%s\":\"%d\"", meta->identifier, meta->integer);
            }
            else if (meta->type == META_TYPE_BOOLEAN)
            {
                snprintf(tmp, YARA_MAX_RESULT_LENGTH, "\"%s\":\"%s\"", meta->identifier, (meta->boolean)?("true"):("false"));
            }
            else
            {
                snprintf(tmp, YARA_MAX_RESULT_LENGTH,"\"%s\":\"%s\"", meta->identifier, meta->string);
            }

            if (meta->next != NULL)
                strcat(tmp,",");

            if (strlen(buf)< YARA_MAX_RESULT_LENGTH)
                strncat(buf, tmp, YARA_MAX_RESULT_LENGTH - strlen(buf));
            meta = meta->next;

    }
    if (strlen(buf)< YARA_MAX_RESULT_LENGTH)
        strncat(buf, ",\"matches\":[", YARA_MAX_RESULT_LENGTH - strlen(buf));

    string = rule->string_list_head;

    while (string != NULL)
    {
        string_found = string->flags & STRING_FLAGS_FOUND;

        if (string_found)
        {
            match = string->matches;
            match_counter = 0;


            while (match != NULL)
            {
                match_counter++;
                bzero(tmp, YARA_MAX_RESULT_LENGTH + 2);
                snprintf(tmp,YARA_MAX_RESULT_LENGTH, "{\"offset\":\"%08X\",\"content\":\"", match->offset);
                if (strlen(buf)< YARA_MAX_RESULT_LENGTH)
                    strncat(buf, tmp, YARA_MAX_RESULT_LENGTH - strlen(buf));
                bzero(tmp, YARA_MAX_RESULT_LENGTH + 2);

                if (IS_HEX(string))
                {
                    print_hex_string(tmp, YARA_MAX_RESULT_LENGTH, buffer, buffer_size, match->offset, match->length);
                }
                else if (IS_WIDE(string))
                {
                    print_string(tmp, YARA_MAX_RESULT_LENGTH, buffer, buffer_size, match->offset, match->length, TRUE);
                }
                else
                {
                    print_string(tmp, YARA_MAX_RESULT_LENGTH, buffer, buffer_size, match->offset, match->length, FALSE);
                }
                if (strlen(buf)< YARA_MAX_RESULT_LENGTH)
                    strncat(buf, tmp, YARA_MAX_RESULT_LENGTH - strlen(buf));
                if (strlen(buf)< YARA_MAX_RESULT_LENGTH)
                    strcat(buf,"\"");
                if (strlen(buf)< YARA_MAX_RESULT_LENGTH)
                    strcat(buf,"}");
                if (match->next != NULL && strlen(buf)< YARA_MAX_RESULT_LENGTH)
                    strcat(buf,",");

                match = match->next;
            }
            if (match_counter != 0 && string->next != NULL && strlen(buf)< YARA_MAX_RESULT_LENGTH && (string->next->flags & STRING_FLAGS_FOUND))
                 strcat(buf,",");
        }

        string = string->next;
    }


    if (strlen(buf)< YARA_MAX_RESULT_LENGTH - 1)
            strcat(buf, "]}");
    snprintf(rez, res_size, "{\"rule_name\":\"%s\",%s}", rule->identifier, buf);
}
/* this gets called every time yara matches a pattern */

int yara_callback(RULE* rule, unsigned char* buffer, unsigned int buffer_size, void* data) {
    //TAG* tag;
    IDENTIFIER* identifier, *id;
    int rule_match;
    char result[YARA_MAX_RESULT_LENGTH + 1];

    yara_data_t *yd = ci_service_data ((ci_request_t *)data);
    rule_match = (rule->flags & RULE_FLAGS_MATCH);
    if (!rule_match) {
        ci_debug_printf(1, "Rule %s did not match\n", rule->identifier);
        return 0;
    }

    yd->matched++;

    ci_debug_printf(1, "Rule match: %s\n", rule->identifier);
    bzero((void *)result, YARA_MAX_RESULT_LENGTH + 1);
    yara_get_result_string(rule, result, YARA_MAX_RESULT_LENGTH, (char *) buffer, buffer_size);

    identifier = (IDENTIFIER *)ci_membuf_new_sized (sizeof(IDENTIFIER));
    identifier->name = ci_buffer_alloc (strlen (result) + 2);
    strcpy (identifier->name, result);
    strcat(identifier->name, ",");
    yd->ident_len += strlen(identifier->name);
    identifier->next = NULL;
    id = (IDENTIFIER *)yd->ident;
    if (yd->ident == NULL)
        yd->ident = (ci_membuf_t *)identifier;
    else {
        while (id->next != NULL) {
                id = id->next;
        }
        id->next = identifier;
    }
ci_debug_printf(2, "Returning from callback\n");
return 0;
}

int yara_initialize_context() {
  ci_debug_printf(2, "Initializing yara context\n");
  yr_init();
  yara_context = yr_create_context();
  if (yara_context == NULL) {
    ci_debug_printf(2, "Failed to initialize yara!\n");
    return CI_ERROR;
  }
  yara_context->error_report_function = yara_report_error;
  return 0;
}

/* some formatting funcs */
void print_string(char* rez, unsigned int rez_size, char* buffer, unsigned int buffer_size, unsigned int offset, unsigned int length, int unicode)
{
	unsigned int i;
	char* str;
    char tmp[1024];

    str = (char*) (buffer + offset);

    for (i = 0; i < length; i++)
    {
        bzero(tmp, 1024);
        if ((char)str[i] >= 32 && (char)str[i] <= 126 && (char)str[i] != '"'
            && str[i] !='\\' && str[i] != '/'
            )
        {
            sprintf(tmp,"%c",str[i]);
        }
        else if (str[i] == '"' || str[i] == '\\') {
            sprintf(tmp, "\\%c", str[i]);
        } else
        {
            switch(str[i]) {
                    case '\b':
                        sprintf(tmp, "\\b");
                        break;
                    case '\n':
                        sprintf(tmp, "\\n");
                        break;
                    case '\r':
                        sprintf(tmp, "\\r");
                        break;
                    case '\t':
                        sprintf(tmp, "\\t");
                        break;
                    case '/':
                        sprintf(tmp, "\\/");
                        break;
                    default:
                        sprintf(tmp,"\\u00%02x", str[i]);
            }
        }

        if (unicode) i++;

        if ((unsigned int)(strlen(rez) + strlen(tmp)) < rez_size)
            strcat(rez, tmp);
    }

}

void print_hex_string(char* rez, unsigned int rez_size, char* buffer, unsigned int buffer_size, unsigned int offset, unsigned int length)
{
	unsigned int i;
	char* str;
    char tmp[1024];

    str = (char*) (buffer + offset);

    for (i = 0; i < length; i++)
    {
        sprintf(tmp,"%02X ", str[i]);
        if ((unsigned int)(strlen(rez) + strlen(tmp)) < rez_size)
            strcat(rez, tmp);
    }

}

