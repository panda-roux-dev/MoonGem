#ifndef STATUS_H
#define STATUS_H

#define STATUS_INPUT 10
#define STATUS_SENSITIVE_INPUT 11
#define STATUS_SUCCESS 20
#define STATUS_TEMPORARY_REDIRECT 30
#define STATUS_PERMANENT_REDIRECT 31
#define STATUS_TEMPORARY_FAILURE 40
#define STATUS_SERVER_UNAVAILABLE 41
#define STATUS_CGI_ERROR 42
#define STATUS_PROXY_ERROR 43
#define STATUS_SLOW_DOWN 44
#define STATUS_PERMANENT_FAILURE 50
#define STATUS_NOT_FOUND 51
#define STATUS_GONE 52
#define STATUS_PROXY_REQUEST_REFUSED 53
#define STATUS_BAD_REQUEST 59
#define STATUS_CLIENT_CERTIFICATE_REQUIRED 60
#define STATUS_CERTIFICATE_NOT_AUTHORIZED 61

#define STATUS_DEFAULT STATUS_SUCCESS

#define STATUS_IS_ERROR(value) \
  (value >= STATUS_TEMPORARY_FAILURE && value <= STATUS_BAD_REQUEST)

#define META_INPUT "Input Required"
#define META_SENSITIVE_INPUT "Input Required"
#define META_SERVER_UNAVAILABLE "Server Unavailable"
#define META_CGI_ERROR "Script Error"
#define META_NOT_FOUND "Not Found"
#define META_GONE "Gone"
#define META_BAD_REQUEST "Bad Request"
#define META_CLIENT_CERTIFICATE_REQUIRED "Certificate Required"
#define META_CERTIFICATE_NOT_AUTHORIZED "Not Authorized"

#endif
