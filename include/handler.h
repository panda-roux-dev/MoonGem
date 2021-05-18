#ifndef HANDLER_H
#define HANDLER_H

#include "net.h"

callback_result_t handle_request(const request_t* request, response_t* response,
                                 response_body_builder_t* builder);
#endif
