import ignition as ig
from ignition.response import BaseResponse

def fail(msg):
    return False, msg

def ok():
    return True, None

def exists(response: BaseResponse):
    if response.status == ig.RESPONSE_STATUSDETAIL_PERM_FAILURE_NOT_FOUND:
        return fail('Resource was not found')
    return ok()

def does_not_exist(response: BaseResponse):
    if response.status != ig.RESPONSE_STATUSDETAIL_PERM_FAILURE_NOT_FOUND:
        return fail('Resource was found')
    return ok()

