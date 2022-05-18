from flask import current_app, request, Response, make_response
from functools import wraps
import traceback
import sqlalchemy as sqla
from time import monotonic
from datetime import datetime, timedelta
from .db import Database

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_CONTENT_LENGTH = 2048

def get_remote_addr():
    return (
        request.headers['X-Real-IP']
        if 'X-Real-IP' in request.headers
        else request.remote_addr
    )

def error(message, *, data=None, context=None, code=400):
    # Maybe log

    err = {'message': message, 'code': code}
    if data is not None:
        err['data'] = data

    if context is not None:
        err['context'] = context

    return make_response(err, code)

def route(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except:
            traceback.print_exc()
            return error(
                'Unknown error',
                data=traceback.format_exc(),
                code=500
            )

def enforce_content_length(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'Content-Length' not in request.headers or int(request.headers['Content-Length']) > MAX_CONTENT_LENGTH:
            return error("Request payload too large", data={'max-content-length': MAX_CONTENT_LENGTH}, code=413)
        return func(*args, **kwargs)

    return wrapper

def log_request(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        t0 = monotonic()
        try:
            result = func(*args, **kwargs)
            with Database.get_db() as db:
                db.insert(
                    'requests',
                    time=datetime.now(),
                    host=request.headers['Host'][:512] if 'Host' in request.headers else None,
                    agent=request.headers['User-Agent'], #User-Agent required by Router
                    length=int(request.headers['Content-Length']) if 'Content-Length' in request.headers else None,
                    ip=get_remote_addr(),
                    url_path=request.full_path[:512],
                    endpoint=func.__name__[:64],
                    method=request.method,
                    container=current_app.config['DODO_ROLE'],
                    response_code=result.status_code,
                    response_time=int(1000*(monotonic()-t0))
                )
            return result
        except:
            traceback.print_exc()
            with Database.get_db() as db:
                db.insert(
                    'requests',
                    time=datetime.now(),
                    host=request.headers['Host'][:512] if 'Host' in request.headers else None,
                    agent=request.headers['User-Agent'], # User-Agent required by Router
                    length=int(request.headers['Content-Length']) if 'Content-Length' in request.headers else None,
                    ip=get_remote_addr(),
                    url_path=request.full_path[:512],
                    endpoint=func.__name__[:64],
                    method=request.method,
                    container=current_app.config['DODO_ROLE'],
                    response_code=None,
                    response_time=int(1000*(monotonic()-t0))
                )
            raise

    wrapper.not_logged = lambda *args, **kwargs: func(*args, **kwargs)

    return wrapper
