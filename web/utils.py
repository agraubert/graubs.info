from flask import current_app, request, Response, make_response
from functools import wraps
import traceback
import sqlalchemy as sqla
from time import monotonic
from datetime import datetime, timedelta
from .db import Database
import os
import base64
import hashlib

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_CONTENT_LENGTH = 2048

def getpath(pubkey):
    path = os.path.join('/var/graubs', pubkey[:2], pubkey[2:4], pubkey[4:])
    if not os.path.isdir(path):
        os.makedirs(path)
    return path

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
    return wrapper

def enforce_content_length(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        length = request.headers.get('Content-Length', None)
        if length is None or int(length) > MAX_CONTENT_LENGTH:
            return error("Request payload too large", data={'content-length': length, 'max-content-length': MAX_CONTENT_LENGTH}, code=413)
        return func(*args, **kwargs)

    return wrapper

def validate_token(token):
    with Database(os.environ.get('GRAUBS_DB', None), tables=['auth']) as db:
        return len(db.query(
            db['auth'].select.where(
                db['auth'].c.token == token
            )
        )) > 0

def issue_token():
    entropy = os.urandom(128)
    token = hashlib.sha512(os.urandom(32)).digest()
    for i in range(8):
        token = hashlib.sha512(token + entropy[i*16:(i+1)*16]).digest()
    return token.hex()

def keygen():
    privkey = pubkey = os.urandom(64)
    salt = os.urandom(16)
    for _ in range(10000):
       pubkey = hashlib.sha256(salt + pubkey).digest()
    return base64.urlsafe_b64encode(pubkey).decode(), base64.urlsafe_b64encode(salt + privkey).decode()

def extract_pubkey(priv):
    raw = base64.urlsafe_b64decode(priv)
    salt = raw[:16]
    priv = raw[16:]
    for _ in range(10000):
       priv = hashlib.sha256(salt + priv).digest()
    return base64.urlsafe_b64encode(priv).decode()


def extract_auth():
    return request.cookies.get('auth', request.args.get('auth', None))

def authenticated(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        token = extract_auth()
        if token is not None and validate_token(token):
            return func(*args, **kwargs)
        return error(
            "Not logged in or could not validate credentials",
            context="Must be logged in to access this endpoint",
            code=401
        )

    return wrapper

def issue_csrf(formid):
    with Database(os.environ.get('GRAUBS_DB', None), tables=['csrf']) as db:
        token = base64.b64encode(os.urandom(32)).decode()
        db.insert(
            'csrf',
            form=formid[-128:],
            token=token,
            ip=get_remote_addr(),
            expires=datetime.now() + timedelta(days=1),
            agent_hash=base64.b64encode(hashlib.md5(request.headers['User-Agent'].encode()).digest()).decode()
        )
        db.execute(
            db['csrf'].delete.where(
                (db['csrf'].c.expires <= datetime.now())
            )
        )
    return token

def csrf_protected(formid):

    def decorator(func):

        @wraps(func)
        def wrapper(*args, **kwargs):
            token = request.form.get('csrf', None)
            if token is not None:
                agent_hash = base64.b64encode(hashlib.md5(request.headers['User-Agent'].encode()).digest()).decode()
                with Database(os.environ.get('GRAUBS_DB', None), tables=['csrf']) as db:
                    results = db.query(
                        db['csrf'].select.where(
                            (db['csrf'].c.token == token) &
                            (db['csrf'].c.form == formid[-128:]) &
                            (db['csrf'].c.ip == get_remote_addr()) &
                            (db['csrf'].c.expires > datetime.now()) &
                            (db['csrf'].c.agent_hash == agent_hash)
                        )
                    )
                    db.execute(
                        db['csrf'].delete.where(
                            (db['csrf'].c.expires <= datetime.now()) |
                            (db['csrf'].c.token == token)
                        )
                    )
                    if len(results) > 0:
                        return func(*args, **kwargs)
            return error("Forbidden: No CSRF token provided. If you did not intend to submit this form, someone may be trying to scam you. Otherwise, please refresh the page and try again", code=403)

        return wrapper

    return decorator

def log_request(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        t0 = monotonic()
        try:
            result = func(*args, **kwargs)
            with Database(os.environ.get('GRAUBS_DB', None), tables=['requests']) as db:
                db.insert(
                    'requests',
                    time=datetime.now(),
                    host=request.headers['Host'][:512] if 'Host' in request.headers else None,
                    agent_hash=base64.b64encode(hashlib.md5(request.headers['User-Agent'].encode()).digest()).decode(), #User-Agent required by Router
                    length=int(request.headers['Content-Length']) if 'Content-Length' in request.headers else None,
                    ip=get_remote_addr(),
                    url_path=request.full_path[:512],
                    endpoint=func.__name__[:64],
                    method=request.method,
                    response_code=result.status_code,
                    response_time=int(1000*(monotonic()-t0))
                )
            return result
        except:
            traceback.print_exc()
            with Database(os.environ.get('GRAUBS_DB', None), tables=['requests']) as db:
                db.insert(
                    'requests',
                    time=datetime.now(),
                    host=request.headers['Host'][:512] if 'Host' in request.headers else None,
                    agent_hash=base64.b64encode(hashlib.md5(request.headers['User-Agent'].encode()).digest()).decode(), # User-Agent required by Router
                    length=int(request.headers['Content-Length']) if 'Content-Length' in request.headers else None,
                    ip=get_remote_addr(),
                    url_path=request.full_path[:512],
                    endpoint=func.__name__[:64],
                    method=request.method,
                    response_code=None,
                    response_time=int(1000*(monotonic()-t0))
                )
            raise

    wrapper.not_logged = lambda *args, **kwargs: func(*args, **kwargs)

    return wrapper
