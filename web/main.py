import flask
import os
from .db import Database
from .utils import log_request, error, route, enforce_content_length

app = flask.Flask('graubs.info', host='0.0.0.0', port=int(os.environ.get('GRAUBS_PORT', 8080)))

GRAUBS_DB = os.environ.get('GRAUBS_DB', None)

def lookup_code(short_code):
    with Database(GRAUBS_DB, tables=['lookup']) as db:
        results = db.query(
            db['lookup'].select.where(db['lookup'].c.short_code == short_code)
        )
        if len(results):
            results.iloc[0]['destination']
    return None

@app.route('/<short_code>')
@log_request
@enforce_content_length
@route
def forward(short_code):
    destination = lookup_code(short_code)
    if destination is not None:
        return flask.redirect(destination)
    return error(
        'Not found',
        context='This short code has not been defined',
        code=404
    )

@app.route('/_/bind', methods=['POST'])
@log_request
@enforce_content_length
@route
def bind():
    data = flask.request.form
    for key in ['short_code', 'url']:
        if key not in data:
            return error(
                'Missing required form parameter "{}"'.format(key),
                error=400
            )
    if short_code == '' or short_code == '_':
        return error(
            'Invalid short code',
            context='Short code must be 1-127 printable ASCII characters and cannot be _',
            code=400
        )
    if lookup_code(data['short_code']) is not None:
        return error(
            'Taken',
            context='This short code is already in use',
            code=409
        )
    if not validators.url(data['url']):
        return error(
            'Invalid URL',
            context='The given destination does not look like a URL',
            code=400
        )
    with Database(GRAUBS_DB, tables=['lookup']) as db:
        db.insert('lookup', short_code=data['short_code'], destination=data['url'])
    return flask.make_response('OK', 200)

@app.route('/')
@log_request
@route
def index():
    return flask.current_app.send_static_file('index.html')

@app.errorhandler(404)
@log_request
@route
def not_found():
    return flask.current_app.send_static_file('404.html')
