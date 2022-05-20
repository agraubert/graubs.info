import flask
import os
import validators
import sqlalchemy as sqla
from .db import Database
from .utils import log_request, error, route, enforce_content_length, csrf_protected, authenticated, issue_csrf, issue_token

app = flask.Flask('graubs-info', static_folder='/opt/graubs/static/', template_folder='/opt/graubs/templates/')

GRAUBS_DB = os.environ.get('GRAUBS_DB', None)

with Database(GRAUBS_DB, tables=['auth']) as db:
    results = db.query(
        db['auth'].select
    )
    if not len(results):
        db.insert(
            'auth',
            token=issue_token()
        )

def lookup_code(short_code):
    with Database(GRAUBS_DB, tables=['lookup']) as db:
        results = db.query(
            db['lookup'].select.where(db['lookup'].c.short_code == short_code)
        )
        if len(results):
            return results.iloc[0]['destination']
    return None

@app.route('/<short_code>')
@log_request
@route
def forward(short_code):
    destination = lookup_code(short_code.strip())
    if destination is not None:
        return flask.redirect(destination)
    return error(
        'Not found',
        context='This short code has not been defined',
        code=404
    )

@app.route('/_/bind', methods=['POST'])
@csrf_protected('bind')
@log_request
@enforce_content_length
@route
def bind():
    data = flask.request.form
    short_code = data['short_code'].strip()
    for key in ['short_code', 'url', 'csrf']:
        if key not in data:
            return error(
                'Missing required form parameter "{}"'.format(key),
                error=400
            )
    if len(short_code) < 2:
        return error(
            'Invalid short code',
            context='Short code must be 2-127 printable ASCII characters',
            code=400
        )
    if lookup_code(short_code) is not None:
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
        db.insert('lookup', short_code=short_code, destination=data['url'])
    return flask.make_response('OK', 200)


@app.route('/a/requests')
@route
@log_request
@authenticated
def get_requests():
    with Database(GRAUBS_DB, tables=['requests']) as db:
        return flask.make_response(
            db.query(
                db['requests'].select.order_by(
                    sqla.desc(db['requests'].c.ID)
                ).limit(1000)
            ).sort_values("ID").set_index("ID").to_html(),
            200
        )


@app.route('/')
@log_request
@route
def index():
    return flask.make_response(
        flask.render_template('index.html', csrf=issue_csrf('bind')),
        200
    )

@app.route('/p')
@log_request
@route
def privacy():
    return flask.current_app.send_static_file('privacy.html')

@app.errorhandler(404)
@log_request
@route
def not_found():
    return flask.current_app.send_static_file('404.html')


app.run(host='0.0.0.0', port=int(os.environ.get('GRAUBS_PORT', 8080)))
