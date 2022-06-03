import flask
import os
import validators
import sqlalchemy as sqla
import re
from hashlib import sha256
from .db import Database
from .utils import log_request, error, route, enforce_content_length, csrf_protected, authenticated, issue_csrf, issue_token, keygen, extract_pubkey

short_code_pattern = re.compile(r'\w{2,127}')
MAX_FILESIZE = 2 * 1024 * 1024 * 1024

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

@app.route('/x/<key>/upload')
@log_request
@route
def upload_page(key):
    with Database(GRAUBS_DB, tables=['files']) as db:
        results = db.query(
            db['files'].select.where(
                db['files'].c.privkey == key
            )
        )
        if not len(results) == 1:
            return error(
                'No such key',
                context='Please contact an administrator to initiate a file upload',
                code=403
            )
    return flask.make_response(
        flask.render_template('upload.html', csrf=issue_csrf('upload'), privkey=key)
    )

@app.route('/_/upload', methods=['POST'])
@csrf_protected('upload')
@log_request
# @enforce_content_length
@route
def upload_file():
    data = flask.request.form
    if 'privkey' not in data:
        return error(
            'Missing transfer key',
            context='Please contact an administrator to initiate a file upload',
            code=401
        )
    with Database(GRAUBS_DB, tables=['files']) as db:
        results = db.query(
            db['files'].select.where(
                db['files'].c.privkey == data['privkey']
            )
        )
        if not len(results) == 1:
            return error(
                'No such key',
                context='Please contact an administrator to initiate a file upload',
                code=403
            )
        pubkey = extract_pubkey(data['privkey'])
        file = flask.request.files['file']
        file.seek(0, 2)
        filesize = file.tell()
        if filesize > MAX_FILESIZE:
            return error(
                'Too large',
                context='The uploaded file exceeded the limit of {} bytes'.format(MAX_FILESIZE),
                code=400
            )
        file.seek(0, 0)
        blob = file.read()
        with open(os.path.join('/var/graubs/', pubkey), 'wb') as w:
            w.write(blob)
        db.execute(
            db['files'].update.values(
                filesize=filesize,
                sha256=sha256(blob).hexdigest()
            ).where(
                db['files'].c.privkey == data['privkey']
            )
        )
        if 'short_code' in data and data['short_code']:
            if lookup_code(data['short_code']) is not None:
                return error(
                    'Taken',
                    context='This short code is already in use',
                    code=409
                )
            with Database(GRAUBS_DB, tables=['lookup']) as db:
                db.insert('lookup', short_code=data['short_code'], destination='https://graubs.info/x/{}'.format(pubkey))
            return flask.make_response(
                flask.render_template('bound.html', binding=data['short_code']),
                200
            )
        return flask.make_response(
            flask.render_template('bound.html', binding='x/{}'.format(pubkey)),
            200
        )


@app.route('/_/key', methods=['POST'])
@csrf_protected('keypair')
@log_request
@enforce_content_length
@route
def key():
    data = flask.request.form
    pub, priv = keygen()
    with Database(GRAUBS_DB, tables=['files']) as db:
        db.insert('files', privkey=priv, pubkey=pub)
    return flask.make_response(
        {
            'transfer-keys': {
                'download': pub,
                'upload': priv
            }
        },
        200
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
    if not short_code_pattern.match(short_code):
        return error(
            "Invalid short code",
            context="Short code must be 2-127 letters or numbers. No special characters allowed",
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
    return flask.make_response(
        flask.render_template('bound.html', binding=short_code),
        200
    )


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
# select lookup.short_code, count(*) as count, count(distinct requests.ip) as unq from requests join lookup on requests.url_path like concat("/", lookup.short_code, "?") group by lookup.short_code;
@app.route('/a/usage')
@route
@log_request
@authenticated
def get_usage():
    with Database(GRAUBS_DB, tables=['lookup', 'requests']) as db:
        return flask.make_response(
            db.query(
                sqla.select(
                    db['lookup'].c.short_code,
                    sqla.func.count(db['lookup'].c.short_code).label('uses'),
                    sqla.func.count(sqla.func.distinct(db['requests'].c.ip)).label('distinct_users')
                ).select_from(db['requests'].table).join(
                    db['lookup'].table,
                    onclause=db['requests'].c.url_path.like(sqla.func.concat("/", db['lookup'].c.short_code, "%"))
                ).group_by(db['lookup'].c.short_code).where(
                    db['requests'].c.response_code == 302
                )
            ).sort_values("uses").set_index("short_code").to_html(),
            200
        )

@app.route('/a/panel')
@log_request
@route
def admin_panel():
    return flask.make_response(
        flask.render_template('admin.html', csrf_uploadkey=issue_csrf('keypair')),
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
def not_found(url):
    return flask.current_app.send_static_file('404.html')


app.run(host='0.0.0.0', port=int(os.environ.get('GRAUBS_PORT', 8080)))
