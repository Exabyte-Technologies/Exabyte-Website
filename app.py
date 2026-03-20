import os
from flask import Flask, request, render_template, redirect, url_for
from flask_session import Session
from redis import Redis
from werkzeug.middleware.proxy_fix import ProxyFix

from subsystems.captcha import start_cleanup_task, should_checkpoint
from subsystems.captcha.routes import captcha_bp

app = Flask(__name__, template_folder='templates', static_folder='static')
app.register_blueprint(captcha_bp)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_key")
if not app.secret_key or app.secret_key == "dev_secret_key":
    print("WARNING: using insecure secret; set FLASK_SECRET_KEY in prod")

app.config.update({
    "SESSION_TYPE": "redis",
    "SESSION_REDIS": Redis(host=os.getenv("REDIS_HOST", "localhost"), port=int(os.getenv("REDIS_PORT", 6379))),
    "SESSION_PERMANENT": False,
    "SESSION_USE_SIGNER": True,
})
Session(app)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

start_cleanup_task()


@app.before_request
def checkpoint_middleware():
    allowed_endpoints = ['captcha.checkpoint', 'captcha.cap_challenge', 'captcha.cap_redeem', 'static']
    if request.endpoint in allowed_endpoints:
        return

    if should_checkpoint():
        return redirect(url_for('captcha.checkpoint', next=request.url))


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/services')
def services():
    return render_template('services.html')


@app.route('/mission')
def mission():
    return render_template('mission.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/mslcTransfer/<path:mslcURL>')
def mslcTransfer(mslcURL):
    try:
        code = request.args.get('code')
        return redirect(str(mslcURL) + f'?code={code}')
    except Exception:
        return "There was an error with the redirect URL. We don't know where to redirect you. Please return to the page you came from manually."


if __name__ == '__main__':
    app.run(debug=False, port=80, host='0.0.0.0')
