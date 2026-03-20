from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session

from . import cap, is_safe_url, is_session_verified, add_rate_event, reset_rate_limit, validate_and_use_token

captcha_bp = Blueprint('captcha', __name__)


@captcha_bp.route('/checkpoint', methods=['GET', 'POST'])
def checkpoint():
    user_ip = request.remote_addr
    is_ip_flagged = add_rate_event(user_ip)
    verified = is_session_verified()

    next_url = request.args.get('next') or url_for('home')
    if not is_safe_url(next_url):
        next_url = url_for('home')

    if not (is_ip_flagged or not verified):
        return redirect(next_url)

    if request.method == 'POST':
        cap_token = request.form.get('cap-token')

        if not cap_token:
            return render_template('checkpoint.html', error='CAPTCHA is missing!')

        valid, error = validate_and_use_token(cap_token)
        if not valid:
            return render_template('checkpoint.html', error=error)

        session['verified_at'] = __import__('time').time()
        reset_rate_limit(user_ip)

        next_url = request.args.get('next') or url_for('home')
        if not is_safe_url(next_url):
            next_url = url_for('home')

        return redirect(next_url)

    return render_template('checkpoint.html')


@captcha_bp.route('/api/cap/challenge', methods=['POST'])
def cap_challenge():
    challenge = cap.create_challenge()
    return jsonify(challenge)


@captcha_bp.route('/api/cap/redeem', methods=['POST'])
def cap_redeem():
    data = request.get_json() or {}
    token = data.get('token')
    solutions = data.get('solutions', [])

    result = cap.redeem(token, solutions)
    return jsonify(result)
