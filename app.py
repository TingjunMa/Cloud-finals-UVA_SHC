import os
import base64
import logging
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, flash, session, \
    abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Required, Length, EqualTo
import onetimepass
import pyqrcode
####
from datetime import datetime
import pymysql
from flask import request
from wtforms import TextAreaField, HiddenField
from flask_ask import Ask, question, session as ask_session, statement

# create application instance
app = Flask(__name__)
ask = Ask(app, '/')
log = logging.getLogger()
app.config.from_object('config')

# initialize extensions
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
lm = LoginManager(app)


class User(UserMixin, db.Model):
    """User model."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    otp_secret = db.Column(db.String(16))
    schedules = db.Column(db.String(30))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_totp_uri(self):
        return 'otpauth://totp/2FA-Demo:{0}?secret={1}&issuer=2FA-Demo' \
            .format(self.username, self.otp_secret)

    def verify_totp(self, token):
        return onetimepass.valid_totp(token, self.otp_secret)

@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    """Registration form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    password_again = PasswordField('Password again',
                                   validators=[Required(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username', validators=[Required(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Login')

class VisitDetailForm(FlaskForm):
    visit_id = HiddenField('')
    visit_time = StringField('Visit Date')
    visit_doctor = StringField('Doctor')
    visit_reason = TextAreaField('Visit Reason', validators=[Length(1,200)])
    visit_submit = SubmitField('Submit')
    visit_cancel = SubmitField('Cancel')

@app.route('/', methods = ['GET'])
def index():
    if current_user.is_authenticated:
        user_schedules = get_user_upcoming_schedules(current_user.username, is_Alexa_user=False)
        # appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
        # request_user_schedules = appointment_db.cursor()
        # request_user_schedules.execute("select schedules from users where username = '%s'" % current_user.username)
        # user_schedules = []
        # for row in request_user_schedules:
        #     schedule_ids = row[0][:-1] if row[0] is not None else ""
        # request_user_schedules.close()
        # if schedule_ids != "":
        #     request_user_schedules = appointment_db.cursor()
        #     request_user_schedules.execute("select id, DATE_FORMAT(date, '%Y-%m-%d'), TIME_FORMAT(time, '%H:%i'), doctor_name from schedules where id in (" + schedule_ids + ") and ((date = curdate() and time > curtime()) or date > curdate())")
        #     for row in request_user_schedules:
        #         user_schedules.append([row[0], row[1], row[2], row[3]])
        #     request_user_schedules.close()
        appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
        available_schedule = []
        selected_date = request.args.get('selected_date', default="")
        selected_doctor = request.args.get('selected_doctor', default="")
        try:
            available_date
        except:
            available_date = []
            request_date = appointment_db.cursor()
            request_date.execute("select DATE_FORMAT(date, '%Y-%m-%d') from schedules where date BETWEEN NOW() AND DATE_ADD(CURDATE(), INTERVAL 6 DAY) group by date")
            for date in request_date:
                available_date.append(date[0])
            request_date.close()
        try:
            available_doctor
        except:
            available_doctor = []
            request_doctor = appointment_db.cursor()
            request_doctor.execute("select doctor_name from schedules group by doctor_name")
            for doctor in request_doctor:
                available_doctor.append(doctor[0])
            request_doctor.close()
        if selected_date != "":
            if selected_doctor == "All doctor":
                # get_schedules_sql = "select id, date, TIME_FORMAT(time, '%H:%i'), doctor_name, doctor_info from schedules where date = '" + selected_date + "' and occupied is null"
                available_schedule = get_available_schedules_base_on_information(given_date=selected_date, given_doctor="")
            else:
            	available_schedule = get_available_schedules_base_on_information(given_date=selected_date, given_doctor=selected_doctor)
            #     get_schedules_sql = "select id, date, TIME_FORMAT(time, '%H:%i'), doctor_name, doctor_info from schedules where date = '" + selected_date + "' and doctor_name = '" + selected_doctor + "' and occupied is null"
            # available_schedule = []
            # request_schedule = appointment_db.cursor()
            # request_schedule.execute(get_schedules_sql)
            # for schedule in request_schedule:
            #     available_schedule.append(schedule)
            # request_schedule.close()
        return render_template('index.html', user_schedules=user_schedules, available_date=available_date, available_doctor=available_doctor, selected_date=selected_date, selected_doctor=selected_doctor, available_schedule=available_schedule)
    else:
        return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # add new user to the database
        curr_id = User.query.order_by(User.id.desc()).first().id
        if curr_id is None:
           curr_id = 0
        user = User(username=form.username.data, password=form.password.data, id = int(curr_id) + 1)
        db.session.add(user)
        db.session.commit()

        # redirect to the two-factor auth page, passing username in session
        session['username'] = user.username
        return redirect(url_for('two_factor_setup'))
    return render_template('register.html', form=form)


@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('index'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        # if user is logged in we get out of here
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash('Invalid username, password.')
            return redirect(url_for('login'))

        # log user in
        login_user(user)
        flash('You are now logged in!')
        return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """User logout route."""
    logout_user()
    return redirect(url_for('index'))

@app.route('/confirm_schedule', methods=['GET', 'POST'])
def confirm_schedule():
    if request.method == 'POST' and current_user.is_authenticated:
        if 'choose_one_schedule' in request.form:
            form = VisitDetailForm()
            details = request.form['choose_one_schedule'].split("$")
            form.visit_time.data = details[1] + " " + details[2]
            form.visit_doctor.data = details[3]
            form.visit_id.data = details[0]
            return render_template('confirm_schedule.html', form=form, reservation_succeed = "pending")
        if 'visit_submit' in request.form:
            visit_reason = request.form['visit_reason'][:200]
            visit_id = request.form['visit_id']
            patient = current_user.username
            # appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
            # set_schedule = appointment_db.cursor()
            # set_schedule.execute("select * from schedules where id = " + str(visit_id) + " and occupied is null")
            # if set_schedule.rowcount == 0:
            #     set_schedule.close()
            #     appointment_db.close()
            if reserve_schedule_by_id(schedule_id=visit_id, user_id=patient, is_Alexa_user=False, reason=visit_reason):
                return render_template ('confirm_schedule.html', reservation_succeed = "true", time = request.form['visit_time'], doctor = request.form['visit_doctor'])
            else:
                return render_template('confirm_schedule.html', reservation_succeed = "false")
            # else:
            #     set_schedule.execute("update schedules set occupied = '" + patient + "', task = '" + visit_reason + "' where id = " + str(visit_id))
            #     appointment_db.commit()
            #     set_schedule.execute("update users set schedules = concat(ifnull(schedules,''), '%s,') where username = '%s'" % (visit_id, patient))
            #     appointment_db.commit()
            #     set_schedule.close()
            #     appointment_db.close()
                
        if 'visit_cancel' in request.form:
            redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/cancel_schedule', methods=['GET', 'POST'])
def cancel_schedule():
    if request.method == 'POST' and current_user.is_authenticated:
        if 'cancel_schedule_confirm' in request.form:
            details = request.form['cancel_schedule_confirm'].split("$")
            visit_id = details[0]
            visit_time = details[1] + " " + details[2]
            visit_doctor = details[3]
            # appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
            # cancel_user_schedule = appointment_db.cursor()
            # cancel_user_schedule.execute("update users set schedules = replace(schedules, '%s,', '') where username = '%s'" % (visit_id, current_user.username))
            # cancel_user_schedule.execute("update schedules set occupied = null, task = null where id= '%s'" % visit_id)
            # appointment_db.commit()
            # cancel_user_schedule.close()
            # appointment_db.close()
            cancel_schedule_by_id(schedule_id=visit_id, username=current_user.username, is_Alexa_user=False)
            message = "The schedule with " + details[3] + " on " + visit_time + " has been cancelled!"
        else:
            message = "Please choose a schedule you want to cancel!"
        return render_template('cancel_schedule.html', message=message)
    return redirect(url_for('index'))

### APIs

def get_available_schedules_base_on_information(given_date="", given_doctor=""):
    sql = "select id, DATE_FORMAT(date, '%Y-%m-%d'), TIME_FORMAT(time, '%H:%i'), doctor_name, doctor_info from schedules where "
    if given_date != "":
        sql_date = "date = '" + given_date +"'"
    else:
        sql_date = "((date = curdate() and time > curtime()) or date > curdate())"
    if given_doctor != "":
        sql_doctor = " and doctor_name like '%" + given_doctor +"%'"
    else:
        sql_doctor = ""
    sql = sql + sql_date + sql_doctor + " and occupied is null"
    log.debug("SQL: " + sql)
    appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
    conn = appointment_db.cursor()
    conn.execute(sql)
    res = []
    for row in conn:
        res.append(row)
    conn.close()
    appointment_db.close()
    return res

def reserve_schedule_by_id(schedule_id, user_id, is_Alexa_user=False, reason=""):
    appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
    conn = appointment_db.cursor()
    conn.execute("select * from schedules where id = " + str(schedule_id) + " and occupied is null")
    if conn.rowcount == 0:
        conn.close()
        appointment_db.close()
        return False
    else:
        conn.execute("update schedules set occupied = '" + user_id + "', task = '" + reason + "' where id = " + str(schedule_id))
        appointment_db.commit()
        if is_Alexa_user:
            conn.execute("select * from alexa_users where alexa_id = '" + user_id +"'")
            if conn.rowcount == 0:
                log.debug("insert into alexa_users values ('%s', %s)" % (user_id, ''))
                conn.execute("insert into alexa_users values ('%s', %s)" % (user_id, ''))
                appointment_db.commit()
            conn.execute("update alexa_users set schedules = concat(ifnull(schedules,''), '%s,') where alexa_id = '%s'" % (schedule_id, user_id))
        else:
            conn.execute("update users set schedules = concat(ifnull(schedules,''), '%s,') where username = '%s'" % (schedule_id, user_id))
        appointment_db.commit()
        conn.close()
        appointment_db.close()
        return True

def cancel_schedule_by_id(schedule_id, username, is_Alexa_user=False):
    appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
    conn = appointment_db.cursor()
    if is_Alexa_user:
        conn.execute("update alexa_users set schedules = replace(schedules, '%s,', '') where alexa_id = '%s'" % (schedule_id, username))
    else:
        conn.execute("update users set schedules = replace(schedules, '%s,', '') where username = '%s'" % (schedule_id, username))
    conn.execute("update schedules set occupied = null, task = null where id= '%s'" % schedule_id)
    appointment_db.commit()
    conn.close()
    appointment_db.close()

def get_user_upcoming_schedules(username, is_Alexa_user=False):
    appointment_db = pymysql.connect(user='master', passwd='CS6501cloud', host='uvastudenthealth.ccoount3qles.us-east-1.rds.amazonaws.com', port=3306, db='appointment')
    conn = appointment_db.cursor()
    if is_Alexa_user:
        conn.execute("select schedules from alexa_users where alexa_id = '%s'" % username)
    else:
        conn.execute("select schedules from users where username = '%s'" % username)
    user_schedules = []
    schedule_ids = ""
    for row in conn:
        schedule_ids = row[0][:-1] if row[0] is not None else ""
    conn.close()
    if schedule_ids != "":
        conn = appointment_db.cursor()
        conn.execute("select id, DATE_FORMAT(date, '%Y-%m-%d'), TIME_FORMAT(time, '%H:%i'), doctor_name from schedules where id in (" + schedule_ids + ") and ((date = curdate() and time > curtime()) or date > curdate())")
        for row in conn:
            user_schedules.append([row[0], row[1], row[2], row[3]])
        conn.close()
    appointment_db.close()
    return user_schedules

def tostring(date):
    if date == '':
        return ''
    return date.strftime("%Y-%m-%d")

### Alexa skills

@ask.launch
def launch():
    speech = "Hello, this is University of Virginia Student Health Center Appointment System"
    return statement(speech)

@ask.intent('GetSchedule',
    mapping = {'date': 'Date', 'name': 'Name'},
    convert = {'date': 'date'},
    default = {'date': '', 'name': ''})
def getSchedule(date, name):
    rows = get_available_schedules_base_on_information(tostring(date), name)
    number = len(rows)
    choice = ""
    index = 0
    select = 1
    ask_session.attributes['visit_id'] = []
    ask_session.attributes['date'] = []
    ask_session.attributes['time'] = []
    ask_session.attributes['doctor_name'] = []
    ask_session.attributes['intent'] = 'book'
    for row in rows:
        if index % (number/3) == 0 or index == number-1:
            choice += str(select) + ", <say-as interpret-as='time'>" + row[2] + "</say-as>"
            if date == '':
                choice += " " + row[1]
            if name == '':
                choice += " with " + row[3]
            choice += ". "
            ask_session.attributes['visit_id'].append(row[0])
            ask_session.attributes['date'].append(row[1])
            ask_session.attributes['time'].append(row[2])
            ask_session.attributes['doctor_name'].append(row[3])
            select += 1
        index += 1

    if number > 0:
        speech = "Which one? " + choice
        # , following by reason for visiting
        return question(speech)
    else:
        speech = "There is no spot available"
        return statement(speech)

@ask.intent('CancelSchedule')
def cancelSchedule():
    rows = get_user_upcoming_schedules(ask_session.user.userId, True)
    number = len(rows)
    choice = ""
    index = 1
    ask_session.attributes['visit_id'] = []
    ask_session.attributes['date'] = []
    ask_session.attributes['time'] = []
    ask_session.attributes['doctor_name'] = []
    ask_session.attributes['intent'] = 'cancel'
    for row in rows:
        choice += str(index) + ", <say-as interpret-as='time'>" + row[2] + "</say-as>"
        if date == '':
            choice += " " + row[1]
        if name == '':
            choice += " with " + row[3]
        choice += ". "
        ask_session.attributes['visit_id'].append(row[0])
        ask_session.attributes['date'].append(row[1])
        ask_session.attributes['time'].append(row[2])
        ask_session.attributes['doctor_name'].append(row[3])
        index += 1

    if number > 0:
        speech = "Which one to cancel? " + choice
        return question(speech)
    else:
        speech = "There is no appointment for now"
        return statement(speech)

@ask.intent('ConfirmSpot',
    mapping = {'number': 'Number'},
    convert = {'number': int},
    default = {'number': 0})
def confirmSpot(number):
    option = len(ask_session.attributes['visit_id'])
    if number > 0 and number < option:
        visit_id = ask_session.attributes['visit_id'][number-1]
        date = ask_session.attributes['date'][number-1]
        time = ask_session.attributes['time'][number-1]
        name = ask_session.attributes['doctor_name'][number-1]
        if ask_session.attributes['intent'] == 'book':
            succeed = reserve_schedule_by_id(visit_id, ask_session.user.userId, True)
            if succeed:
                speech = 'Booked ' + str(number) \
                    + ", <say-as interpret-as='time'>" + time + "</say-as> " \
                    + date + " with " + name
                # if reason != '':
                #     speech += " because of " + reason
            else:
                speech = 'Spot unavailable for now'
            return statement(speech)
        elif ask_session.attributes['intent'] == 'cancel':
            cancel_schedule_by_id(visit_id, ask_session.user.userId, True)
            speech = 'Canceled ' + str(number) \
                + ", <say-as interpret-as='time'>" + time + "</say-as> " \
                + date + " with " + name
            return statement(speech)
    else:
        choice = ""
        for i in range(option):
            choice += str(i+1) + ", <say-as interpret-as='time'>" + ask_session.attributes['time'][i] + "</say-as>"
            choice += " " + ask_session.attributes['date'][i]
            choice += " with " + ask_session.attributes['doctor_name'][i]
            choice += ". "
        speech = "Sorry, but only " + str(option) + " available options, please choose from " + choice
        return question(speech)

@ask.intent('AMAZON.StopIntent')
def stop():
    return statement("Thank you for using Appointment System")

@ask.intent('AMAZON.CancelIntent')
def cancel():
    return statement("Thank you for using Appointment System")

@ask.session_ended
def session_ended():
    return "{}", 200

@ask.on_session_started
def new_session():
    log.info('new session started')

# create database tables if they don't exist yet
db.create_all()


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
