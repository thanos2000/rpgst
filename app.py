import os
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
import pymongo, re


def Flask(__name__):
    pass


app = Flask(__name__)
app.config['plotting'] = False

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
client = pymongo.MongoClient('MONGO_CONNECTION_STRING')

db = client.test
class User(UserMixin):
    def __init__(self, username):
        self.username = username

    def get_id(self):
        return self.username
    @login_manager.user_loader
    def load_user(username):
        user = db.users.find_one({ "username": username })
        if user is None:
            return None
        return User(username=user['username'])
    @staticmethod
    def check_password(password_entered, password):
        if bcrypt.check_password_hash(password, password_entered):
            return True
        return False

## Login/Register page
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/main')
@app.route("/", methods = ["POST"])
def login_or_register():
    if request.method == 'POST':
        name_entered = str(request.form.get('user_name')) # Get username and password from form
        pw_entered = str(request.form.get('user_pw'))

        if request.form.get('login'): # Log in logic
            user = db.users.find_one({ 'username': name_entered })
            if user and User.check_password(pw_entered, user['password']):
                usr_obj = User(username=user['username'])
                login_user(usr_obj)
                return redirect(url_for('main'))
            else:
                return "Incorrect username or password."

        elif request.form.get('register'): # Register logic
            # Validate username and password
            if not re.match("[a-zA-Z0-9_]{1,20}", name_entered):
                return "Username must be between 1 and 20 characters. Letters, numbers and underscores allowed."
            if len(pw_entered) < 8:
                return "Password must be at least 8 characters."

            if db.users.find_one({ 'username': name_entered }):
                return "User already exists."

            new_user = { 'username': name_entered,
                         'password': bcrypt.generate_password_hash(pw_entered) }
            db.users.insert_one(new_user) # insert new user to db
            return redirect(url_for('login')) # redirect after register

def main():
    return render_template('main.html')
@app.route('/main')
def main():
    if current_user.get_id() is None:
        return redirect(url_for('login')) # redirect to login page if not logged in

    user_data = db.users.find_one({ 'username': current_user.get_id() })
    return render_template("main.html", user=user_data, plot=app.config['plotting'])

def submit_sleep():
    if request.form.get('submit'): # if submitting new sleep data
        time_entered = float(request.form.get('time'))
        date_entered = request.form.get('date')
        message = add_sleep(time_entered,date_entered,db.users.find_one({'username':current_user.get_id()}))
        if message:
          return message

        def add_sleep(time, date, user):
            if not re.match("[0-9]{4}-[0-1][0-9]-[0-3][0-9]", date):
                return "Invalid date supplied."

            if time < 0.0 or time > 24.0:
                return "Sleep time must be between 0 and 24 hours."

            if 'date' in user:
                user['date'].append(date)
                user['time'].append(time)
            else:  # adding sleep data for the first time
                user['date'] = [date]
                user['time'] = [time]

            # Update MongoDB Atlas
            db.users.update_one({'username': user['username']},
                                {'$set': {'date': user['date'],
                                          'time': user['time']}})


    if request.form.get('logout'):
        logout_user()
        app.config['plotting'] = False
        return 'You logged out!'

    elif request.form.get('graph'):
        app.config['plotting'] = True

    return redirect(url_for('main'))


