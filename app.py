
from flask import Flask, render_template, url_for, redirect, flash

from flask_login.utils import login_user
from flask_login import UserMixin, LoginManager, current_user, login_required, logout_user

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Integer, String, Column, update
from sqlalchemy.orm import relationship

from flask_wtf import FlaskForm
from flask_wtf.form import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError

from flask_bcrypt import Bcrypt


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt()

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '123'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    if user_id is not None:
        return User.query.get(int(user_id))
    else:
        return None



# User attributes
class User(db.Model, UserMixin):
    id = Column(Integer, primary_key=True, unique=True, nullable=False)
    username = Column(String(20), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    role = Column(Integer, default=0)
    total_points = Column(Integer, default=0) # default 0 as cant add points with null as current value
    relationship = relationship('User_challenge')

# Challenge attributes
class Challenges(db.Model):
    id = Column(Integer, primary_key=True, unique=True, nullable=False)
    ctf_string = Column(String(40), nullable=False, unique=True)
    ctf_weight = Column(Integer, nullable=False)
    relationship = relationship('User_challenge')

#join table
class User_challenge(db.Model):
    user_id = Column(Integer, ForeignKey(User.id), primary_key=True)
    challenge_id = Column(Integer, ForeignKey(Challenges.id), primary_key=True)

# create above tables
db.create_all()
# add admin to group 1
db.engine.execute("update user set role=1 where username='admin';")


#Register form
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=3, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=6, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            flash("Username not available.")

# login form
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=1, max=80)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")

# Challenges form
class ChallengeForm(FlaskForm):
    ctf_string = StringField(validators=[InputRequired()],render_kw={"placeholder": "FLAG{Capture_the_flag}",})
    submit = SubmitField("Submit")

# adding challenges in admin dashboard
class AddChallengeForm(FlaskForm):
    ctf_string = StringField(validators=[InputRequired()])
    ctf_weight = IntegerField(validators=[InputRequired()])
    submit = SubmitField("Add")

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

# Add some error handling here
@app.route('/login', methods=['GET', 'POST'])
def login():
    #Initialize a object from LoginForm class
    form = LoginForm()
    if form.validate_on_submit():
        user =  User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash("Wrong username or password")
                return redirect(url_for('login'))
        if not user: 
            flash("Wrong username or password")
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    try:
        if form.validate_on_submit():
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Registration success")
            return redirect(url_for('login'))
    except:
        flash("Account already exist")
        return redirect(url_for('register'))
    return render_template('register.html', form=form)

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template("dashboard.html")



@app.route("/admin", methods=['GET', 'POST'])
@login_required
def admin():
    query = db.session.query(Challenges).all()
    form = AddChallengeForm()

    # restricts normal users for accessing the panel
    if current_user.role == 0: 
        return redirect(url_for('dashboard'))

    elif current_user.role == 1:
        if form.validate_on_submit():
            try:
                add_challenge = Challenges(ctf_string=form.ctf_string.data, ctf_weight=form.ctf_weight.data)
                db.session.add(add_challenge)
                db.session.commit()
                flash("Successfully added a challenge")
                return redirect("admin")
            except:
                flash("Challenge already exist")
                return redirect(url_for('admin'))
    return render_template('admin.html', form=form, query=query)

# Delete challenge
@login_required
@app.route("/delete/<int:id>", methods=['GET', 'POST'])
def delete(id):
    challenge = Challenges.query.get_or_404(id)
    if current_user.role == 1:
        try:
            db.session.delete(challenge)
            db.session.commit()
            flash("Successfully deleted challenge")
            return redirect(url_for("admin"))
        except:
            flash("Couldn't delete that challenge")
            return redirect(url_for("admin"))

@app.route("/get_started")
def get_started():
    return render_template("get_started.html")

#TODO 
#Add function to display completed and noncompleted challenges
#Query all challenge ID's
#Select Challenge ID's from current user and compare with all challenges


@app.route("/challenges", methods=['GET', 'POST'])
@login_required
def challenges():
    form = ChallengeForm() # initialize the ChallengeForm
    current_points = current_user.total_points
    username = current_user.username
    #newPointValue = User(total_points=User.total_points + check.ctf_weight) # to add current points with new points
    check = Challenges.query.filter_by(ctf_string=form.ctf_string.data).first()
    if check: # Checks if the flag submitted exists in the challenge table.
        try: # to counter errors that occur when putting same challenge twice
            db.session.execute(update(User).where(User.username =='{}'.format(username)).values(total_points='{}'.format(check.ctf_weight + current_points))) # updates the new score if the challenge exists
            add_jointable = User_challenge(user_id=current_user.id, challenge_id=check.id) # adds the completed challenge into join table with the user id
            db.session.add(add_jointable)
            db.session.commit()
            flash("Well done! you've completed a challenge")
            return redirect(url_for("challenges"))
        except:
            flash("Challenge has already been submitted")
            return redirect(url_for("challenges"))
    return render_template("challenges.html", form=form)



@app.route("/leaderboard", methods=['GET'])
def leaderboard():
    score = User.query.order_by(User.total_points.desc()).all() # queries high->low score in db to use in leaderboard template
    rank = db.session.execute("select RANK() OVER(ORDER BY total_points DESC) AS rank FROM user;").all()
    # Normalizes data received from rank query
    rank2 = []
    for i in rank:
        rank2.append(i.rank)
    return render_template("leaderboard.html", score=score, rank=rank2)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)