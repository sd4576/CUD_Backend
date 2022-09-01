from flask_sqlalchemy import SQLAlchemy
import datetime
import hashlib
import os
import bcrypt



# you have classes and objects --> translation b/w SQL and Python code
db = SQLAlchemy()
 
# implement database model classes
class User(db.Model):
    """
    User model

    Has a one-to-many relationship with the Question model
    """
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # User information
    username = db.Column(db.String, nullable=False, unique=True)
    password_digest = db.Column(db.String, nullable=False)
    # Session information
    session_token = db.Column(db.String, nullable=False, unique=True)
    session_expiration = db.Column(db.DateTime, nullable=False)
    update_token = db.Column(db.String, nullable=False, unique=True)
    
    questions = db.relationship("Question", cascade="delete")

    def __init__(self, **kwargs):
        """
        Initialize Users object/entry
        """

        self.username = kwargs.get("username")
        self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds=13))

        self.renew_session()    
 
    def serialize(self):
       """
       Serialize Users object
       """
       return {
            "id": self.id
        }
 
    def _urlsafe_base_64(self):
        """
        Randomly generates hashed tokens (used for session/update tokens)
        """
        return hashlib.sha1(os.urandom(64)).hexdigest()

    def renew_session(self):
        """
        Renews the sessions, i.e.
        1. Creates a new session token
        2. Sets the expiration time of the session to be a day from now
        3. Creates a new update token
        """
        self.session_token = self._urlsafe_base_64()
        self.session_expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        self.update_token = self._urlsafe_base_64()

    def verify_password(self, password):
        """
        Verifies the password of a user
        """
        return bcrypt.checkpw(password.encode("utf8"), self.password_digest)

    def verify_session_token(self, session_token):
        """
        Verifies the session token of a user
        """
        return session_token == self.session_token and datetime.datetime.now() < self.session_expiration

    def verify_update_token(self, update_token):
        """
        Verifies the update token of a user
        """
        return update_token == self.update_token

class Question(db.Model):
    """
    Question Model
 
    Has a one-to-many relationship with the User model
    """
    __tablename__ = "questions"
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    description = db.Column(db.String, nullable = False)
    response = db.Column(db.Integer, nullable = False)
    asked = db.Column(db.Integer, nullable = False)
    answered = db.Column(db.Integer, nullable = True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable = False)
 
    def __init__(self, **kwargs):
        """
        Initialize Questions object
        """
        self.description = kwargs.get("description", "")
        self.response = kwargs.get("response")
        self.asked = kwargs.get("asked")
        self.answered = kwargs.get("answered", None)
        self.user_id = kwargs.get("user_id")
 
    def serialize(self):
        """
        Serialize a Questions object
        """
        return{
            "id": self.id,
            "description": self.description,
            "response": self.response,
            "asked": self.asked,
            "answered": self.answered,
            "user_id": self.user_id
        }


