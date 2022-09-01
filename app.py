import json
from db import db
from db import User
from db import Question
from flask import Flask
from flask import request

from datetime import datetime
import users_dao

app = Flask(__name__)
db_filename = "data.db"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()

def success_response(data, code=200):
    return json.dumps(data), code

def failure_response(message, code=404):
    return json.dumps({"error": message}), code


#test endpoint
@app.route("/")
def hello_world():
    """
    Endpoint for printing Hello World!
    """
    return "Hello World!"

#routes here
@app.route("/api/users/")
def get_all_users():
    """
    Endpoint for getting all users
    """
    return success_response({"users": [c.serialize() for c in User.query.all()]})

@app.route("/api/users/id/")
def get_user_id():
    """
    Endpoint for getting a user's id
    """
    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None:
        return failure_response("User not found!")
    return json.dumps(user.id)

@app.route("/api/user/")
def get_user():
    """
    Endpoint for getting a user
    """
    #get user by session token
    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None:
        return failure_response("User not found!")
    return success_response(user.serialize())

@app.route("/api/user/", methods=["DELETE"])
def delete_user():
    """
    Endpoint for deleting a user
    """
    #delete user by session token
    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None or not user.verify_session_token(extract_token(request)[1]):
        return failure_response("User not found!")
    db.session.delete(user)
    db.session.commit()
    return success_response(user.serialize())

@app.route("/api/questions/", methods=["POST"])
def create_question():
    """
    Endpoint for creating a question
    """
    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None or not user.verify_session_token(extract_token(request)[1]):
        return failure_response("User not found!")
    body = json.loads(request.data)
    if body.get("response") is None or body.get("description") is None:
        return failure_response("Missing parameters",400)
    new_question = Question(response=body.get("response"), description=body.get("description"), asked=user.id, user_id=user.id)
    db.session.add(new_question)
    db.session.commit()
    return success_response(new_question.serialize(), 201)

@app.route("/api/questions/")
def get_all_unanswered_questions():
    """
    Endpoint for getting all questions
    """
    questions = Question.query.filter_by(answered = None)
    return success_response({"questions": [c.serialize() for c in questions.all()]})

@app.route("/api/questions/next/")
def get_next_unanswered_questions():
    """
    Endpoint for getting next unanswered question
    """
    questions = Question.query.filter_by(answered = None)
    if questions is None:
        return failure_response("Question not Found!")

    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None:
        return failure_response("Invalid session token")
    for q in questions:
        if q.asked != user.id:
            return success_response({"question": q.serialize()})

    return failure_response("Question not Found!")

@app.route("/api/questions/<int:question_id>/")
def get_question(question_id):
    """
    Endpoint for getting a question by question_id
    """
    question = Question.query.filter_by(id=question_id).first()
    if question is None:
        return failure_response("Question not Found!")
    return success_response(question.serialize())

@app.route("/api/questions/<int:question_id>/", methods=["DELETE"])
def delete_question(question_id):
    """
    Endpoint for deleting a question by question_id
    """
    question = Question.query.filter_by(id=question_id).first()
    if question is None:
        return failure_response("Question not found!")
    db.session.delete(question)
    db.session.commit()
    return success_response(question.serialize())

@app.route("/api/questions/<int:question_id>/", methods=["POST"])
def reply_to_question(question_id):
    """
    Endpoint for responding to a question
    """
    question = Question.query.filter_by(id=question_id).first()
    if question is None:
        return failure_response("Question not found!")
        
    body = json.loads(request.data)
    if body.get("response") is None:
        return failure_response("Missing parameters")

    if question.answered is None:
        user = users_dao.get_user_by_session_token(extract_token(request)[1])
        if not user:
            return failure_response("User not authenticated!", 403)
        else:
            question.answered = user.id
        response = body.get("response")
        question.response = response
    else:
        return json.dumps({"error": "Question has already been responded to!"}), 403
    #db.session.update()
    db.session.commit()
    return success_response(question.serialize())

@app.route("/api/questions/asked/")
def get_asked_questions():
    """
    Endpoint for getting asked question
    """
    #getting asked questions by session token
    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None or not user.verify_session_token(extract_token(request)[1]):
        return failure_response("Invalid session token")
    user_id=user.id
    asked_questions = Question.query.filter_by(asked=user_id)
    if asked_questions is None:
        return failure_response("Question not Found!")
    return success_response({"asked": [c.serialize() for c in asked_questions.all()]})

@app.route("/api/questions/answered/")
def get_answered_questions():
    """
    Endpoint for getting answered question
    """
    #Get user's answered questions by session token
    user = users_dao.get_user_by_session_token(extract_token(request)[1])
    if user is None or not user.verify_session_token(extract_token(request)[1]):
        return failure_response("Invalid session token")
    user_id=user.id
    answered_questions = Question.query.filter_by(answered=user_id)
    if answered_questions is None:
        return failure_response("Question not Found!")
    return success_response({"answered": [c.serialize() for c in answered_questions.all()]})

def extract_token(request):
    """
    Helper function that extracts the token from the header of a request
    """
    auth_header = request.headers.get("Authorization")

    if auth_header is None:
        return False, json.dumps({"error":"Missing Authorization header"})
    
    bearer_token = auth_header.replace("Bearer", "").strip()

    return True, bearer_token

#authorization
@app.route("/register/", methods=["POST"])
def register_account():
    """
    Endpoint for registering a new user
    """
    body = json.loads(request.data)
    username = body.get("username")
    password = body.get("password")

    if username is None or password is None:
        return failure_response("Missing username or password")

    was_successful, user = users_dao.create_user(username, password)
    
    if not was_successful:
        return failure_response("User already exists")
    
    return success_response(
        {
            "session token": user.session_token,
            "session_expiration": str(user.session_expiration),
            "update_token": user.update_token

        }, 201  
    )


@app.route("/login/", methods=["POST"])
def login():
    """
    Endpoint for logging in a user
    """
    body = json.loads(request.data)
    username = body.get("username")
    password = body.get("password")

    if username is None or password is None:
        return failure_response("Missing username or password")

    was_successful, user = users_dao.verify_credentials(username, password)

    if not was_successful:
        return failure_response("incorrect username or password")

    return success_response(
        {
            "session token": user.session_token,
            "session_expiration": str(user.session_expiration),
            "update_token": user.update_token
        }
    )

@app.route("/session/", methods=["POST"])
def update_session():
    """
    Endpoint for updating a user's session
    """
    was_successful, update_token = extract_token(request)
    
    if not was_successful:
        return update_token
    try:
        user = users_dao.renew_session(update_token)
    except Exception as e:
        return failure_response(f"Invalid update token: {str(e)}")

    return success_response(
        {
            "session token": user.session_token,
            "session_expiration": str(user.session_expiration),
            "update_token": user.update_token 
        }
    )



@app.route("/secret/", methods=["GET"])
def secret_message():
    """
    Endpoint for verifying a session token and returning a secret message
    """
    was_successful, session_token = extract_token(request)

    if not was_successful:
        return session_token
    
    user = users_dao.get_user_by_session_token(session_token)
    if not user or not user.verify_session_token(session_token):
        return failure_response("Invalid session token")

    return success_response(
        {"message":"You have successfully implemented sessions!"}
    )

@app.route("/logout/", methods = ["POST"])
def logout():
    was_successful, session_token = extract_token(request)

    if not was_successful:
        return session_token
    
    user = users_dao.get_user_by_session_token(session_token)
    if not user or not user.verify_session_token(session_token):
        return failure_response("Invalid session token")

    user.session_expiration = datetime.now()
    db.session.commit()

    return success_response(
        {
            "message":"you have successfully logged out!"
        }
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
