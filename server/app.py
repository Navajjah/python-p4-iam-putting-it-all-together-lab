#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe
from werkzeug.security import generate_password_hash, check_password_hash

class Signup(Resource):
    def post(self):
        data = request.get_json()

        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400
        
        password_hash = generate_password_hash(password)
        
        new_user = User(username=username, _password_hash=password_hash, image_url=image_url, bio=bio)
        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Failed to create user'}), 500

        session['user_id'] = new_user.id
        return jsonify ({
            'id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }), 201

class CheckSession(Resource):
    def get(self):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        user = User.query.get(session['user_id'])  # Updated to use session.get()
        new_user = User(username=username, _password_hash=password_hash, image_url=image_url, bio=bio)

        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Failed to create user'}), 500

        session['user_id'] = new_user.id
        return jsonify ({
            'id': new_user.id,
            'username': new_user.username,
            'image_url': new_user.image_url,
            'bio': new_user.bio
        }), 201

class CheckSession(Resource):
    def get(self):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        user = db.session.get(User, session['user_id'])  # Updated to use session.get()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify ({
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        }), 200

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user._password_hash, password):
            return jsonify({'error': 'Invalid username or password'}), 401
        session['user_id'] = user.id

        return jsonify({
            'id': user.id,
            'username': user.username,
            'image_url': user.image_url,
            'bio': user.bio
        })

class Logout(Resource):
    def delete(self):
        session.pop('user_id', None)
        return '', 204

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        recipes = Recipe.query.all()  # Renamed variable
        return jsonify([{
            'id': recipe.id,
            'title': recipe.title,
            'instructions': recipe.instructions,
            'minutes_to_complete': recipe.minutes_to_complete,
            'user': {
                'id': recipe.user_id,
                'username': User.query.get(recipe.user_id).username
            }
        } for recipe in recipes]), 200
    
    def post(self):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        data = request.get_json()
        title = data.get('title')
        instructions = data.get('instructions')
        minutes_to_complete = data.get('minutes_to_complete')

        if not title or not instructions or len(instructions) < 50:
            return jsonify({'error': 'Invalid data'}), 422
        
        user = User.query.get(session['user_id'])
        new_recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete, user=user)
        try:
            db.session.add(new_recipe)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return jsonify({'error': 'Failed to create recipe'}), 500

        return jsonify ({
            'id': new_recipe.id,
            'title': new_recipe.title,
            'instructions': new_recipe.instructions,
            'minutes_to_complete': new_recipe.minutes_to_complete,
            'user': {
                'id': user.id,
                'username': user.username
            }
        }), 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
