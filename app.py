# importing required libraries
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, logout_user, login_required, UserMixin, current_user, LoginManager
import uuid
from collections import Counter
import json
import numpy as np
import pandas as pd

# Declaring required configurations
app = Flask(__name__)
app.secret_key = "secret-key"
app.config['SQLALCHEMY_DATABASE_URI'] ='mysql+mysqlconnector://'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Declaring our database
class User(db.Model, UserMixin):
    __tablename__ = 'user_data_test'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

class Expense(db.Model):
    __tablename__ = 'expense_details'
    expenseid = db.Column(db.String(45), primary_key=True,default=str(uuid.uuid4()))
    expense_description = db.Column(db.String(100))
    expense_amount = db.Column(db.Integer)
    expense_category = db.Column(db.String(30))

# Our main login manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Authentication Functions
@app.route('/signup', methods=['GET', 'POST']) 
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user:
            flash('Username already exists, please choose another one', 'danger')
            return redirect(url_for('signup'))

        new_user = User(email=email, name=name, password=password)
        db.session.add(new_user)
        db.session.commit()
        print(email,name,password)
        flash('Account created successfully.', 'success')
        return render_template("login.html")
    return render_template("signup.html")

@app.route('/login', methods=['GET', 'POST']) 
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        if not email or not password:
            flash("Please provide both email and password.")
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()

        if not user or (user.password != password):
            flash("Your Login details are incorrect.")
            return redirect('login')

        login_user(user, remember=remember)
        return redirect(url_for('home'))

    return render_template("login.html")

@app.route('/logout') 
@login_required
def logout():
    logout_user()
    flash("You have been Logged Out!")
    return redirect(url_for('login'))

# Main Functions
categories = ['Food', 'Transportation', 'Shopping', 'Bills', 'Entertainment','Other','All']
@app.route("/")
@login_required
def home():
    category_sums = {}
    for category in categories:
        total_amount = db.session.query(db.func.sum(Expense.expense_amount)).filter_by(expense_category=category).scalar() or 0
        category_sums[category] = total_amount
    return render_template('index.html', category_sums=category_sums, name=current_user.name)

@app.route("/dashboard", methods=['GET', 'POST'])
@login_required
def dashboard():  
    if request.method == 'POST':
        category = request.form['expense_category']
        if category=='All':
            expenses = Expense.query.all()
            return render_template('dashboard.html', expenses=expenses,categories=categories)
        expenses = Expense.query.filter_by(expense_category=category).all()
        return render_template('dashboard.html', expenses=expenses,categories=categories)
    expenses = Expense.query.all()
    return render_template('dashboard.html', expenses=expenses,categories=categories)

@app.route('/addexp', methods=['GET', 'POST'])
@login_required
def addexp():
    if request.method == 'POST':
        try:
            expenseid = str(uuid.uuid4()) 
            expense_description = request.form['expense_description']
            expense_amount = int(request.form['expense_amount'])
            expense_category = request.form['expense_category']

            new_expense = Expense(expenseid=expenseid, expense_description=expense_description, expense_amount=expense_amount, expense_category=expense_category)
            db.session.add(new_expense)
            db.session.commit()

            result = {
                'message': "Expense added successfully",
                'status': "success",
                }
            return jsonify(result)
        except Exception as e:
            print(f"Error: {str(e)}")
            return jsonify({'error': 'Internal Server Error'}), 500
    return render_template('addexp.html', categories=categories)

@app.route('/edit_expense', methods=['GET', 'POST'])
def edit_expense():
    if request.method == 'POST':
        expenseid = request.form['expenseid']
        expense = Expense.query.get(expenseid)
        if not expense:
            return jsonify({'error': 'Expense not found'}), 404
        try:
            expense.expense_description = request.form['expense_description']
            expense.expense_amount = int(request.form['expense_amount'])
            expense.expense_category = request.form['expense_category']

            db.session.commit()

            result = {
                'message': "Expense added successfully",
                'status': "success",
                }
            return jsonify(result)
        except Exception as e:
            print(f"Error: {str(e)}")
            return jsonify({'error': 'Internal Server Error'}), 500
    return render_template('edit_expense.html', expense=expense, categories=categories)

@app.route('/delete_expense/<string:expenseid>')
def delete_expense(expenseid):
    expense = Expense.query.get(expenseid)
    return render_template('delete_expense.html', expense=expense)

@app.route('/confirm_delete/<string:expenseid>', methods=['POST'])
def confirm_delete(expenseid):
    expense = Expense.query.get(expenseid)
    try:
        db.session.delete(expense)
        db.session.commit()
        result = {
                'message': "Expense added successfully",
                'status': "success",
                }
        return jsonify(result)
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({'error': 'Internal Server Error'}), 500
    return redirect(url_for('dashboard'))

@app.route('/analysis', methods=['GET', 'POST'])
@login_required
def analysis():
    if request.method == 'POST':
        try:
            f = request.files['file']  
            data = pd.read_csv(f)
            if list(data.columns) != ['expenseid','expense_description','expense_amount','expense_category']:
                flash("The CSV file does not contain required Columns.")
                return render_template('data_analysis.html')
            # Define Plot Data 
            list1 = data.iloc[:, 3].tolist()
            ch_data = Counter(list1) 
            labels = list(ch_data.keys())
            data = list(ch_data.values())
            result = {
                'labels': labels,
                'data': data,
            }
            return jsonify(result)
        except Exception as e:
            print(f"Error: {str(e)}")
            return jsonify({'error': 'Internal Server Error'}), 500
    return render_template('data_analysis.html')

if __name__ == "__main__":
    app.run(debug=True)

