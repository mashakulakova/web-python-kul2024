from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import login_required, current_user
from mysql_db import MySQL
import mysql.connector

app = Flask(__name__)

application = app

app.config.from_pyfile('config.py')

db = MySQL(app)

from auth import bp_auth, check_rights, init_login_manager
from visits import bp_visit

app.register_blueprint(bp_auth)
app.register_blueprint(bp_visit)
app.jinja_env.globals.update(current_user=current_user)

init_login_manager(app)


@app.before_request
def journal():
    query = '''
        INSERT INTO `visit_logs` (path, user_id) VALUES (%s, %s)
    '''
    try:
        cursor = db.connection().cursor(named_tuple=True)
        cursor.execute(query, (request.path, getattr(current_user, "id", None)))
        db.connection().commit()
        cursor.close()
    except mysql.connector.errors.DatabaseError:
        db.connection().rollback()


def get_roles():
    query = 'SELECT * FROM roles'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query)
    roles = cursor.fetchall()
    cursor.close()
    return roles


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/users/')
@login_required
def show_users():
    query = '''
        SELECT users.*, roles.name as role_name
        FROM users
        LEFT JOIN roles
        on roles.id = users.role_id
        '''
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query)
    users = cursor.fetchall()
    cursor.close()
    return render_template('users/index.html',users=users)


@app.route('/users/create', methods = ['POST', 'GET'])
@login_required
@check_rights('create')
def create():
    roles = get_roles()
    if request.method == 'POST':
        login = request.form['login']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        middle_name = request.form['middle_name']
        password = request.form['oldpassword']
        role_id = request.form['role_id']
        try:
            query = '''
                insert into users (login, last_name, first_name, middle_name, password_hash, role_id)
                VALUES (%s, %s, %s, %s, SHA2(%s, 256), %s)
                '''
            cursor = db.connection().cursor(named_tuple=True)
            cursor.execute(query, (login, last_name, first_name, middle_name, password, role_id))
            db.connection().commit()
            flash(f'Пользователь {login} успешно создан.', 'success')
            cursor.close()
        except mysql.connector.errors.DatabaseError:
            db.connection().rollback()
            flash(f'При создании пользователя произошла ошибка.', 'danger')
            return render_template('users/create.html')

    return render_template('users/create.html', roles=roles)


@app.route('/users/show/<int:user_id>')
@login_required
@check_rights('show')
def show_user(user_id):
    query = 'SELECT users.*, roles.name AS role_name FROM users LEFT JOIN roles ON users.role_id = roles.id WHERE users.id=%s'
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('users/show.html', user=user)


@app.route('/users/edit/<int:user_id>', methods=["POST", "GET"])
@check_rights('edit')
def edit(user_id):
    roles = get_roles()
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        middle_name = request.form['middle_name']
        try:
            if current_user.is_admin():
                role_id = request.form['role_id']
                query = '''
                    UPDATE users set first_name = %s, last_name = %s, middle_name = %s, role_id = %s where id = %s
                    '''
                cursor = db.connection().cursor(named_tuple=True)
                cursor.execute(query, (first_name, last_name, middle_name, role_id, user_id))
                db.connection().commit()
            else:
                query = '''
                    UPDATE users set first_name = %s, last_name = %s, middle_name = %s where id = %s
                    '''
                cursor = db.connection().cursor(named_tuple=True)
                cursor.execute(query, (first_name, last_name, middle_name, user_id))
                db.connection().commit()
            flash(f'Данные пользователя {first_name} успешно обновлены.', 'success')
            cursor.close()
        except mysql.connector.errors.DatabaseError:
            db.connection().rollback()
            flash(f'При обновлении пользователя произошла ошибка.', 'danger')
            return render_template('users/edit.html')

    query = '''
        SELECT users.*, roles.name as role_name
        FROM users
        LEFT JOIN roles
        on roles.id = users.role_id
        where users.id=%s
        '''
    cursor = db.connection().cursor(named_tuple=True)
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()
    cursor.close()
    return render_template('users/edit.html', user=user, roles=roles)

@app.route('/users/delete/')
@check_rights('delete')
def delete():
    try:
        user_id = request.args.get('user_id')
        query = '''
            DELETE from users where id = %s
            '''
        cursor = db.connection().cursor(named_tuple=True)
        cursor.execute(query, (user_id,))
        db.connection().commit()
        flash(f'Пользователь {user_id} успешно удален.', 'success')
        cursor.close()
    except mysql.connector.errors.DatabaseError:
        db.connection().rollback()
        flash(f'При удалении пользователя произошла ошибка.', 'danger')
        return render_template('users/index.html', user_id=user_id)

    return redirect(url_for('show_users'))
