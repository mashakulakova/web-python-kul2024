from flask import Flask, render_template,request, make_response

app = Flask(__name__)

application = app

@app.route('/')
def index():
    msg = 'Hello world'
    return render_template('index.html',msg=msg)

@app.route('/argv')
def argv():
    return render_template('argv.html')

@app.route('/calc')
def calc():
    result = ''
    num1 =  request.args.get('num1') 
    oper = request.args.get('operation') 
    num2 = request.args.get('num2')
    if oper == "+": 
        result = int(num1)+ int(num2)
    elif oper == "-":
        result = int(num1) - int(num2)
    elif oper == "*":
        result = int(num1) * int(num2)
    elif oper == "/":
        result = int(num1)/int(num2)

    return render_template('calc.html', result=result)

@app.route('/headers')
def headers():
    return render_template('headers.html')

@app.route('/cookie')
def cookie():
    resp = make_response(render_template('cookie.html'))
    if 'user' in request.cookies:
        resp.delete_cookie('user')
    else:
        resp.set_cookie('user','NoName')
    return resp

@app.route('/form', methods = ['POST', 'GET'])
def form():
    return render_template('form.html')

@app.route('/number', methods=['GET', 'POST'])
def number():
    if request.method == 'POST':
        phone_number = request.form['phone_number']
        error = None

        phone_number_digits = ''.join(filter(str.isdigit, phone_number))
        if (phone_number.startswith('+7') or phone_number.startswith('8')) and len(phone_number_digits) != 11:
            error = 'Недопустимый ввод. Неверное количество цифр.'

        if len(phone_number_digits) > 11:
            error = 'Недопустимый ввод. Неверное количество цифр.'
        
        if len(phone_number_digits) < 10:
            error = 'Недопустимый ввод. Неверное количество цифр.'

        allowed_chars = set('0123456789 +()-.')
        if not all(char in allowed_chars for char in phone_number):
            error = 'Недопустимый ввод. В номере телефона встречаются недопустимые символы.'

        if phone_number.startswith('+7'):
            phone_number_digits = phone_number_digits[1:]  # Удаляем +7 из начала номера
        elif phone_number.startswith('8'):
            phone_number_digits = phone_number_digits[1:]  # Удаляем 8 из начала номера
        elif phone_number.startswith('7'):
            phone_number_digits = phone_number_digits[1:]  # Удаляем 7 из начала номера


        if error:
            return render_template('number.html', error=error, phone_number=phone_number)
        elif len(phone_number_digits) == 10:
            formatted_number = '8-{}-{}-{}-{}'.format(phone_number_digits[:3], phone_number_digits[3:6], phone_number_digits[6:8], phone_number_digits[8:])
            return render_template('number.html', success=True, formatted_number=formatted_number)

    return render_template('number.html')