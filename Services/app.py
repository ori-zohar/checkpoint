from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy




app = Flask(__name__)
app.secret_key = "Secret Key"

#SqlAlchemy Database Configuration With Mysql
app.config['SQLALCHEMY_DATABASE_URI'] = 'http://demo.phpmyadmin.net/master-config/index.php?route=/database/operations&server=2&db=ori'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#Creating model table for our CRUD database
class Data(db.Model):
    __tablename__ = 'rule_fw'
    id = db.Column(db.Integer, primary_key = True)
    personal_number = db.Column(db.String(100))
    project = db.Column(db.String(100))
    source = db.Column(db.String(100))
    destination = db.Column(db.String(100))
    port_TCP = db.Column(db.String(100))
    port_UDP = db.Column(db.String(100))
    datatime = db.Column(db.String(100))
    link_type =db.Column(db.String(100))
    massage = db.Column(db.String(500))

    def __init__(self, personal_number,project,source,destination,port_TCP ,port_UDP ,datatime, link_type,massage):

        self.personal_number = personal_number
        self.project = project
        self.source = source
        self.destination = destination
        self.port_TCP = port_TCP
        self.port_UDP = port_UDP
        self.datatime = datatime
        self.link_type = link_type
        self.massage = massage


#This is the index route where we are going to
#query on all our employee data
@app.route('/')
def Index():
    all_data = Data.query.all()
    return render_template("index.html", employees = all_data)



#this route is for inserting data to mysql database via html forms
@app.route('/insert', methods = ['POST'])
def insert():

    if request.method == 'POST':

        personal_number = request.form['personal_number']
        project = request.form['project']
        source = request.form['source']
        destination = request.form['destination']
        port_TCP = request.form['port_TCP']
        port_UDP = request.form['port_UDP']
        datatime = request.form['datatime']
        link_type = request.form['link_type']
        massage = request.form['massage']

        my_data = Data(personal_number, project,source ,destination,port_TCP ,port_UDP ,datatime ,link_type ,massage)
        db.session.add(my_data)
        db.session.commit()

        flash("Employee Inserted Successfully")

        return render_template('bini.html')


#this is our update route where we are going to update our employee
@app.route('/update', methods=['GET', 'POST'])
def update():

    if request.method == 'POST':
        my_data = Data.query.get(request.form.get('id'))

        my_data.name = request.form['name']
        my_data.email = request.form['email']
        my_data.phone = request.form['phone']
        my_data.rsonal_number = request.form['personal_number']
        my_data.project = request.form['project']
        my_data.source = request.form['source']
        my_data.destination = request.form['destination']
        my_data.port_TCP = request.form['port_TCP']
        my_data.port_UDP = request.form['port_UDP']
        my_data.datatime = request.form['datatime']
        my_data.link_type = request.form['link_type']
        my_data.massage = request.form['massage']

        db.session.commit()
        flash("Employee Updated Successfully")

        return render_template('bini.html')


#This route is for deleting our employee
@app.route('/delete/<id>/', methods = ['GET', 'POST'])
def delete(id):
    my_data = Data.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Employee Deleted Successfully")

    return redirect(url_for('Index'))

if __name__ == "__main__":
    app.run(debug=True)