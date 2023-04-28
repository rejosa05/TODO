from flask import Blueprint, render_template,request,flash,jsonify
from flask_login import login_required, current_user
from .models import Note
from . import db
import json

views = Blueprint('views',__name__)

@views.route('/', methods = ['GET','POST'])
@login_required
def index():
    if request.method == 'POST':
        note = request.form.get('note')

        if note == '':
            flash("Please enter notes!!",category='error')
        elif len(note) < 5:
            flash("Note is to short!", category='error')
        else:
            note = Note(data=note,user_id=current_user.id)
            db.session.add(note)
            db.session.commit()
            flash("Note Added Successfully!!")
            #return redirect (url_for('views.index'))        
    return render_template("home.html", user=current_user)

@views.route('/delete-note', methods =['POST'])
def delete_note():
    note = json.loads(request.data)
    noteId = note['noteId']
    note = Note.query.get(noteId)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
    return jsonify({})

@views.route('/update')
def update_note():
    pass