# -*- coding: utf-8 -*-

import boto3
import datetime

from flask import Flask
from flask import jsonify, request, abort
from flask_cors import CORS

from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity

import flask_bcrypt
from flask_bcrypt import Bcrypt

import os
from pymongo import MongoClient, DESCENDING

from bson.objectid import ObjectId
from werkzeug.utils import secure_filename

from encoder import JSONEncoder
from mailing import send_mail

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=5)

client = MongoClient(os.environ.get('MONGO_URL'))
db = client.RecruitDSM

ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY')
SECRET_KEY = os.environ.get('AWS_SECRET_KEY')
REGION = 'ap-northeast-2'

s3 = boto3.client('s3', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET_KEY, region_name=REGION)

S3_BUCKET_PATH = "https://recruitdsm.s3.ap-northeast-2.amazonaws.com/"

flask_bcrypt = Bcrypt(app)
jwt = JWTManager(app)
app.json_encoder = JSONEncoder


@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e)), 400


def get_all_document(cursor, apply=None):
    output = []
    for document in cursor:
        document['_id'] = str(document['_id'])
        output.append(document)
    if apply:
        output = list(map(apply, output))
    return output


def upload_file_to_s3(file, name, key):
    filename = secure_filename(name)
    s3_response = s3.put_object(Body=file, Bucket="recruitdsm", Key=key + filename, ContentType=request.mimetype)
    if s3_response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return S3_BUCKET_PATH + key + filename
    else:
        raise Exception


def change_date_format(document):
    document['date'] = document['date'].strftime('%y/%m/%d')
    return document


@app.route('/api/employee', methods=['GET'])
def get_employee():
    cursor = db.employees.find({})
    return jsonify({'employees': get_all_document(cursor)}), 200


@app.route('/api/recruitment/<id>', methods=['GET'])
@jwt_required
def get_recruitment(id):
    recruitment = db.recruitments.find_one({'_id': ObjectId(id)}, {'_id': False})
    if recruitment:
        return jsonify({'recruitment': recruitment}), 200
    else:
        abort(400, description='Failed to get recruitment.')


@app.route('/api/company/<id>', methods=['GET'])
@jwt_required
def get_company(id):
    company = db.company.find_one({'_id': ObjectId(id)}, {'_id': False})
    if company:
        return jsonify({'company': company}), 200
    else:
        abort(400, description='Failed to get company.')


@app.route('/api/notice/<id>', methods=['GET'])
@jwt_required
def get_notice(id):
    notice = db.notices.find_one({'_id': ObjectId(id)}, {'_id': False})
    if notice:
        notice['date'] = notice['date'].strftime('%y/%m/%d')
        return jsonify({'notice': notice}), 200
    else:
        abort(400, description='Failed to get notice.')


@app.route('/api/recruitment', methods=['GET'])
@jwt_required
def get_recruitments():
    query = {}
    if request.args:
        for filter in ['position', 'region', 'status']:
            query_params = request.args.getlist(filter)
            if "전체" not in query_params:
                query[filter] = {'$in': query_params}

    cursor = db.recruitments.find(query).sort('_id', DESCENDING)
    is_authorized = db.users.find_one({'email': get_jwt_identity()['email']})['membership'] == 1

    return jsonify({'recruitments': get_all_document(cursor), 'isAuthorized': is_authorized}), 200


@app.route('/api/company', methods=['GET'])
@jwt_required
def get_companys(page_size=12):
    try:
        skips = int(request.args.get('skip'))
        cursor = db.company.find({}).sort('_id', DESCENDING).skip(skips).limit(page_size)

        is_authorized = db.users.find_one({'email': get_jwt_identity()['email']})['membership'] == 1

        return jsonify({'companys': get_all_document(cursor), 'isAuthorized': is_authorized}), 200
    except Exception as e:
        print(str(e))
        abort(400, description='Bad request params.')


@app.route('/api/notice', methods=['GET'])
@jwt_required
def get_notices(page_size=15):
    try:
        skips = int(request.args.get('skip'))
        cursor = db.notices.find({}).sort('date', DESCENDING).skip(skips).limit(page_size)

        is_authorized = db.users.find_one({'email': get_jwt_identity()['email']})['membership'] == 1

        return jsonify({'notices': get_all_document(cursor, change_date_format), 'isAuthorized': is_authorized}), 200
    except Exception as e:
        print(str(e))
        abort(400, description='Bad request params.')


@app.route('/api/recruitment', methods=['POST'])
@jwt_required
def create_recruitment():
    _form = request.form.to_dict()

    recruit_img_paths = []
    document_file_path = ''

    try:
        for name, file in request.files.items():
            if name.split('.')[-1] in ['pdf', 'PDF']:
                document_file_path = upload_file_to_s3(file, name, 'recruitment/document/')
            else:
                recruit_img_paths.append(upload_file_to_s3(file, name, 'recruitment/recruit_img/'))

        _form['document_file_path'] = document_file_path
        _form['recruit_img_paths'] = recruit_img_paths

        db_response = db.recruitments.insert_one(_form)
        if db_response.inserted_id:
            return jsonify({'message': 'Created recruitment successfully.'}), 201
        else:
            return abort(400, description='Failed to create recruitment.')
    except Exception as e:
        print(str(e))
        abort(400, description='Failed to upload recruitment to s3.')


@app.route('/api/company', methods=['POST'])
@jwt_required
def create_company():
    _form = request.form.to_dict()

    company_img_paths = []

    try:
        for name, file in request.files.items():
            company_img_paths.append(upload_file_to_s3(file, name, 'company/'))

        _form['company_img_paths'] = company_img_paths

        db_response = db.company.insert_one(_form)
        if db_response.inserted_id:
            return jsonify({'message': 'Created company successfully.'}), 201
        else:
            return abort(400, description='Failed to create company.')
    except Exception as e:
        print(str(e))
        abort(400, description='Failed to upload recruitment to s3.')


@app.route('/api/notice', methods=['POST'])
@jwt_required
def create_notice():
    try:
        _form = request.form.to_dict()

        attachment_paths = []

        for name, file in request.files.items():
            filename = secure_filename(name)
            s3_response = s3.put_object(Body=file, Bucket="recruitdsm", Key="notice/" + filename,
                                        ContentType=request.mimetype)
            if s3_response['ResponseMetadata']['HTTPStatusCode'] == 200:
                attachment_paths.append(S3_BUCKET_PATH + "notice/" + filename)
            else:
                return abort(400, description='Failed to upload recruitment to s3.')
        _form['attachment_paths'] = attachment_paths
        _form['date'] = datetime.datetime.now()

        db_response = db.notices.insert_one(_form)

        if db_response.inserted_id:
            return jsonify({'message': 'Created notice successfully.'}), 201
        else:
            return abort(400, description='Failed to create notice.')
    except Exception as e:
        print(str(e))


@app.route('/api/search', methods=['GET'])
@jwt_required
def get_search_result():
    keyword = request.args.get('keyword')
    companys = get_all_document(db.company.find({'$text': {'$search': keyword}}))
    recruitments = get_all_document(db.recruitments.find({'$text': {'$search': keyword}}))

    return jsonify({'companys': companys, 'recruitments': recruitments}), 200


@app.route('/api/user', methods=['PATCH'])
@jwt_required
def user():
    for name, file in request.files.items():
        filename = secure_filename(name)

        s3_response = s3.put_object(Body=file, Bucket="recruitdsm", Key="resume/" + filename,
                                    ContentType=request.mimetype)

        if s3_response['ResponseMetadata']['HTTPStatusCode'] == 200:
            resume_path = S3_BUCKET_PATH + "resume/" + filename
            db.users.update_one({'email': get_jwt_identity()['email']},
                                {'$set': {'resume_path': resume_path}})
        else:
            return abort(400, description='Failed to upload file to s3.')
    user = db.users.find_one({'email': get_jwt_identity()['email']})
    if 'resume_path' in user:
        return jsonify({'result': user['resume_path']}), 200
    else:
        return abort(400, description='Failed to get user resume path.')


@app.route('/api/signin', methods=['POST'])
def sign_in():
    _json = request.get_json(silent=True)
    if _json:
        user = db.users.find_one({'email': _json['email']}, {'_id': 0})
        if user and flask_bcrypt.check_password_hash(user['password'], _json['password']):
            del user['password']
            access_token = create_access_token(identity=_json)
            refresh_token = create_refresh_token(identity=_json)
            user['token'] = access_token
            user['refresh'] = refresh_token
            return jsonify({'result': user}), 200
        else:
            return jsonify({'message': 'Invalid username or password'}), 401
    else:
        return abort(400, description='Bad request params.')


@app.route('/api/signup', methods=['POST'])
def sign_up():
    _json = request.get_json(silent=True)
    if _json['email'].split('@')[-1] == 'dsm.hs.kr':
        if not db.users.find_one({'email': _json['email']}):
            _json['password'] = flask_bcrypt.generate_password_hash(_json['password'])
            _json['membership'] = 0
            db_response = db.users.insert_one(dict(_json))
            if db_response.inserted_id:
                return jsonify({'message': 'Created user successfully.'}), 201
            else:
                return abort(400, description='Failed to create user.')
        else:
            return abort(400, description='Failed to create recruitment.')
    return abort(400, description='Bad request params.')


@app.route('/api/apply')
@jwt_required
def send_apply_mail():
    company_name = request.args.get('recruitment')

    user = db.users.find_one({'email': get_jwt_identity()['email']})


    try:
        if 'resume_path' in user:
            student = user['grade'] + user['class'] + str(int(user['number']) + 100)[-2:] + user['name']

            send_mail(student, company_name, user['resume_path'])
            return jsonify({'message': 'Sent mail successfully.'}), 200
        else:
            return abort(400, description='Bad request params.')
    except Exception as e:
        print(str(e))
        abort(400, description='Failed to send mail.')


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
