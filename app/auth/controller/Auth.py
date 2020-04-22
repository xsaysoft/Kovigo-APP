#
#@KEVIN Authentication module for registartion , login, validation , splashscreen, token Resend 
#
from flask import request
from flask_restful import Resource
from app.auth.util.__code import *
from app.auth.model.Auth_DB import db, User, UserSchema ,UserAllSchema, UserAuth, UserAuthSchema, UserLog, UserLogSchema, AuthCode,AuthCodeSchema,UnLinkLog,ActivitiesLog
from app.auth.service.resource import random_gentarted,save_changes ,verify_expire_code,sms_token
from app.auth.util.token import token_required,SECRET_KEY,auth,hash_password ,verify_password as veri_pass
import jwt,json,secrets,datetime
from marshmallow import ValidationError, post_load
from sqlalchemy import or_, and_



users_schema = UserAllSchema(many=True)
user_schema = UserSchema()
authcode_schema =  AuthCodeSchema()
userlog_schema =UserLogSchema()
user_all_schema = UserAllSchema()





#
#password verify @param {phone & passowrd}
#
@auth.verify_password
def verify_password(phone, password):
    user = User.query.filter_by(phone = phone).first()
    if not user or not veri_pass(user.password,password):
       return False
    user = user
    return True


@auth.error_handler
def auth_error():
     return  {'status': "error","data": {"code":INVALID_LOGIN,"message": "Invalid Login details"}}, 200

#
#Registartion @param {phone,@device_id }
#

class RegResource(Resource):
    #@token_required # securing the api route with generated token 
    def get(self):
        users = User.query.all()
        users = users_schema.dump(users)
        return {'status': 'success', 'data': users}, 200
       

    def post(self):
        verify_code = verify_expire_code["code"]= random_gentarted(4) 
        json_data = request.get_json(force=True)
        if not json_data:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
        try:
            data = authcode_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200

      
        user = User.query.filter(and_(User.phone==data['phone'],User.device_id==data['device_id'],User.status == 0)).first()
        if  user:
            return  {'status': "error","data": {"code":UNCOMPELETED_REG,"message":'Uncompleted registration',"level":user.level}}, 200
        
        phone = User.query.filter(and_(User.phone==data['phone'],User.device_id!=data['device_id']),User.status == 0).first()
        if  phone:
            user = UnLinkLog(phone=data['phone'],device_id=phone.device_id,user_id=phone.id)
            save=save_changes(user)
            phone.device_id=data['device_id']
            db.session.commit()
           
            if save:
               return  {'status': "error","data": {"code":USERFOUND,"message":'User already exists (take to login) ','phone':user.phone,"level":phone.level,}}, 200
            print ('Activated phone number found (take to unlink phone)')
            

        device = User.query.filter(and_(User.phone!=data['phone'],User.device_id==data['device_id']),User.status == 0).first()
        if  device:
            user = UnLinkLog(phone=data['phone'],device_id=device.device_id,user_id=device.id)
            save=save_changes(user)
            device.device_id="null"
            db.session.commit()
            
            if save:
                auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.auth_status == 0)).first()
                if not auth_user:
                    user = AuthCode(phone=data['phone'],device_id=data['device_id'],activation=verify_code,auth_status=0)
                    save_changes(user)
                    #remove verify_code on production
                    code_msg= "Your Verification code is  :" + str(verify_code)
                    sms_token(str(data['phone']),code_msg)
                    return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code}}, 200
                else:
                    auth_user.activation=verify_code
                    db.session.commit()
                    #remove verify_code on production
                    code_msg= "Your Verification code is  :" + str(verify_code)
                    sms_token(str(data['phone']),code_msg)
                    return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code}}, 200
            print ('Activated Device ID found (take to unlink phone)')
            
            
        phone = User.query.filter(and_(User.phone==data['phone'],User.status == 0)).first()
        if  phone:
            return  {'status': "error","data": {"code":UNCOMPELETED_REG,"message":'Uncompleted registration',"level":phone.level}}, 200

        device = User.query.filter(and_(User.device_id==data['device_id'],User.status == 0)).first()
        if  device:
            return  {'status': "error","data": {"code":UNCOMPELETED_REG,"message":'Uncompleted registration',"level":device.level}}, 200 
        #
        user = User.query.filter_by(phone=data['phone'],device_id=data['device_id'],status = 1).first()
        if  user:
            return  {'status': "error","data": {"code":USERFOUND,"message":'User already exists (take to login) ','phone':user.phone}}, 200
        
        user = User.query.filter(and_(User.phone==data['phone'],User.status == 1)).first()
        if  user:
            user = UnLinkLog(phone=data['phone'],device_id=user.device_id,user_id=user.id)
            save=save_changes(user)
            user.device_id=data['device_id']
            db.session.commit()
            
            if save:
               return  {'status': "error","data": {"code":USERFOUND,"message":'User already exists (take to login) ','phone':user.phone}}, 200
            print ('Activated phone number found (take to unlink phone)')

        user = User.query.filter(and_(User.device_id==data['device_id'],User.status == 1)).first()
        if  user:
            user = UnLinkLog(phone=data['phone'],device_id=user.device_id,user_id=user.id)
            save=save_changes(user)
            user.device_id="null"
            db.session.commit()
            
            if save:
                auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.auth_status == 0)).first()
                if not auth_user:
                    user = AuthCode(phone=data['phone'],device_id=data['device_id'],activation=verify_code,auth_status=0)
                    save_changes(user)
                    #remove verify_code on production
                    code_msg= "Your Verification code is  :" + str(verify_code)
                    sms_token(str(data['phone']),code_msg)
                    return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code}}, 200
                else:
                    auth_user.activation=verify_code
                    auth_user =data
                    db.session.commit()
                    #remove verify_code on production
                    code_msg= "Your Verification code is  :" + str(verify_code)
                    sms_token(str(data['phone']),code_msg)
                    return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code}}, 200
            print ('Activated Device ID found (take to unlink phone)')

        phone = User.query.filter(and_(User.phone==data['phone'],User.status == 5)).first()
        if  phone:
            return  {'status': "error","data": {"code":USER_BLOCK,"message":'Phone number has been blocked'}}, 200
        device = User.query.filter(and_(User.device_id==data['device_id'],User.status == 5)).first()
        if  device:
            return  {'status': "error","data": {"code":USER_BLOCK,"message":'Device id has been blocked'}}, 200  
     
        user = User.query.filter(or_(User.phone==data['phone'],User.device_id==data['device_id']), and_(User.status == 0)).first()
        if not user:
            auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.auth_status == 0)).first()
            if not auth_user:
                user = AuthCode(phone=data['phone'],device_id=data['device_id'],activation=verify_code,auth_status=0)
                save_changes(user)
                #remove verify_code on production
                code_msg= "Your Verification code is  :" + str(verify_code)
                sms_token(str(data['phone']),code_msg)
                return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code}}, 200
            else:
                auth_user.activation=verify_code
                auth_user =data
                db.session.commit()
                #remove verify_code on production
                code_msg= "Your Verification code is  :" + str(verify_code)
                sms_token(str(data['phone']),code_msg)
                return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code}}, 200
            

        
    #
    #Resend verification code @param {phone,@device_id,activation_code}
    #
    def put(self):
        verify_code = verify_expire_code["code"]= random_gentarted(4) 
        json_data = request.get_json(force=True)
        if not json_data:
               return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
        try:
            data = authcode_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 

        auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.auth_status == 0)).first()
        if not auth_user:
            return  {'status': "error","data": {"code":INVALID_CODE_RESEND_DETAILS , "message":'User details does not exist for code resend' }}, 200

        auth_user.activation=verify_code
        auth_user =data
        db.session.commit()
        #remove verify_code on production
        code_msg= "Your Verification code is  :" + str(verify_code)
        sms_token(str(data['phone']),code_msg)
        return  {'status': "success","data": {"code":SUCCESSFUL,"message":'successful',"verify_code": verify_code}}, 200
     
    #
    #Delete Data Remove on production 
    #
    def delete(self):
        json_data = request.get_json(force=True)
        if not json_data:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
        try:
            data = user_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200  

        user= User.query.filter_by(phone=data['phone']).delete()
    
        if not user:
            return  {'status': "error","data": {"code":USER_NOT_FOUND, "message":'User does not exist' }}, 200
        db.session.commit()
        return  {'status': "success","data": {"code":SUCCESSFUL,"message":'User data has been deleted'}}, 200
       


#
#Validation  @param  {@phone,@device_id,@activation_code}
#
class ValidateResource(Resource):

    def put(self):
        json_data = request.get_json(force=True)
        print(json_data)
        if not json_data:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
       
        try:
            data = authcode_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 

    
        if not 'activation_code' in request.json:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (activation_code) field."}}, 200 

        user = AuthCode.query.filter_by(phone=data['phone'],device_id=data['device_id'],activation=data['activation_code'],auth_status = 0).first()
        if not user:
            return  {'status': "error","data": {"code":INVALID_CODE,"message": "activation code does not match."}}, 200 
            
        validCode= verify_expire_code.get('code')
        if not validCode:
            return  {'status': "error","data": {"code":EXPIRED_CODE,"message": "activation code has expired."}}, 200
        else:
            user=User(phone=data['phone'],device_id=data['device_id'],activation=1,level=PHONE_LEVEL,status=0)
            save_changes(user)
            if user:
               auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.activation == data['activation_code'])).first() 
               auth_user.auth_status=1
               db.session.commit()
               return  {'status': "success","data": {"code":SUCCESSFUL,"message":'activation successful'}}, 200

        return  {'status': "error","data": {"code":ACTIVATION_FAILED ,"message":'activation  was not successful'}}, 200
       

#
#Password Check @phone,@device_id 
#
class PasswordSetResource(Resource):
    
    def put(self):
        json_data = request.get_json(force=True)
        if not json_data:
               return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided." }}, 200
        try:
            data = user_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200  

        if not 'password' in request.json:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (password field.)"}}, 200

        if not 'recovery_phone' in request.json :
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (recovery_phone.)"}}, 200
        
        user = User.query.filter_by(phone=data['phone'],device_id=data['device_id'],status = 1).first()
        if  user:
            return  {'status': "error","data": {"code":PASSWORD_NOT_FOUND,"message": "User already set a password  (take to login )."}}, 200

        user = User.query.filter_by(phone=data['phone'],device_id=data['device_id']).first()
        if not user:
            return  {'status': "error","data": {"code":PASSWORD_NOT_SET ,"message": "Unable to set password  (details does not match) ."}}, 200 
        
        user.password =hash_password(data['password'])
        user.recovery_phone=data['recovery_phone']
        user.status = 1
        user.level =PASSWORD_LEVEL
        db.session.commit()
        
        token=jwt.encode({'phone': user.phone,'password': user.password,'full_name': user.full_name, 'device_id': user.device_id,'exp' : datetime.datetime.utcnow()+ datetime.timedelta(minutes=525600)},SECRET_KEY,algorithm='HS256')
        return { "status": 'success', "data": {'code':PASSWORD_SUCCESSFUL,'message': 'password set was successful','token':token.decode('UTF-8')}}, 200


    #
    #Password Reset code @param {phone,@device_id}
    #
    def get(self):
        verify_code = verify_expire_code["code"]= random_gentarted(4)
        # json_data = request.get_json(force=True)
        getPhone=request.args['phone']
        getDevice_id=request.args['device_id']
        if not getPhone:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200

        if not getDevice_id:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200


        users = User.query.filter_by(phone=getPhone,device_id=getDevice_id).first()
        if not users:
            return  {'status': "error","data": {"code":INVALID_CODE_RESEND_DETAILS , "message":'User details does not exist' }}, 200 


        auth_user = AuthCode.query.filter(and_(AuthCode.phone==getPhone,AuthCode.auth_status == 0)).first()
        if not auth_user:
            user = AuthCode(phone=getPhone,device_id=getDevice_id,activation=verify_code,auth_status=0)
            save_changes(user)
            user = ActivitiesLog(phone=getPhone,device_id=getDevice_id,user_id=users.id,activities="Start Password Change ")
            save=save_changes(user)
            #remove verify_code on production and send code to recovery number 
            code_msg= "Your password reset code is  :" + str(verify_code)
            sms_token(str(data['phone']),code_msg)
            return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code,"message":"successful"}}, 200
        else:
            auth_user.activation=verify_code
            db.session.commit()
            user = ActivitiesLog(phone=getPhone,device_id=getDevice_id,user_id=users.id,activities="Start Password Change ")
            save=save_changes(user)
            #remove verify_code on production and send code to recovery number
            code_msg= "Your Password Reset Code is  :" + str(verify_code)
            sms_token(str(getPhone),code_msg)
            return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code,"message":"successful"}}, 200

    #
    #Password Reset verification @param {phone,@device_id,code, password }
    #
    def post(self):
        json_data = request.get_json(force=True)
        if not json_data:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
       
        try:
            data = user_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 

    
        if not 'activation_code' in request.json:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (activation_code) field."}}, 200 

        user = AuthCode.query.filter_by(phone=data['phone'],device_id=data['device_id'],activation=data['activation_code'],auth_status = 0).first()
        if not user:
            return  {'status': "error","data": {"code":INVALID_CODE,"message": "activation code does not match."}}, 200 
            
        validCode= verify_expire_code.get('code')
        if not validCode:
            return  {'status': "error","data": {"code":EXPIRED_CODE,"message": "activation code has expired."}}, 200
        else:
            user = User.query.filter_by(phone=data['phone']).first()
            user.password =hash_password(data['password'])
            user.device_id=data['device_id']
            db.session.commit()
            if user:
               auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.activation == data['activation_code'])).first() 
               auth_user.auth_status=1
               db.session.commit()
               return { "status": 'success', "data": {'code':PASSWORD_SUCCESSFUL,'message': 'password reset was successful'}}, 200

        return  {'status': "error","data": {"code":PASSWORD_NOT_SET ,"message":'password reset  was not successful'}}, 200




#
#SplachSscreen  @param{@phone,@device_id ,@TOKEN}
#

class SplashSetResource(Resource):
   
    def post(self):
       
        json_data = request.get_json(force=True)
        if not json_data:
               return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided." }}, 200
   
        data = json_data
        if not 'device_id' in request.json:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (device_id) field."}}, 200 

        user = User.query.filter_by(device_id=data['device_id'], status=5).first()
        if  user:
            return  {'status': "error","data": {"code":USER_BLOCK,"message":'Device id has been blocked'}}, 200 
            
        
        user = User.query.filter_by(device_id=data['device_id']).first()
        if not  user:
             return  {'status': "success","data": {"code":DEVICE_NOT_FOUND,"message": "Device id does not match (take to Registration )."}}, 200

        if 'appmart-token' not in request.headers:
            return  {'status': "error","data": {"code":DEVICE_FOUND,"message":'Device id matches a record',"level":user.level}}, 200

        if 'appmart-token' in request.headers:
            token =request.headers['appmart-token']

        if not  token:
            return  {'status': "error","data": {"code":MISSING_TOKEN,"message": "Token is missing."}}, 200
           
        try:
            current_data=jwt.decode(token,SECRET_KEY,algorithm='HS256')

        except jwt.ExpiredSignatureError:

               return  {'status': "error","data": {"code":TOKEN_EXPIRED ,"message": "Token expired. Get new one.",'phone':user.phone}}, 200
        except jwt.InvalidSignatureError:
               
                #cause for accout lock
               user.status=5
               db.session.commit() 
               return  {'status': "error","data": {"code":INVALID_SIGNATURE,"message": "Token’s signature doesn’t match . "}}, 200
        except jwt.DecodeError:
                #cause for accout lock
                user.status=5
                db.session.commit() 
                return  {'status': "error","data": {"code":DECODED_ERROR,"message": "token cannot be decoded because it failed validation. Fake Token "}}, 200 
      
        if current_data['device_id'] != data['device_id']:
            #block account details
            user.status=5
            db.session.commit()
            return  {'status': "error","data": {"code":FAKE_TOKEN,"message": "Fake Token Generated  ."}}, 200

        user = User.query.filter_by(phone=current_data['phone'],device_id=current_data['device_id'],password=current_data['password']).first()
        if user:
            token=jwt.encode({'phone': user.phone,'password': user.password,'full_name': user.full_name, 'device_id': user.device_id,'exp' : datetime.datetime.utcnow()+ datetime.timedelta(seconds=1)},SECRET_KEY,algorithm='HS256')
            return  {'status': "success","data": {"code":LOGIN_SUCCESSFUL,"message": "Login successful",'token':token.decode('UTF-8')}}, 200

        
        

#
#Login @param {@phone , @device_id, @lat, @log }
#
class LoginSetResource(Resource):
    @auth.login_required
    def post(self):
        json_data = request.get_json(force=True)
        if not json_data:
               return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided." }}, 200
   
        try:
            data = user_all_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 

        user = User.query.filter_by(phone=data['phone'],device_id=data['device_id']).first()
        if user:
            token=jwt.encode({'phone': user.phone,'password': user.password,'full_name': user.full_name, 'device_id': user.device_id,'exp' : datetime.datetime.utcnow()+ datetime.timedelta(minutes=525600)},SECRET_KEY,algorithm='HS256')
          
            userlog = UserLog.query.filter_by(user_id=user.id).first()
            if not userlog:
               user = UserLog(token=token.decode('UTF-8'),user_id=user.id,log_status=1)
               save_changes(user)
            else:
                if not 'lat' in json_data and not 'log' in json_data:
                    userlog.token =token.decode('UTF-8')
                    userlog.log_status=1
                    db.session.commit()
                else:
                    userlog.lat=data['lat']
                    userlog.log=data['log']
                    userlog.token =token.decode('UTF-8')
                    userlog.log_status=1
                    db.session.commit()
            
            return  {'status': "success","data": {"code":LOGIN_SUCCESSFUL,"message": "Login successful","level": user.level,"token":token.decode('UTF-8')}}, 200

        return  {'status': "error","data": {"code":INVALID_LOGIN ,"message": "Invalid Login details"}}, 200

#
# Auth UserUpdate{ @phone,@device_id,@data @token } 
#
class ProfileUpdateSetResource(Resource):
    @token_required
    def put(self):
        json_data = request.get_json(force=True)
        if not json_data:
               return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided." }}, 200  
        data = user_all_schema.load(json_data)
        if not 'username' in request.json:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (username field.)"}}, 200

        
        user = User.query.filter_by(phone=self['phone'],device_id=self['device_id'],status = 1).first()
        if  user: 
            user.username =data['username']
            user.level = DASHBOARD_LEVEL
            user=data
            db.session.commit()
            return { "status": 'success', "data": {'code':SUCCESSFUL,'message': 'Action was successful'}}, 200
        else:
            pass 
            return { "status": 'error', "data": {'code':FAILED ,'message': 'Action was not successful'}}, 200 


#
# Biometric { @phone,@device_id,@data} 
#
class BiometricSetResource(Resource):
    def put(self):
        json_data = request.get_json(force=True)
        if not json_data:
               return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided." }}, 200
        try:
            data = user_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 
        
        if not 'biometric_id' in request.json:
                return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (biometric_id) field."}}, 200
        user = User.query.filter_by(phone=data['phone'],device_id=data['device_id']).first()
        if  user: 
            user.level=BIOMETRIC_LEVEL
            db.session.commit()
            userauth=UserAuth(user_id=user.id,biometric_status=1,biometric_id=data["biometric_id"])
            save_changes(userauth)
            return { "status": 'success', "data": {'code':SUCCESSFUL,'message': 'Action was successful'}}, 200
        else:
            pass 
            return { "status": 'error', "data": {'code':FAILED ,'message': 'Action was not successful'}}, 200           


    def post(self):
            json_data = request.get_json(force=True)
            if not json_data:
                return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided." }}, 200
            try:
                data = user_schema.load(json_data)
            except ValidationError as err:
                return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200  

            if not 'photo' in request.json:
                return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (photo) field."}}, 200 
            user = User.query.filter_by(phone=data['phone'],device_id=data['device_id']).first()
            if  user: 
                user.photo=data["photo"]
                db.session.commit()
                return { "status": 'success', "data": {'code':SUCCESSFUL,'message': 'Biometric photo was successful'}}, 200
            else:
                pass 
                return { "status": 'error', "data": {'code':FAILED ,'message': 'Biometric photo was not successful'}}, 200 
#
# Recovery Acount { @recovery_phone,@device_id} 
#
class RecoverySetResource(Resource):
    def put(self):
        verify_code = verify_expire_code["code"]= random_gentarted(4)
        json_data = request.get_json(force=True)
        if not json_data:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
       
        try:
            data = user_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 


        user = User.query.filter_by(phone=data['phone']).first()
        if not user:
            return  {'status': "error","data": {"code":INVALID_CODE_RESEND_DETAILS , "message":'User details does not exist' }}, 200 


        auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.auth_status == 0)).first()
        if not auth_user:
            userAuth = AuthCode(phone=data['phone'],device_id=data['device_id'],activation=verify_code,auth_status=0)
            save_changes(userAuth)
            #remove verify_code on production and send code to recovery number 
            code_msg= "Your Recovery code is  :" + str(verify_code)
            sms_token(str(data['phone']),code_msg)
            return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code,"recovery_phone":user.recovery_phone}}, 200
        else:
            auth_user.activation=verify_code
            db.session.commit()
            #remove verify_code on production and send code to recovery number
            code_msg= "Your Recovery code is  :" + str(verify_code)
            sms_token(str(data['phone']),code_msg)
            return  {'status': "success","data": {"code":SUCCESSFUL,"verify_code": verify_code,"recovery_phone":user.recovery_phone}}, 200


#
# Recovery Validate { @bio_phone,new_phone,@device_id} 
#
class RecoveryValidateSetResource(Resource):
    def put(self):
        json_data = request.get_json(force=True)
        if not json_data:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "No input data provided"}}, 200
       
        try:
            data = authcode_schema.load(json_data)
        except ValidationError as err:
            return  {'status': "error","data": {"code":NO_INPUT,"message": err.messages }}, 200 

    
        if not 'activation_code' in request.json:
            return  {'status': "error","data": {"code":NO_INPUT,"message": "Missing (activation_code) field."}}, 200 

        user = AuthCode.query.filter_by(phone=data['phone'],device_id=data['device_id'],activation=data['activation_code'],auth_status = 0).first()
        if not user:
            return  {'status': "error","data": {"code":INVALID_CODE,"message": "activation code does not match."}}, 200 
            
        validCode= verify_expire_code.get('code')
        if not validCode:
            return  {'status': "error","data": {"code":EXPIRED_CODE,"message": "activation code has expired."}}, 200
        else:
            user = User.query.filter_by(phone=data['phone']).first()
            user.phone=data['new_phone']
            user.device_id=data['device_id']
            db.session.commit()
            if user:
               auth_user = AuthCode.query.filter(and_(AuthCode.phone==data['phone'],AuthCode.device_id==data['device_id'],AuthCode.activation == data['activation_code'])).first() 
               auth_user.auth_status=1
               db.session.commit()
               return  {'status': "success","data": {"code":SUCCESSFUL,"message":'activation successful(take to login)'}}, 200

        return  {'status': "error","data": {"code":ACTIVATION_FAILED ,"message":'activation  was not successful'}}, 200



