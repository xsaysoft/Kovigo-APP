from flask import Flask,Blueprint
from flask_restful import reqparse, abort, Api, Resource
from app.auth.controller.Auth import RegResource,ValidateResource,PasswordSetResource,LoginSetResource,SplashSetResource,ProfileUpdateSetResource,BiometricSetResource,RecoverySetResource,RecoveryValidateSetResource
app_service = Blueprint('api', __name__)
api = Api(app_service)

##
## Actually setup the Api resource routing here
##
api.add_resource(SplashSetResource, '/v1/splashscreen')
api.add_resource(RegResource, '/v1/registration')
api.add_resource(ValidateResource, '/v1/validate')
api.add_resource(BiometricSetResource, '/v1/biometric')
api.add_resource(PasswordSetResource, '/v1/password_set')
api.add_resource(LoginSetResource, '/v1/login')
api.add_resource(ProfileUpdateSetResource, '/v1/profile_update')
api.add_resource(RecoverySetResource, '/v1/account_recovery')
api.add_resource(RecoveryValidateSetResource, '/v1/account_recovery_verify') 