import os

# You need to replace the next values with the appropriate values for your configuration

basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_ECHO = True
SQLALCHEMY_TRACK_MODIFICATIONS = True
# Uncomment  if you want to use PostgreSql, 
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'app.db')
#SQLALCHEMY_DATABASE_URI = "postgresql://username:password@localhost/database_name"

#Uncomment  if you want to use multiple databases
# SQLALCHEMY_BINDS = {
#     'db1':        'mysqldb://localhost/users',
#     'db2':      'postgresql://username:password@localhost/database_name'
# }

