import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    """Define app configurations"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess'

    # Data configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.dib')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

