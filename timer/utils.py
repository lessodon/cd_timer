import uuid
from hashlib import sha256

from .consts import *
from .models import Session

class SessionInterface():
    session = None
    
    def new(self, user, request):
        suid = str(uuid.uuid1())
        self.session = Session()
        self.session.user = user
        self.session.uuid = suid
        self.session.save()
        request.session['uuid'] = suid
    
    def get(self, request):
        try:
            s = Session.objects.get(uuid=request.session['uuid'])
        except:
            return False
        else:
            self.session = s
        return self.session
    
    def delete(self, request):
        self.session.delete()
        request.session['uuid'] = ''

    
def valid_alnum(input, digits=True):
    for c in input.lower():
        if c < 'a' and c != '_':
            if digits == True and (c < '0' or c > '9'):
                raise ValueError
        elif c > 'z':
            raise ValueError

def valid(username, password):
    if username is not None:
        if type(username) != str:
            raise TypeError('username type')
        elif len(username) < USERNAME_LEN_MIN or (len(username) > USERNAME_LEN_MAX and USERNAME_LEN_MAX > 0):
            raise ValueError('username length')
        try:
            valid_alnum(username)
        except:
            raise ValueError('username invalid')

    if password is not None:
        if type(password) != str:
            raise TypeError('password type')
        elif len(password) < PASSWORD_LEN_MIN or (len(password) > PASSWORD_LEN_MAX and PASSWORD_LEN_MAX > 0):
            raise ValueError('password length')
    

GET_PASSWORD_FAIL = 'GET_PASSWORD_FAIL'
def get_password(request):
    foo = 'timer.utils.get_password(): '
    try:
        password = request.POST['password']
        valid(None, password)
    except (AttributeError, TypeError, KeyError):
        print(foo + 'invalid argument!')
        return GET_PASSWORD_FAIL
    except ValueError:
        print(foo + 'password must have at least 8 characters')
        return GET_PASSWORD_FAIL

    hasher = sha256()
    hasher.update(password.encode())
    return hasher.hexdigest()