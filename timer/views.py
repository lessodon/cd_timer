from django.shortcuts import render
from django.template import loader
from django.http import HttpResponse, HttpResponseRedirect
from django.http import HttpResponseNotFound, HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.urls import reverse
from django.utils import timezone

from .models import User, Session, Timer

# App utils
from .utils import *


# Views

######################
# Session management #
######################

def index(request):
    """Manda o cliente para a página de login se a sessão não existir; ou manda ele para a página do usuário (timers)."""
    siface = SessionInterface()
    if siface.get(request) == False:
        return HttpResponseRedirect(reverse('timer:login'))
    else:
        return HttpResponseRedirect(reverse('timer:timers'))


def login(request):
    """Tenta iniciar uma sessão; se o usuário não existir, cria a conta com as credenciais inexistentes e inicia a sessão."""
    tmpl = loader.get_template('timer/login.html')
    if request.method == 'GET':
        return HttpResponse(tmpl.render({ 'error': None }, request))

    else:
        try:
            valid(request.POST['username'], request.POST['password'])
        except (TypeError, ValueError) as error:
            return HttpResponseBadRequest(tmpl.render({ 'error': str(error) }, request))
        except:
            return HttpResponseBadRequest('Que requisição ridícula, mal feita, horrorosa, trabalho seboso, um digno cocozinho...')
        
        req_uname = request.POST['username']
        req_hpass = get_password(request)
        siface = SessionInterface()
        
        try:
            u = User.objects.get(username = req_uname)
        except User.DoesNotExist:
            u = User()
            u.username = req_uname
            u.password = req_hpass
            u.save()
            return login(request)
        else:
            if u.password == req_hpass:
                siface.new(u, request)
                return HttpResponseRedirect(reverse('timer:index'))
        return HttpResponseNotFound(tmpl.render({ 'error': '' }, request))


def logout(request):
    """Encerra a sessão e/ou manda para a página de login"""
    siface = SessionInterface()
    if siface.get(request) != False:
        siface.delete(request)

    return HttpResponseRedirect(reverse('timer:login'))


def timers(request):
    """Página do usuário: lista os timers do usuário se este estiver logado"""
    siface = SessionInterface()
    
    if siface.get(request) == False:
        return HttpResponseRedirect(reverse('timer:login'))
    
    user = siface.session.user
    timers = []
    for timer in user.timer_set.all():
        delta = timezone.now() - timer.t_start
        hours = delta.seconds/3600
        mins = (delta.seconds/60)%60
        secs = delta.seconds%60
        # timestr = '%d:%d:%d' % (mins, secs, milis)
        timers.append({
            'pk': timer.pk,
            'days': delta.days,
            'hours': int(hours),
            'mins': int(mins),
            'secs': int(secs)
       })
    
    context = {
        'user': siface.session.user,
        'timers': timers
    }
    return render(request, 'timer/timers.html', context)


#####################
# Timers management #
#####################

def new_timer(request):
    """Cria um timer e atualiza a página do usuário"""
    siface = SessionInterface()
    
    try:
        if siface.get(request) == False:
            raise Session.DoesNotExist
    except Session.DoesNotExist:
        return HttpResponseRedirect(reverse('timer:login'))
    else:
        timer = Timer(user = siface.session.user)
        timer.t_start = timezone.now()
        timer.save()
    return HttpResponseRedirect(reverse('timer:timers'))


def reset_timer(request, req_pk):
    """Reinicia o timer solicitado"""
    siface = SessionInterface()
    
    try:
        if siface.get(request) == False:
            raise Session.DoesNotExist
    except Session.DoesNotExist:
        return HttpResponseRedirect(reverse('timer:login'))
   
    try:
        timer = Timer.objects.get(pk=req_pk)
        if timer.user != siface.session.user:
            raise Timer.DoesNotExist
        
    except Timer.DoesNotExist:
        return HttpResponseForbidden('O timer não foi encontrado ou é de outro proprietário.')
    else:
        timer.t_start = timezone.now()
        timer.save()
    
    return HttpResponseRedirect(reverse('timer:timers'))


def delete_timer(request, req_pk):
    """Remove o timer solicitado"""
    siface = SessionInterface()
    
    try:
        if siface.get(request) == False:
            raise Session.DoesNotExist
    except Session.DoesNotExist:
        return HttpResponseRedirect(reverse('timer:login'))
    
    try:
        timer = Timer.objects.get(pk=req_pk)
        if timer.user != siface.session.user:
            raise Timer.DoesNotExist
        
    except Timer.DoesNotExist:
        return HttpResponseForbidden('O timer não foi encontrado ou é de outro proprietário.')
    else:
        timer.delete()
    
    return HttpResponseRedirect(reverse('timer:timers'))