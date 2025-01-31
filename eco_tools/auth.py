from rest_framework import authentication
from rest_framework import exceptions
from datetime import datetime
from django.db import models
import inspect
import eco_tools.tools
import importlib
from django.conf import settings


class EcoAuthentication(authentication.BaseAuthentication):
    """Clase de autenticación para el sistema deecosistema, por defecto retorna request.user el username del token (str)
    si desea personalizar la autenticación debera proporcionar una tabla, modelo con un campo llamado username. Adicionalmente
    se recomienda revisar la informacion de la función get_model"""

    model = None
    def authenticate(self, request):
        e_token = request.headers.get('Authorization')
        if not e_token:
            raise exceptions.AuthenticationFailed('no proporcionó un token')
        token = eco_tools.tools.desencriptar(e_token = e_token, priv_key = eco_tools.tools.CRIP_KEY_PRIVATE)
        if datetime.strptime(token.get('refresco'), "%m/%d/%Y %H:%M:%S") < datetime.now():
            raise exceptions.NotAuthenticated('token expirado, loguéese de nuevo')
        if datetime.strptime(token.get('vencimiento'), "%m/%d/%Y %H:%M:%S") < datetime.now():
            raise exceptions.PermissionDenied('refresque el token e intente nuevamente')
        return self.authenticate_credentials(token)
    
    def get_model(self) -> models.Model:
        """Obtiene el modelo que desee utilizar para verificar sus usuarios, 
        en el caso de que se instancie mal el nombre del modelo, se seguira pasando el string con el username
        de backend de login. Se debe instancia en el settings el path de la ruta y el nombre del modelo:
        APP_USERS = 'app.models'
        USER_MODEL = 'Modelo
        '"""
        try: path_model = settings.APP_USERS
        except AttributeError: return None
        try: model_name =  settings.USER_MODEL
        except AttributeError: raise AttributeError('No se ha definido el modelo de usuario')
        modules = inspect.getmembers(importlib.import_module(path_model) , inspect.isclass)
        modules_dict = dict((nombre, clase) for nombre, clase in modules)
        self.model = modules_dict.get(model_name, None)        
        if self.model is not None:
            return self.model
        else:
            return None
    
    def authenticate_credentials(self, token):
        """Funcion que retorna el usuario"""
        model = self.get_model()
        if model is not None:
            try:
                user:self.model = model.objects.get(username=token['username'])
                return (user, None)
            except model.DoesNotExist:
                raise exceptions.AuthenticationFailed('No se encontró Usuario')
        else:
            return (token['username'], None)