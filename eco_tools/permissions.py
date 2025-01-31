from rest_framework import permissions
from eco_tools.tools import desencriptar, CRIP_KEY_PRIVATE
from typing import Optional
from rest_framework.response import Response

class HasRequiredRoles(permissions.BasePermission):
    message = {'mensaje': ['No tiene permisos para realizar esta acción']}
    def has_permission(self, request, view):
        # Verificar si el usuario tiene un rol específico
        required_roles:Optional[list] = getattr(view, 'required_roles', None)
        roles_permitidos = ["ECO.ADMIN"]
        if required_roles is not None:
            roles_permitidos = roles_permitidos + required_roles
        e_token = request.META.get('HTTP_AUTHORIZATION') #o e_token = request.headers.get('Authorization')
        if e_token:
            payload = desencriptar(CRIP_KEY_PRIVATE, e_token.replace("Bearer ", ""))
        else:
            return False
        roles_permitidos_set = set(roles_permitidos)
        roles_token_set = set(payload.get('roles'))
        for rol in roles_token_set:
            if rol in roles_permitidos_set:
                return bool(request.user and True)
        return False