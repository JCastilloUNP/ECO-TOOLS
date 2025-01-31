import json
from datetime import datetime
from functools import wraps
from typing import Optional

from jwcrypto import jwt
from rest_framework import status
from rest_framework.response import Response

CRIP_KEY_PRIVATE = None

def endpoint_protegido(roles:Optional[list] = None):
    def decorator(fun):
        @wraps(fun)
        def _wrapped_fun(self, request, *args, **kwargs):
            if roles is None:
                roles_list = ["ECO.ADMIN"]
            else:
                roles_list = roles
            e_token = request.META.get('HTTP_AUTHORIZATION')
            if e_token:
                payload = desencriptar(CRIP_KEY_PRIVATE, e_token.replace("Bearer ", ""))
                if payload is None:
                    return Response({'mensaje': 'token incorrecto'},
                                    status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'mensaje': 'no proporcionó un token'},
                                status=status.HTTP_401_UNAUTHORIZED)

            if datetime.strptime(payload.get('refresco'), "%m/%d/%Y %H:%M:%S") < datetime.now():
                return Response({'mensaje': 'token expirado, loguéese de nuevo'},
                         status=status.HTTP_401_UNAUTHORIZED)

            if datetime.strptime(payload.get('vencimiento'), "%m/%d/%Y %H:%M:%S") < datetime.now():
                return Response({'mensaje': 'refresque el token e intente nuevamente'},
                         status=status.HTTP_403_FORBIDDEN)
            roles_permitidos_set = set(roles_list)
            roles_token_set = set(payload.get('roles'))
            for rol in roles_token_set:
                if rol in roles_permitidos_set:
                    return fun(self, request, *args, **kwargs)
            return Response({'mensaje': 'no tiene el rol necesario para acceder a este recurso'},
                            status=status.HTTP_401_UNAUTHORIZED)
        return _wrapped_fun
    return decorator


def encriptar(pub_key, payload):
    # Se encripta el token con la key PÚBLICA
    e_token = jwt.JWT(header={"alg": "RSA-OAEP-256", "enc": "A256CBC-HS512"},
                      claims=payload)
    e_token.make_encrypted_token(pub_key)
    # Token que va en headers como Authorization: Bearer {e_token_str}
    return e_token.serialize()

def desencriptar(priv_key, e_token):
    try:
        # Se desencripta el token con la key PRIVADA
        e_token_des = jwt.JWT(key=priv_key, jwt=e_token, expected_type="JWE")
        # Se imprime el payload
        return json.loads(e_token_des.claims)
    except ValueError:
        return None


