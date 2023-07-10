from rest_framework.views import APIView
from rest_framework.response import Response

from rest_framework.authentication import (
    SessionAuthentication, BasicAuthentication,
    TokenAuthentication)

from rest_framework.permissions import IsAuthenticated

from rest_framework import status

from rest_framework_simplejwt.authentication import JWTAuthentication

class IndexView(APIView):
    authentication_classes = [JWTAuthentication,TokenAuthentication,SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self,request):
        context= {
            'mensaje':'acceso autorizado'
        }
        return Response(context)
    
from django.contrib.auth import authenticate 
from rest_framework.authtoken.models import Token
    
class LoginView(APIView):
    
    def post(self,request):
        username = request.data.get("username")
        password = request.data.get("password")
        
        user = authenticate(username=username,password=password)
        
        if user:
            Token.objects.get_or_create(user=user)
            return Response({
                'token':user.auth_token.key
            })
        else:
            return Response({
                'error':'datos no validos'
            },status=status.HTTP_400_BAD_REQUEST)    

from rest_framework_simplejwt.tokens import RefreshToken

class TokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Obtener el token de actualización
        refresh_token = RefreshToken.for_user(request.user)
        # Generar el token de acceso a partir del token de actualización
        access_token = refresh_token.access_token
        return Response({
            'token': str(access_token)
        })
