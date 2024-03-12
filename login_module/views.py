from django.contrib.auth.models import User
from rest_framework import status
from .serializers import *
from rest_framework_simplejwt.views import TokenObtainPairView
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from django.http import JsonResponse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view

# Signup
@api_view(['POST'])
def signup(request):
    new_rec = UserSerializer(data=request.data)
    if new_rec.is_valid():
        new_rec.save()
        user_rec = User.objects.get(email=request.data.get('email'))
        serialized_user = UserSerializer(user_rec, context={'request': request})
        return Response(serialized_user.data, status=status.HTTP_201_CREATED)
    return Response(new_rec.errors, status=status.HTTP_400_BAD_REQUEST)

# Logging User In    
class UserLoginView(TokenObtainPairView):
    serializer_class = UserLoginSerializer

# Forget Password Api
@csrf_exempt
@api_view(['POST'])
def request_reset_email(request):
    data = JSONParser().parse(request)
    serializers = SendPasswordResetEmailSerializer(data=data)
    if serializers.is_valid(raise_exception=True):
        msg = "Password Reset link send. Please check your email."
        response = {'status': 'success','code': status.HTTP_200_OK,'message': msg}
        return JsonResponse(response, status=201)
    return JsonResponse(serializers.errors, status=400)

# Reset Password
@csrf_exempt
@api_view(['POST'])
def resetPassword(request, uid, token):
    data = JSONParser().parse(request)
    serializers = UserPasswordResetSerializer(data = data, context = {'uid':uid, 'token': token})
    if serializers.is_valid(raise_exception=True):
        msg = "Password Reset successfully"
        response = {'status': 'success','code': status.HTTP_200_OK,'message': msg}
        return JsonResponse(response, status=201)
    return JsonResponse(serializers.errors, status=400)