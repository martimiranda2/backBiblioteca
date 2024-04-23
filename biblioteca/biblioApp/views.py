import json
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .models import Book, CD, Item, Dispositive, Log, User, Role, UserProfile

@csrf_exempt
def get_token_by_email_and_password(email, password):
    try:
        user = authenticate(username=email, password=password)
        if user is None:
            raise AuthenticationFailed('Invalid DNI or password')

        refresh = RefreshToken.for_user(user)

        token_data = {
            'id': user.id,
            'email': user.username,
        }

        token_data['refresh'] = str(refresh)
        token_data['access'] = str(refresh.access_token)

        return token_data
    except Exception as error:
        print('auth.service | get_token_by_dni_and_password -> error:', error)

@csrf_exempt
def new_login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('username')
        password = data.get('password')

        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            token = get_token_by_email_and_password(email, password)
            return JsonResponse({'message': 'User Authenticated successfully', 'token': token})
        else:
            return JsonResponse({'message': 'Incorrect credentials'}, status=401)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

def register(password, name, surname, surname2, role_id, date_of_birth, center, cycle, dni, email, image=None):
    try:
        role = Role.objects.get(id=role_id)

        user_profile = User.objects.create(
            name=name,
            surname=surname,
            surname2=surname2,
            role=role,
            date_of_birth=date_of_birth,
            center=center,
            cycle=cycle,
            image=image,
            dni=dni,
            email=email
        )

        return user_profile
    except Exception as error:
        print('auth.service | register -> error:', error)



def get_user_by_id(user_id):
    user = get_object_or_404(User, id=user_id)
    return user

def get_user_profile_by_email(email):
    user_profile = get_object_or_404(UserProfile, email=email)
    return user_profile

# Funcion logs
# Level 1:INFO, 2:SUCCESS , 3:WARNING, 4:ERROR


def InfoLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level=1,
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )


def SuccessLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level=2,
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )


def WarningLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level=3,
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )


def ErrorLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level=4,
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )

@api_view(['POST'])
def refresh_token(request):
    if request.method == 'POST':
        refresh_token = request.data.get('refreshToken')
        if not refresh_token:
            return Response({'error': 'Missing refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Validar el token de actualización
            token = RefreshToken(refresh_token)
            token_payload = token.payload

            # Obtener el usuario asociado al token de actualización
            user = authenticate(request, id=token_payload.get('user_id'))

            if user:
                # Generar un nuevo token de acceso
                access_token = token.access_token

                # Devolver el nuevo token de acceso en la respuesta
                return Response({'token': str(access_token)}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({'error': 'Failed to refresh token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
def user_details(request):
    if request.method == 'GET':
        try:
            authorization_header = request.headers.get('Authorization')
            if not authorization_header:
                return JsonResponse({'error': 'Authorization header missing'}, status=400)

            token = authorization_header.split(' ')[1]

            access_token = AccessToken(token)
            user_id = access_token.payload.get('user_id')

            user_profile = UserProfile.objects.get(user_id=user_id)

            user_data = {
                'id': user_profile.user_id,
                'username': user_profile.user.username,
                'email': user_profile.user.email,
                'name': user_profile.name,
                'surname': user_profile.surname,
                'surname2': user_profile.surname2,
                'role': user_profile.role.id,
                'date_of_birth': user_profile.date_of_birth,
                'center': user_profile.center,
                'cycle': user_profile.cycle,
                'image': str(user_profile.image) if user_profile.image else None,
                'dni': user_profile.dni,
            }

            return JsonResponse(user_data, status=200)

        except UserProfile.DoesNotExist:
            return JsonResponse({'error': 'User profile not found'}, status=404)

        except Exception as error:
            print('Error:', error)
            return JsonResponse({'error': 'Failed to get user details'}, status=500)

    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST']) 
def update_data_user(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        print('data', data)
        user_data = data.get('data')
        print('userData', user_data)

        try:
            user = User.objects.get(username=user_data.get('username'))
            print('user encontrado')
            user_profile = UserProfile.objects.get(user=user)
            print('user profile encontrado')

            if 'email' in user_data:
                user.username = user_data.get('email')
            if 'first_name' in user_data:
                user_profile.name = user_data.get('first_name')
            if 'last_name' in user_data:
                user_profile.surname = user_data.get('last_name')
            if 'second_last_name' in user_data:
                user_profile.surname2 = user_data.get('second_last_name')

            user.save()
            user_profile.save()
            return JsonResponse({'message': 'User data updated successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User does not exist'}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def verify_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        print(request.body)
        email = data.get('email')
        password = data.get('password')

        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            return JsonResponse({'isValid': True}, status=200)
        else:
            print('Incorrect password')
            return JsonResponse({'isValid': False}, status=401)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
@api_view(['POST'])
def save_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        new_password = data.get('password')

        try:
            user = User.objects.get(username=email)
            user.set_password(new_password)
            user.save()
            return JsonResponse({'message': 'Password updated successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User does not exist'}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)