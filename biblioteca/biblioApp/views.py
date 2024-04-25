# import json
# from django.shortcuts import render, get_object_or_404
# from django.http import Http404, HttpResponse, JsonResponse
# from django.contrib.auth import authenticate, login
# from django.utils import timezone
# from django.views.decorators.csrf import csrf_exempt
# from django.db.models import Q

# from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
# from rest_framework.exceptions import AuthenticationFailed
# from rest_framework.decorators import api_view
# from rest_framework.response import Response
# from rest_framework import status

# from .models import Book, CD, Item, Dispositive, Log, User, Role, UserProfile

# from datetime import timedelta
# from rest_framework_simplejwt.settings import api_settings
# api_settings.ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
# api_settings.REFRESH_TOKEN_LIFETIME = timedelta(days=1)

# @csrf_exempt
# def get_token_by_email_and_password(email, password):
#     try:
#         user = authenticate(username=email, password=password)
#         if user is None:
#             raise AuthenticationFailed('Invalid email or password')

#         refresh = RefreshToken.for_user(user)

#         token_data = {
#             'id': user.id,
#             'email': user.username,
#         }

#         token_data['refresh'] = str(refresh)
#         token_data['access'] = str(refresh.access_token)
#         InfoLog(user, 'get_token_by_email_and_password', 'Token generado exitosamente', '/get_token_by_email_and_password')

#         return token_data
#     except Exception as error:
#         ErrorLog(None, 'get_token_by_email_and_password', str(error), '/get_token_by_email_and_password')

# @csrf_exempt
# def new_login(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         email = data.get('username')
#         password = data.get('password')

#         user = authenticate(request, username=email, password=password)
#         if user is not None and user.is_active:
#             token = get_token_by_email_and_password(email, password)
#             InfoLog(user, 'new_login', 'Usuario autenticado exitosamente', '/new_login')
#             return JsonResponse({'message': 'User Authenticated successfully', 'token': token})
#         else:
#             WarningLog(None, 'new_login', 'Credenciales incorrectas', '/new_login')
#             return JsonResponse({'message': 'Incorrect credentials'}, status=401)
#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)

# def register(password, name, surname, surname2, role_id, date_of_birth, center, cycle, dni, email, image=None):
#     try:
#         role = Role.objects.get(id=role_id)

#         user_profile = User.objects.create(
#             name=name,
#             surname=surname,
#             surname2=surname2,
#             role=role,
#             date_of_birth=date_of_birth,
#             center=center,
#             cycle=cycle,
#             image=image,
#             dni=dni,
#             email=email
#         )

#         return user_profile
#     except Exception as error:
#         print('register -> error:', error)



# def get_user_by_id(user_id):
#     try:
#         user = get_object_or_404(User, id=user_id)
#         InfoLog(user, 'get_user_by_id', f'Usuario {user_id} obtenido exitosamente', '/get_user_by_id')
#         return user
#     except Http404 as error:
#         ErrorLog(None, 'get_user_by_id', f'Usuario {user_id} no encontrado', '/get_user_by_id')
#         raise error

# def get_user_profile_by_email(email):
#     try:
#         user_profile = get_object_or_404(UserProfile, email=email)
#         InfoLog(None, 'get_user_profile_by_email', f'Perfil de usuario con email {email} obtenido exitosamente', '/get_user_profile_by_email')
#         return user_profile
#     except Http404 as error:
#         ErrorLog(None, 'get_user_profile_by_email', f'Perfil de usuario con email {email} no encontrado', '/get_user_profile_by_email')
#         raise error


# # Funcion logs
# def InfoLog(user, title, description, route):
#     Log.objects.create(
#         user=user,
#         log_level='INFO',
#         title=title,
#         description=description,
#         route=route,
#         date=timezone.now()
#     )


# def FatalLog(user, title, description, route):
#     Log.objects.create(
#         user=user,
#         log_level='FATAL',
#         title=title,
#         description=description,
#         route=route,
#         date=timezone.now()
#     )


# def WarningLog(user, title, description, route):
#     Log.objects.create(
#         user=user,
#         log_level='WARNING',
#         title=title,
#         description=description,
#         route=route,
#         date=timezone.now()
#     )


# def ErrorLog(user, title, description, route):
#     Log.objects.create(
#         user=user,
#         log_level='ERROR',
#         title=title,
#         description=description,
#         route=route,
#         date=timezone.now()
#     )

# @csrf_exempt
# @api_view(['POST'])
# def save_logs(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         for log_data in data:
#             user = log_data.get('user')
#             log_level = log_data.get('log_level')
#             title = log_data.get('title')
#             description = log_data.get('description')
#             route = log_data.get('route')

#             Log.objects.create(
#                 user=user,
#                 log_level=log_level,
#                 title=title,
#                 description=description,
#                 route=route,
#                 date=timezone.now()
#             )

#         return JsonResponse({'message': 'Logs saved successfully'}, status=201)

#     return JsonResponse({'error': 'Invalid request'}, status=400)

# @api_view(['POST'])
# def refresh_token(request):
#     if request.method == 'POST':
#         refresh_token = request.data.get('refreshToken')
#         if not refresh_token:
#             WarningLog(None, 'refresh_token', 'Falta token de actualización', '/refresh_token')
#             return Response({'error': 'Missing refresh token'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Validar el token de actualización
#             token = RefreshToken(refresh_token)
#             token_payload = token.payload

#             # Obtener el usuario asociado al token de actualización
#             user = authenticate(request, id=token_payload.get('user_id'))

#             if user:
#                 # Generar un nuevo token de acceso
#                 access_token = token.access_token

#                 # Devolver el nuevo token de acceso en la respuesta
#                 InfoLog(user, 'refresh_token', 'Token refrescado exitosamente', '/refresh_token')
#                 return Response({'token': str(access_token)}, status=status.HTTP_200_OK)
#             else:
#                 WarningLog(None, 'refresh_token', 'Token de actualización inválido', '/refresh_token')
#                 return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

#         except Exception as e:
#             ErrorLog(None, 'refresh_token', 'Error al refrescar el token', '/refresh_token')
#             return Response({'error': 'Failed to refresh token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#     else:
#         return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
# @api_view(['GET'])
# def user_details(request):
#     if request.method == 'GET':
#         try:
#             authorization_header = request.headers.get('Authorization')
#             if not authorization_header:
#                 WarningLog(None, 'user_details', 'Falta la cabecera de autorización', '/user_details')
#                 return JsonResponse({'error': 'Authorization header missing'}, status=400)

#             token = authorization_header.split(' ')[1]
#             print('token:', token)
#             access_token = AccessToken(token)
#             user_id = access_token.payload.get('user_id')

#             user_profile = UserProfile.objects.get(user_id=user_id)

#             user_data = {
#                 'id': user_profile.user_id,
#                 'username': user_profile.user.username,
#                 'email': user_profile.user.email,
#                 'name': user_profile.name,
#                 'surname': user_profile.surname,
#                 'surname2': user_profile.surname2,
#                 'role': user_profile.role.id,
#                 'date_of_birth': user_profile.date_of_birth,
#                 'center': user_profile.center,
#                 'cycle': user_profile.cycle,
#                 'image': str(user_profile.image) if user_profile.image else None,
#                 'dni': user_profile.dni,
#             }

#             InfoLog(user_profile.user, 'user_details', 'Detalles de usuario obtenidos exitosamente', '/user_details')
#             return JsonResponse(user_data, status=200)

#         except UserProfile.DoesNotExist:
#             ErrorLog(None, 'user_details', 'Perfil de usuario no encontrado', '/user_details')
#             return JsonResponse({'error': 'User profile not found'}, status=404)

#         except Exception as error:
#             ErrorLog(None, 'user_details', 'Error al obtener detalles de usuario', '/user_details')
#             return JsonResponse({'error': 'Failed to get user details'}, status=500)

#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)

# @api_view(['POST']) 
# def update_data_user(request):
#     if request.method == 'POST':
#         user_data = json.loads(request.body).get('data')

#         try:
#             user = User.objects.get(username=user_data.get('username'))
#             user_profile = UserProfile.objects.get(user=user)

#             if 'email' in user_data:
#                 user.username = user_data.get('email')
#             if 'first_name' in user_data:
#                 user_profile.name = user_data.get('first_name')
#             if 'last_name' in user_data:
#                 user_profile.surname = user_data.get('last_name')
#             if 'second_last_name' in user_data:
#                 user_profile.surname2 = user_data.get('second_last_name')

#             user.save()
#             user_profile.save()
#             InfoLog(user, 'update_data_user', 'Datos de usuario actualizados exitosamente', '/update_data_user')
#             return JsonResponse({'message': 'User data updated successfully'}, status=200)
#         except User.DoesNotExist:
#             ErrorLog(None, 'update_data_user', 'Usuario no existe', '/update_data_user')
#             return JsonResponse({'message': 'User does not exist'}, status=404)
#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)

# @api_view(['POST'])
# def verify_password(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         email = data.get('email')
#         password = data.get('password')

#         user = authenticate(request, username=email, password=password)
#         if user is not None and user.is_active:
#             InfoLog(user, 'verify_password', 'Contraseña verificada exitosamente', '/verify_password')
#             return JsonResponse({'isValid': True}, status=200)
#         else:
#             WarningLog(None, 'verify_password', 'Contraseña incorrecta', '/verify_password')
#             return JsonResponse({'isValid': False}, status=401)
#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)
    
# @api_view(['POST'])
# def save_password(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         email = data.get('email')
#         new_password = data.get('password')

#         try:
#             user = User.objects.get(username=email)
#             user.set_password(new_password)
#             user.save()
#             InfoLog(user, 'save_password', 'Contraseña actualizada exitosamente', '/save_password')
#             return JsonResponse({'message': 'Password updated successfully'}, status=200)
#         except User.DoesNotExist:
#             ErrorLog(None, 'save_password', 'Usuario no existe', '/save_password')
#             return JsonResponse({'message': 'User does not exist'}, status=404)
#     else:
#         return JsonResponse({'error': 'Method not allowed'}, status=405)
    
# @api_view(['GET'])
# def search_items(request):
#     query = request.GET.get('item', '')
#     InfoLog(None, 'search_items', f'Búsqueda realizada con la consulta: {query}', '/search_items')

#     results = []

#     models_to_search = [
#         (Item, ['title', 'material_type', 'signature']),
#         (Book, ['title', 'author']),
#         (CD, ['title', 'author']),
#         (Dispositive, ['title', 'brand']),
#     ]

#     for model, fields in models_to_search:
#         for field in fields:
#             filter_kwargs = {f"{field}__icontains": query}
#             model_results = model.objects.filter(**filter_kwargs)[:5]
#             for obj in model_results:
#                 results.append({'id': obj.id, 'name': str(obj)})
#                 if len(results) >= 5:
#                     InfoLog(None, 'search_items', f'Se encontraron {len(results)} resultados', '/search_items')
#                     return JsonResponse(results, safe=False)

#     InfoLog(None, 'search_items', f'Se encontraron {len(results)} resultados', '/search_items')
#     return JsonResponse(results, safe=False)



import json
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .models import Book, CD, Item, Dispositive, Log, User, Role, UserProfile

from datetime import timedelta
from rest_framework_simplejwt.settings import api_settings
api_settings.ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
api_settings.REFRESH_TOKEN_LIFETIME = timedelta(days=1)

@csrf_exempt
def get_token_by_email_and_password(email, password):
    try:
        user = authenticate(username=email, password=password)
        if user is None:
            raise AuthenticationFailed('Invalid email or password')

        refresh = RefreshToken.for_user(user)

        token_data = {
            'id': user.id,
            'email': user.username,
        }

        token_data['refresh'] = str(refresh)
        token_data['access'] = str(refresh.access_token)
        InfoLog(user, 'get_token_by_email_and_password', 'Token generado exitosamente', '/get_token_by_email_and_password')

        return token_data
    except Exception as error:
        ErrorLog(None, 'get_token_by_email_and_password', str(error), '/get_token_by_email_and_password')

@csrf_exempt
def new_login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('username')
        password = data.get('password')

        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            token = get_token_by_email_and_password(email, password)
            InfoLog(user, 'new_login', 'Usuario autenticado exitosamente', '/new_login')
            return JsonResponse({'message': 'User Authenticated successfully', 'token': token})
        else:
            WarningLog(None, 'new_login', 'Credenciales incorrectas', '/new_login')
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
        print('register -> error:', error)



def get_user_by_id(user_id):
    user = get_object_or_404(User, id=user_id)
    return user

def get_user_profile_by_email(email):
    user_profile = get_object_or_404(UserProfile, email=email)
    return user_profile


# Funcion logs
def InfoLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level='INFO',
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )


def FatalLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level='FATAL',
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )


def WarningLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level='WARNING',
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )


def ErrorLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level='ERROR',
        title=title,
        description=description,
        route=route,
        date=timezone.now()
    )

@csrf_exempt
@api_view(['POST'])
def save_logs(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        for log_data in data:
            user = log_data.get('user')
            log_level = log_data.get('log_level')
            title = log_data.get('title')
            description = log_data.get('description')
            route = log_data.get('route')

            Log.objects.create(
                user=user,
                log_level=log_level,
                title=title,
                description=description,
                route=route,
                date=timezone.now()
            )

        return JsonResponse({'message': 'Logs saved successfully'}, status=201)

    return JsonResponse({'error': 'Invalid request'}, status=400)

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
                access_token = token.access_token

                InfoLog(user, 'refresh_token', 'Token refrescado exitosamente', '/refresh_token')
                return Response({'token': str(access_token)}, status=status.HTTP_200_OK)
            else:
                WarningLog(None, 'refresh_token', 'Token de actualización inválido', '/refresh_token')
                return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            FatalLog(None, 'refresh_token', 'Error al refrescar el token', '/refresh_token')
            return Response({'error': 'Failed to refresh token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        return Response({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
@api_view(['GET'])
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

            InfoLog(user_profile.user, 'user_details', 'Detalles de usuario obtenidos exitosamente', '/user_details')
            return JsonResponse(user_data, status=200)

        except UserProfile.DoesNotExist:
            ErrorLog(None, 'user_details', 'Perfil de usuario no encontrado', '/user_details')
            return JsonResponse({'error': 'User profile not found'}, status=404)

        except Exception as error:
            ErrorLog(None, 'user_details', 'Error al obtener detalles de usuario', '/user_details')
            return JsonResponse({'error': 'Failed to get user details'}, status=500)

    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST']) 
def update_data_user(request):
    if request.method == 'POST':
        user_data = json.loads(request.body).get('data')
        print('update_data_user -> user_data', user_data)

        try:
            user = User.objects.get(username=user_data.get('username'))
            print('update_data_user -> user encontrado')
            user_profile = UserProfile.objects.get(user=user)
            print('update_data_user -> user profile encontrado')

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
            print('verify_password -> Incorrect password')
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
    
@api_view(['GET'])
def search_items(request):
    query = request.GET.get('item', '')
    print('search_items -> query:', query)

    results = []

    models_to_search = [
        (Item, ['title', 'material_type', 'signature']),
        (Book, ['title', 'author']),
        (CD, ['title', 'author']),
        (Dispositive, ['title', 'brand']),
    ]

    for model, fields in models_to_search:
        for field in fields:
            filter_kwargs = {f"{field}__icontains": query}
            model_results = model.objects.filter(**filter_kwargs)[:5]
            for obj in model_results:
                results.append({'id': obj.id, 'name': str(obj)})
                if len(results) >= 5:
                    return JsonResponse(results, safe=False)

    return JsonResponse(results, safe=False)

