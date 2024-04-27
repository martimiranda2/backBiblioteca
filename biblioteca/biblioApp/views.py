import json
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError

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
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        user_profile = UserProfile.objects.get(user=user)
        InfoLog(user_profile, 'Token generated', 'Token generado exitosamente', '/get_token_by_email_and_password')

        return token_data
    except AuthenticationFailed as error:
        WarningLog(None, 'Invalid credentials', 'No se ha podido crear un token porque las credenciales són inválidas: email={} / password={}'.format(str(email), str(password)), '/get_token_by_email_and_password')
        raise error
    except TypeError as error:
        ErrorLog(None, 'TypeError', str(error), '/get_token_by_email_and_password')
        raise error
    except AttributeError as error:
        ErrorLog(None, 'AttributeError', str(error), '/get_token_by_email_and_password')
        raise error
    except KeyError as error:
        ErrorLog(None, 'KeyError', str(error), '/get_token_by_email_and_password')
        raise error
    except Exception as error:
        ErrorLog(None, 'ERROR UNDEFINED', str(error), '/get_token_by_email_and_password')


@csrf_exempt
def new_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('username')
            password = data.get('password')

            # Authenticate the user
            user = authenticate(request, username=email, password=password)
            if user is not None and user.is_active:
                user_profile = UserProfile.objects.get(user=user)

                token = get_token_by_email_and_password(email, password)

                InfoLog(user_profile, 'Log In', 'Usuario autenticado exitosamente: {}'.format(email), '/new_login')
                return JsonResponse({'message': 'User Authenticated successfully', 'token': token})
            else:
                WarningLog(None, 'Incorrect credentials', 'Credenciales incorrectas: username={} / password={}'.format(email, password), '/new_login')
                return JsonResponse({'message': 'Incorrect credentials'}, status=401)
        except ObjectDoesNotExist:
            ErrorLog(None, 'User not found', 'Perfil de usuario no encontrado para el usuario: {}'.format(user), '/new_login')
            return JsonResponse({'message': 'User profile not found'}, status=404)
        except TypeError as error:
            ErrorLog(None, 'TypeError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to a TypeError'}, status=500)
        except AttributeError as error:
            ErrorLog(None, 'AttributeError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to an AttributeError'}, status=500)
        except KeyError as error:
            ErrorLog(None, 'KeyError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to a KeyError'}, status=500)
        except json.JSONDecodeError as error:
            ErrorLog(None, 'JSONDecodeError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to a JSONDecodeError'}, status=500)
        except Exception as error:
            ErrorLog(None, 'new_login', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user'}, status=500)
        
    else:
        ErrorLog(None, 'Method not allowed', 'Se ha intentado acceder a new_login mediante un method que no es POST', '/new_login')
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
    try:
        user = User.objects.get(id=user_id)
        return user
    except ObjectDoesNotExist:
        ErrorLog(None, 'User not found', 'Usuario no encontrado con el id: {}'.format(user_id), '/get_user_by_id')
        return JsonResponse({'message': 'User profile not found'}, status=404)

def get_user_profile_by_email(email):
    try:
        user_profile = UserProfile.objects.get(email=email)
        return user_profile
    except UserProfile.DoesNotExist:
        ErrorLog(None, 'User not found', 'Usuario no encontrado con el mail: {}'.format(email), '/get_user_by_id')
        return JsonResponse({'message': 'User profile not found'}, status=404)

# Funcion logs
def InfoLog(user, title, description, route):
    Log.objects.create(
        user=user,
        log_level='INFO'    ,
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
        try:
            data = json.loads(request.body)

            for log_data in data:
                email = log_data.get('user')
                log_level = log_data.get('level')
                title = log_data.get('title')
                description = log_data.get('description')
                route = log_data.get('route')

                user = None;
                if (email is not None):
                    user = get_user_profile_by_email(email)

                Log.objects.create(
                    user=user,
                    log_level=log_level,
                    title=title,
                    description=description,
                    route=route,
                    date=timezone.now()
                )
            return JsonResponse({'message': 'Logs saved successfully'}, status=201)

        except TypeError as error:
            ErrorLog(None, 'TypeError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to a TypeError'}, status=500)
        except AttributeError as error:
            ErrorLog(None, 'AttributeError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to an AttributeError'}, status=500)
        except KeyError as error:
            ErrorLog(None, 'KeyError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to a KeyError'}, status=500)
        except json.JSONDecodeError as error:
            ErrorLog(None, 'JSONDecodeError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to a JSONDecodeError'}, status=500)
        except Exception as error:
            ErrorLog(None, 'ERROR UNDEFINED', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user'}, status=500)
    else:
        ErrorLog(None, 'Method not allowed', 'Se ha intentado acceder a save_logs mediante un method que no es POST', '/save_logs')
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def refresh_token(request):
    if request.method == 'POST':
        try:
            refresh_token = request.data.get('refreshToken')
            if not refresh_token:
                WarningLog(None, 'refresh_token', 'Token de actualización no encontrado', '/refresh_token')
                return Response({'error': 'Refresh token not found'}, status=status.HTTP_400_BAD_REQUEST)

            # Validar el token de actualización
            try:
                token = RefreshToken(refresh_token)
            except TokenError as e:
                WarningLog(None, 'Invalid token', 'Token de actualización inválido', '/refresh_token')
                return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

            token_payload = token.payload

            # Obtener el usuario asociado al token de actualización
            user = authenticate(request, id=token_payload.get('user_id'))

            if not user:
                WarningLog(None, 'User not found', 'Usuario no encontrado con el id extraido del token', '/refresh_token')
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            access_token = token.access_token

            InfoLog(user, 'refresh token', 'Token refrescado exitosamente', '/refresh_token')
            return Response({'token': str(access_token)}, status=status.HTTP_200_OK)

        except Exception as e:
            FatalLog(None, 'Refresh token error', 'Error al refrescar el token', '/refresh_token')
            return Response({'error': 'Failed to refresh token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        ErrorLog(None, 'Method not allowed', 'Se ha intentado acceder a refresh_token mediante un method que no es POST', '/refresh_token')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
@api_view(['GET'])
def user_details(request):
    if request.method == 'GET':
        try:
            authorization_header = request.headers.get('Authorization')

            if not authorization_header:
                ErrorLog(None, 'Missing Auth Header', 'Falta la cabecera de autorización', '/user_details')
                return JsonResponse({'error': 'Authorization header missing'}, status=400)

            token = authorization_header.split(' ')[1]

            try:
                access_token = AccessToken(token)
            except TokenError:
                ErrorLog(None, 'Invalid token', 'Token de acceso inválido', '/user_details')
                return JsonResponse({'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = access_token.payload.get('user_id')

            try:
                user_profile = UserProfile.objects.get(user_id=user_id)

            except UserProfile.DoesNotExist:
                ErrorLog(None, 'User profile not found', 'Perfil de usuario no encontrado con id={}'.format(user_id), '/user_details')
                return JsonResponse({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

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

            InfoLog(user_profile, 'User Details Retrieved', 'Detalles de usuario obtenidos exitosamente', '/user_details')
            return JsonResponse(user_data, status=200)

        except UserProfile.DoesNotExist:
            ErrorLog(None, 'User Profile Not Found', 'Perfil de usuario no encontrado', '/user_details')
            return JsonResponse({'error': 'User profile not found'}, status=404)

        except Exception as error:
            ErrorLog(None, 'User Details Retrieval Error', 'Error al obtener detalles de usuario: {}'.format(error), '/user_details')
            return JsonResponse({'error': 'Failed to get user details'}, status=500)

    else:
        ErrorLog(None, 'Invalid Method', 'Método no permitido', '/user_details')
        return JsonResponse({'error': 'Method not allowed'}, status=405)

from rest_framework import status

@api_view(['POST']) 
def update_data_user(request):
    if request.method == 'POST':
        try:
            user_data = json.loads(request.body).get('data')
        except json.JSONDecodeError:
            ErrorLog(None, 'JSONDecodeError', 'Error al decodificar el JSON del cuerpo de la petición', '/update_data_user')
            return JsonResponse({'error': 'Failed to decode JSON'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(username=user_data.get('username'))
            user_profile = UserProfile.objects.get(user=user)

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

            InfoLog(user, 'User Update', 'Datos de usuario actualizados exitosamente', '/update_data_user')
            return JsonResponse({'message': 'User data updated successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            ErrorLog(None, 'User Not Found', 'Usuario no encontrado durante la actualización', '/update_data_user')
            return JsonResponse({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as error:
            ErrorLog(None, 'User Update Error', 'Error al actualizar los datos del usuario: {}'.format(str(error)), '/update_data_user')
            return JsonResponse({'error': 'Failed to update user data'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        ErrorLog(None, 'Invalid Method', 'Método no permitido en /update_data_user', '/update_data_user')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
def verify_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            ErrorLog(None, 'JSONDecodeError', 'Error al decodificar el JSON del cuerpo de la petición', '/verify_password')
            return JsonResponse({'error': 'Failed to decode JSON'}, status=status.HTTP_400_BAD_REQUEST)

    
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            ErrorLog(None, 'Missing Data', 'Faltan datos de email o contraseña', '/verify_password')
            return JsonResponse({'error': 'Email or password data missing'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            InfoLog(user, 'Password Verification', 'Verificación de contraseña exitosa', '/verify_password')
            return JsonResponse({'isValid': True}, status=status.HTTP_200_OK)
        else:
            ErrorLog(None, 'Incorrect Password', 'Contraseña incorrecta para el usuario: {}'.format(email), '/verify_password')
            return JsonResponse({'isValid': False}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        ErrorLog(None, 'Invalid Method', 'Método no permitido en /verify_password', '/verify_password')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
from rest_framework import status

@api_view(['POST'])
def save_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            ErrorLog(None, 'JSON Decode Error', 'Error al decodificar el JSON del cuerpo de la petición', '/save_password')
            return JsonResponse({'error': 'Failed to decode JSON'}, status=status.HTTP_400_BAD_REQUEST)

        email = data.get('email')
        new_password = data.get('password')

        if not email or not new_password:
            ErrorLog(None, 'Missing Data', 'Faltan datos de email o contraseña', '/save_password')
            return JsonResponse({'error': 'Email or password data missing'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(username=email)
            user.set_password(new_password)
            user.save()
            InfoLog(user, 'Password Update', 'Contraseña actualizada exitosamente', '/save_password')
            return JsonResponse({'message': 'Password updated successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            ErrorLog(None, 'User Not Found', 'Usuario no encontrado durante la actualización de la contraseña', '/save_password')
            return JsonResponse({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    else:
        ErrorLog(None, 'Invalid Method', 'Método no permitido en /save_password', '/save_password')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
from rest_framework import status

@api_view(['GET'])
def search_items(request):
    if request.method == 'GET':
        query = request.GET.get('item', '')
        InfoLog(None, 'Search Query', 'Consulta de búsqueda: {}'.format(query), '/search_items')

        results = []

        models_to_search = [
            (Item, ['title', 'material_type', 'signature']),
            (Book, ['title', 'author']),
            (CD, ['title', 'author']),
            (Dispositive, ['title', 'brand']),
        ]

        try:
            for model, fields in models_to_search:
                for field in fields:
                    filter_kwargs = {f"{field}__icontains": query}
                    model_results = model.objects.filter(**filter_kwargs)[:5]
                    for obj in model_results:
                        results.append({'id': obj.id, 'name': str(obj)})
                        if len(results) >= 5:
                            InfoLog(None, 'Search Results', 'Resultados de búsqueda: {}'.format(results), '/search_items')
                            return JsonResponse(results, safe=False)
            InfoLog(None, 'Search Results', 'Resultados de búsqueda: {}'.format(results), '/search_items')
            return JsonResponse(results, safe=False)
        except Exception as error:
            ErrorLog(None, 'Search Error', 'Error al realizar la búsqueda: {}'.format(str(error)), '/search_items')
            return JsonResponse({'error': 'Failed to perform search'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        ErrorLog(None, 'Invalid Method', 'Método no permitido en /search_items', '/search_items')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

