import json,base64,os,re
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.core.mail import BadHeaderError
from django.core.files.base import ContentFile
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenError

from .models import Book, CD, Loan, Item, Dispositive, Log, User, Role, UserProfile, ItemCopy

from datetime import timedelta,datetime
from rest_framework_simplejwt.settings import api_settings
api_settings.ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
api_settings.REFRESH_TOKEN_LIFETIME = timedelta(days=1)

import environ
env = environ.Env()
environ.Env.read_env()




def get_user_image(request, user_id):
    if request.method == 'GET':
        try:
            user = User.objects.get(id=user_id)
            user_profile = UserProfile.objects.get(user=user)
            if user_profile.image:
                image_data = user_profile.image.read()
                return HttpResponse(image_data, content_type='image/jpeg')
            else:
                image_path = os.path.join(settings.MEDIA_ROOT, 'user_images', 'no-photo-profile.png')
                with open(image_path, 'rb') as f:
                    return HttpResponse(f.read(), content_type='image/png')
        except User.DoesNotExist:

            return JsonResponse({'error': 'User profile not found'}, status=400)
        except UserProfile.DoesNotExist:
            
            return JsonResponse({'error': 'User profile not found'}, status=400)
    else:
        
        return JsonResponse({'error': 'Only GET requests are allowed'}, status=400)

@api_view(['POST'])
def show_users(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email_admin')
        userAdmin = UserProfile.objects.filter(email=email).first()
        if userAdmin is not None:
            rolAdmin = userAdmin.role.name
            if rolAdmin == 'bibliotecari' or rolAdmin == 'admin' :
                center = userAdmin.center
                users_alumne = UserProfile.objects.filter(role__name='alumne', center=center)
                user_profiles_json = list(users_alumne.values())
                return JsonResponse({'user_profiles': user_profiles_json}, status=200)
                
            else:
                return JsonResponse({'error': 'User is not an admin'}, status=400)
        else:
            return JsonResponse({'error': 'User not exist'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def change_user_data_admin(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email_admin = data.get('email_admin')
        email_user = data.get('email_user')
        user_admin = UserProfile.objects.filter(email=email_admin).first()
        user_change = UserProfile.objects.filter(email=email_user).first()

        print('change_user_data_admin -> user_admin:', user_admin)
        print('change_user_data_admin -> user_change:', user_change)
        
        if user_admin is not None and user_change is not None:
            role_admin = user_admin.role.name
            if role_admin == 'bibliotecari' or role_admin == 'admin':
                user_change.name = data.get('name', user_change.name)
                user_change.surname = data.get('surname', user_change.surname)
                user_change.surname2 = data.get('surname2', user_change.surname2)
                user_change.dni = data.get('dni', user_change.dni)
                user_change.phone = data.get('phone', user_change.phone)
                user_change.date_of_birth = datetime.strptime(data.get('birth', user_change.date_of_birth), "%d-%m-%Y")
                user_change.cycle = data.get('cycle', user_change.cycle)
                user_change.save()
                
                return JsonResponse({'message': 'User data updated successfully'}, status=200)
            else:
                return JsonResponse({'error': 'User is not an admin'}, status=400)
        else:
            return JsonResponse({'error': 'User not found'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST']) 
def change_user_image(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        image_data = data.get('image_data')  
        userP = UserProfile.objects.filter(email=email).first()
        if userP is not None:
            user = userP.user
            if image_data and user is not None:
                format, imgstr = image_data.split(';base64,')
                ext = format.split('/')[-1]
                image = ContentFile(base64.b64decode(imgstr), name='temp.' + ext)

                # Guardar la imagen en el objeto UserProfile
                user_profile = UserProfile.objects.get(user=user)
                user_profile.image = image
                user_profile.save()

                return JsonResponse({'message': 'Image uploaded successfully'})
            else:
                return JsonResponse({'error': 'Problem with the json data'}, status=400)
        else:
            return JsonResponse({'error': 'Problem with the json data'}, status=400)

    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def obtain_item_data(request,idItem):
    try:
        item = Item.objects.get(id=idItem)
        
        item_details = {
            'title': item.title,
            'material_type': item.material_type,
            'signature': item.signature,
            'loan_available': item.loan_available,
        }

        if hasattr(item, 'book'):
            book_details = {
                'type':'book',
                'author': item.book.author,
                'edition_date': item.book.edition_date,
                'CDU': item.book.CDU,
                'ISBN': item.book.ISBN,
                'publisher': item.book.publisher,
                'colection': item.book.colection,
                'pages': item.book.pages,
            }
            item_details['more_details'] = book_details

        elif hasattr(item, 'cd'):
            cd_details = {
                'type':'cd',
                'author': item.cd.author,
                'edition_date': item.cd.edition_date,
                'discography': item.cd.discography,
                'style': item.cd.style,
                'duration': item.cd.duration,
            }
            item_details['more_details'] = cd_details

        elif hasattr(item, 'dispositive'):
            dispositive_details = {
                'type':'dispositive',
                'brand': item.dispositive.brand,
                'dispo_type': item.dispositive.dispo_type,
            }
            item_details['more_details'] = dispositive_details

        return JsonResponse(item_details)
    
    except Item.DoesNotExist:
        return JsonResponse({'error': 'Item does not exist'}, status=404)

@csrf_exempt
def search_items_availables(request, search):
    query = search
    print('search_items -> query:', query)

    results = []

    models_to_search = [
        (Item, ['title', 'material_type', 'signature'])
    ]

    for model, fields in models_to_search:
        for field in fields:
            filter_kwargs = {f"{field}__icontains": query}
            model_results = model.objects.filter(**filter_kwargs)[:25]  # Limitar a 25 resultados
            for obj in model_results:
                if obj.loan_available:
                    if ItemCopy.objects.filter(item=obj, status='Available').exists():
                        results.append({'id': obj.id, 'name': str(obj)})
    return JsonResponse(results, safe=False)

@csrf_exempt
def get_token_by_email_and_password(email, password):
    try:
        userP = UserProfile.objects.filter(email=email).first()
        user = authenticate(username=userP.user.username, password=password)
        if user is None:
            raise AuthenticationFailed('Invalid email or password')

        refresh = RefreshToken.for_user(user)

        token_data = {
            'id': user.id,
            'email': user.username,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

        InfoLog(email, 'Token generated', 'Token generado exitosamente', '/get_token_by_email_and_password')

        return token_data
    except AuthenticationFailed as error:
        WarningLog('', 'Invalid credentials', 'No se ha podido crear un token porque las credenciales són inválidas: email={} / password={}'.format(str(email), str(password)), '/get_token_by_email_and_password')
        raise error
    except TypeError as error:
        ErrorLog('', 'TypeError', str(error), '/get_token_by_email_and_password')
        raise error
    except AttributeError as error:
        ErrorLog('', 'AttributeError', str(error), '/get_token_by_email_and_password')
        raise error
    except KeyError as error:
        ErrorLog('', 'KeyError', str(error), '/get_token_by_email_and_password')
        raise error
    except Exception as error:
        ErrorLog('', 'ERROR UNDEFINED', str(error), '/get_token_by_email_and_password')


@csrf_exempt
def new_login(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('username')
            password = data.get('password')

        # Authenticate the user
            userP = UserProfile.objects.filter(email=email)

            if userP.exists():
                user_profile = userP.first()
                if authenticate(username=user_profile.user.username, password=password):
                    token = get_token_by_email_and_password(email, password)
                    InfoLog(email, 'new_login', 'Usuario autenticado exitosamente', '/new_login')
                    return JsonResponse({'message': 'User Authenticated successfully', 'token': token})
                else:
                    WarningLog('', 'new_login', 'Credenciales incorrectas', '/new_login')
                    return JsonResponse({'message': 'Credenciales incorrectas'}, status=401)
            else:
                WarningLog('', 'new_login', 'Credenciales incorrectas', '/new_login')
                return JsonResponse({'message': 'Incorrect credentials'}, status=401)

        except ObjectDoesNotExist:
            ErrorLog('', 'User not found', 'Perfil de usuario no encontrado para el usuario: {}'.format(email), '/new_login')
            return JsonResponse({'message': 'User profile not found'}, status=404)
        except TypeError as error:
            ErrorLog('', 'TypeError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to a TypeError'}, status=500)
        except AttributeError as error:
            ErrorLog('', 'AttributeError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to an AttributeError'}, status=500)
        except KeyError as error:
            ErrorLog('', 'KeyError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to a KeyError'}, status=500)
        except json.JSONDecodeError as error:
            ErrorLog('', 'JSONDecodeError', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user due to a JSONDecodeError'}, status=500)
        except Exception as error:
            ErrorLog('', 'new_login', str(error), '/new_login')
            return JsonResponse({'message': 'Failed to authenticate user'}, status=500)
        
    else:
        ErrorLog('', 'Method not allowed', 'Se ha intentado acceder a new_login mediante un method que no es POST', '/new_login')
        return JsonResponse({'error': 'Method not allowed'}, status=405)


@api_view(['POST'])
def create_user(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            user_data = {
                'email': data.pop('email', None),
                'name': data.pop('name', None),
                'surname': data.pop('surname', None),
                'surname2': data.pop('surname2', None),
                'dni': data.pop('dni', None),
                'phone': data.pop('phone', None),
                'date_of_birth':datetime.strptime(data.pop('birth', None), "%d-%m-%Y"),
                'cycle': data.pop('cycle', None),
            }
            userD ={
                'username': data.pop('username', None),
                'password': data.pop('password', None)

            }
            role = Role.objects.get(name='alumne')
            
            email_admin = data.get('email_admin')
            user_admin = UserProfile.objects.filter(email=email_admin).first()
            if user_admin is None:
                return JsonResponse({'error': 'El usuario administrador no existe'}, status=404)
            
            rol_admin = user_admin.role.name
            if rol_admin not in ['bibliotecari', 'admin']:
                return JsonResponse({'error': 'El usuario administrador no tiene permisos para crear usuarios'}, status=403)
            
            center = user_admin.center
            
            user = User.objects.create_user(**userD)
            
            UserProfile.objects.create(
                user=user,
                role=role,
                center=center,
                **user_data  
            )
            
            return JsonResponse({'message': 'Usuario creado correctamente'}, status=201)
        
        except Exception as e:
            print("Tipo de excepción:", type(e).__name__)
            print("Mensaje de excepción:", str(e))
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Método no permitido'}, status=405)

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
        ErrorLog('', 'User not found', 'Usuario no encontrado con el id: {}'.format(user_id), '/get_user_by_id')
        return JsonResponse({'message': 'User profile not found'}, status=404)
    
def get_user_by_username(username):
    try:
        user = User.objects.get(username=username)
        return user
    except ObjectDoesNotExist:
        Warning('', 'User not found', 'Usuario no encontrado con el username: {}'.format(username), '/get_user_by_username')
        raise ObjectDoesNotExist

def get_user_profile_by_email(email):
    try:
        user_profile = UserProfile.objects.get(email=email)
        return user_profile
    except UserProfile.DoesNotExist:
        Warning('', 'User not found', 'Usuario no encontrado con el mail: {}'.format(email), '/get_user_profile_by_email')
        raise UserProfile.DoesNotExist
    
def get_user_profile_by_id(id):
    try:
        user_profile = UserProfile.objects.get(id=id)
        return user_profile
    except UserProfile.DoesNotExist:
        Warning('', 'User not found', 'Usuario no encontrado con el id: {}'.format(id), '/get_user_profile_by_id')
        raise UserProfile.DoesNotExist
    
@api_view(['POST'])
def get_user_by_id_to_update(request):
    try:
        print('get_user_profile_by_id -> request')
        data = json.loads(request.body)
        id = data.get('id')
        user_profile = UserProfile.objects.get(id=id)

        user_data = {
                'email': user_profile.user.email,
                'name': user_profile.name,
                'surname': user_profile.surname,
                'surname2': user_profile.surname2,
                'role': user_profile.role.id,
                'date_of_birth': user_profile.date_of_birth,
                'center': user_profile.center.name,
                'cycle': user_profile.cycle,
                'image': str(user_profile.image) if user_profile.image else None,
                'dni': user_profile.dni,
            }
        return JsonResponse({'user_profile': user_data}, status=201)
    except UserProfile.DoesNotExist:
        Warning('', 'User not found', 'Usuario no encontrado con el id: {}'.format(id), '/get_user_profile_by_id')
        raise UserProfile.DoesNotExist

@api_view(['GET'])
def check_user_exists(request):
    username = request.GET.get('username')
    email = request.GET.get('email')
    username_exists = email_exists = False
    try:
        get_user_by_username(username)
        username_exists = True
        WarningLog('', 'User exists', f'Existe un usuario con username = "{username}"', '/check_user_exists')
    except ObjectDoesNotExist:
        InfoLog('', 'User not found', f'No existe ningún usuario con username = "{username}"', '/check_user_exists')
    try:
        get_user_profile_by_email(email)
        email_exists = True
        WarningLog('', 'User exists', f'Existe un usuario con email = "{email}"', '/check_user_exists')
    except UserProfile.DoesNotExist:
        InfoLog('', 'User not found', f'No existe ningún usuario con email = "{email}"', '/check_user_exists')
    InfoLog('', 'User check', f'Comprobación de usuario realizada exitosamente (username_exists: {username_exists}, email_exists: {email_exists})', '/check_user_exists')
    return Response({'username_exists': username_exists, 'email_exists': email_exists})

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
                if isinstance(log_data, dict):
                    email = log_data.get('user')
                    log_level = log_data.get('level')
                    title = log_data.get('title')
                    description = log_data.get('description')
                    route = log_data.get('route')

                    if email is None:
                        email = ''

                    Log.objects.create(
                        user=email,
                        log_level=log_level,
                        title=title,
                        description=description,
                        route=route,
                        date=timezone.now()
                    )
                else:
                    WarningLog('', 'Invalid log data', f'Datos de log inválidos: {log_data}', '/save_logs')
                    pass
            return JsonResponse({'message': 'Logs saved successfully'}, status=201)

        except TypeError as error:
            ErrorLog('', 'TypeError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to a TypeError'}, status=500)
        except AttributeError as error:
            ErrorLog('', 'AttributeError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to an AttributeError'}, status=500)
        except KeyError as error:
            ErrorLog('', 'KeyError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to a KeyError'}, status=500)
        except json.JSONDecodeError as error:
            ErrorLog('', 'JSONDecodeError', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user due to a JSONDecodeError'}, status=500)
        except Exception as error:
            ErrorLog('', 'ERROR UNDEFINED', str(error), '/save_logs')
            return JsonResponse({'message': 'Failed to authenticate user'}, status=500)
    else:
        ErrorLog('', 'Method not allowed', 'Se ha intentado acceder a save_logs mediante un method que no es POST', '/save_logs')
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@api_view(['POST'])
def refresh_token(request):
    if request.method == 'POST':
        try:
            refresh_token = request.data.get('refreshToken')
            if not refresh_token:
                WarningLog('', 'refresh_token', 'Token de actualización no encontrado', '/refresh_token')
                return Response({'error': 'Refresh token not found'}, status=status.HTTP_400_BAD_REQUEST)

            # Validar el token de actualización
            try:
                token = RefreshToken(refresh_token)
            except TokenError as e:
                WarningLog('', 'Invalid token', 'Token de actualización inválido', '/refresh_token')
                return Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)

            token_payload = token.payload

            # Obtener el usuario asociado al token de actualización
            user = authenticate(request, id=token_payload.get('user_id'))

            if not user:
                WarningLog('', 'User not found', 'Usuario no encontrado con el id extraido del token', '/refresh_token')
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

            access_token = token.access_token

            InfoLog(user.email, 'refresh token', 'Token refrescado exitosamente', '/refresh_token')
            return Response({'token': str(access_token)}, status=status.HTTP_200_OK)

        except Exception as e:
            FatalLog('', 'Refresh token error', 'Error al refrescar el token', '/refresh_token')
            return Response({'error': 'Failed to refresh token'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        ErrorLog('', 'Method not allowed', 'Se ha intentado acceder a refresh_token mediante un method que no es POST', '/refresh_token')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
@api_view(['GET'])
def user_details(request):
    if request.method == 'GET':
        try:
            authorization_header = request.headers.get('Authorization')

            if not authorization_header:
                ErrorLog('', 'Missing Auth Header', 'Falta la cabecera de autorización', '/user_details')
                return JsonResponse({'error': 'Authorization header missing'}, status=400)

            token = authorization_header.split(' ')[1]

            try:
                access_token = AccessToken(token)
            except TokenError:
                ErrorLog('', 'Invalid token', 'Token de acceso inválido', '/user_details')
                return JsonResponse({'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)

            user_id = access_token.payload.get('user_id')

            try:
                user_profile = UserProfile.objects.get(user_id=user_id)

            except UserProfile.DoesNotExist:
                ErrorLog('', 'User profile not found', 'Perfil de usuario no encontrado con id={}'.format(user_id), '/user_details')
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
                'center': user_profile.center.name,
                'cycle': user_profile.cycle,
                'image': str(user_profile.image) if user_profile.image else None,
                'dni': user_profile.dni,
            }

            InfoLog(user_profile.user.email, 'User Details Retrieved', 'Detalles de usuario obtenidos exitosamente', '/user_details')
            return JsonResponse(user_data, status=200)

        except UserProfile.DoesNotExist:
            ErrorLog('', 'User Profile Not Found', 'Perfil de usuario no encontrado', '/user_details')
            return JsonResponse({'error': 'User profile not found'}, status=404)

        except Exception as error:
            ErrorLog('', 'User Details Retrieval Error', 'Error al obtener detalles de usuario: {}'.format(error), '/user_details')
            return JsonResponse({'error': 'Failed to get user details'}, status=500)

    else:
        ErrorLog('', 'Invalid Method', 'Método no permitido', '/user_details')
        return JsonResponse({'error': 'Method not allowed'}, status=405)

from rest_framework import status

@api_view(['POST']) 
def update_data_user(request):
    if request.method == 'POST':
        user_data = json.loads(request.body)
        try:
            user_profile = get_object_or_404(UserProfile, email=user_data.get('email_user'))
            
            if 'email_change' in user_data:
                user_profile.email = user_data.get('email_change')
                InfoLog(user_data.get('username'), 'Email modifyed', 'Se ha modificado el email del usuario {} a {}'.format(user_profile.email, user_data.get("email")), '/update_data_user')

            if 'first_name' in user_data:
                InfoLog(user_data.get('username'), 'Name modifyed', 'Se ha modificado el nombre del usuario {} a {}'.format(user_profile.name, user_data.get("first_name")), '/update_data_user')
                user_profile.name = user_data.get('first_name')
            if 'surname' in user_data:
                user_profile.surname = user_data.get('surname')
                InfoLog(user_data.get('username'), 'Last name modifyed', 'Se ha modificado el primer apellido del usuario {} a {}'.format(user_profile.surname, user_data.get("last_name")), '/update_data_user')

            if 'surname2' in user_data:
                user_profile.surname2 = user_data.get('surname2')
                InfoLog(user_data.get('username'), 'Second last name modifyed', 'Se ha modificado el segundo apellido del usuario {} a {}'.format(user_profile.surname2, user_data.get("second_last_name")), '/update_data_user')


            user_profile.save()

            InfoLog(user_data.get('username'), 'User Update', 'Datos de usuario actualizados exitosamente', '/update_data_user')
            return JsonResponse({'message': 'User data updated successfully'}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            ErrorLog('', 'User Not Found', 'Usuario no encontrado durante la actualización', '/update_data_user')
            return JsonResponse({'message': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as error:
            ErrorLog('', 'User Update Error', 'Error al actualizar los datos del usuario: {}. ERROR: {}'.format(str(user_data.get('username')), error), '/update_data_user')
            return JsonResponse({'error': 'Failed to update user data'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    else:
        ErrorLog('', 'Invalid Method', 'Método no permitido en /update_data_user', '/update_data_user')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

@api_view(['POST'])
def verify_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            ErrorLog('', 'JSONDecodeError', 'Error al decodificar el JSON del cuerpo de la petición', '/verify_password')
            return JsonResponse({'error': 'Failed to decode JSON'}, status=status.HTTP_400_BAD_REQUEST)

    
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            ErrorLog('', 'Missing Data', 'Faltan datos de email o contraseña', '/verify_password')
            return JsonResponse({'error': 'Email or password data missing'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request, username=email, password=password)
        if user is not None and user.is_active:
            InfoLog(email, 'Password Verification', 'Verificación de contraseña exitosa', '/verify_password')
            return JsonResponse({'isValid': True}, status=status.HTTP_200_OK)
        else:
            ErrorLog('', 'Incorrect Password', 'Contraseña incorrecta para el usuario: {}'.format(email), '/verify_password')
            return JsonResponse({'isValid': False}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        ErrorLog('', 'Invalid Method', 'Método no permitido en /verify_password', '/verify_password')
        return JsonResponse({'error': 'Method not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
from rest_framework import status





@api_view(['POST'])
def send_password_reset_email(request):
    try:
        email = request.data['email']
        user_profile = UserProfile.objects.get(email=email)
        user = user_profile.user

    except User.DoesNotExist:
        ErrorLog('', 'User Not Found', 'No existe un usuario con el correo electrónico {}'.format(email), '/send_password_reset_email')
        return Response({'error': 'No existe un usuario con ese correo electrónico'}, status=404)
    except KeyError:
        ErrorLog('', 'Missing Email', 'No se proporcionó un correo electrónico', '/send_password_reset_email')
        return Response({'error': 'No se proporcionó un correo electrónico'}, status=400)
    except Exception as error:
        ErrorLog('', 'ERROR UNDEFINED', str(error), '/send_password_reset_email')
        return Response({'error': error}, status=500)
    

    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    mail_subject = 'Restabliment de Contrasenya'

    message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f2f2f2;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 50px auto;
                background-color: #fff;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }}
            h1 {{
                color: #333;
                text-align: center;
            }}
            p {{
                color: #666;
                text-align: center;
            }}
            p span {{
                text-align: right;
            }}
            .container > div {{
                display: flex;
                justify-content: center;
            }}
            .container > div > a {{
                display: inline-block;
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                text-align: center;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px auto;
                cursor: pointer;
            }}
            a:hover {{
                background-color: #45a049;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Hola {user_profile.name} {user_profile.surname},</h1>
            <p>Per restablir la contrasenya, si us plau fes clic al botó de sota:</p>
            <div>
                <a href="{env.str('DOMINIO')}/reset-password/{uid}/{token}">Restablir Contrasenya</a>
            </div>
            <p>Si no has sol·licitar un restabliment de contrasenya, si us plau ignora aquest correu electrònic.</p>
            <br>
            <p>Gràcies,<br>El teu equip de la Biblioteca M. Carmen Brito</p>
        </div>
    </body>
    </html>
    """

    try:
        send_mail(
            subject=mail_subject,
            message='',
            from_email='biblIETI - Biblioteca M. Carmen Brito',
            recipient_list=[email],
            html_message=message,
        )
        InfoLog(email, 'Password Reset Email', 'Correo electrónico de restablecimiento de contraseña enviado exitosamente', '/send_password_reset_email')
    except BadHeaderError:
        ErrorLog('', 'Bad Header Error', 'Error al enviar el correo electrónico', '/send_password_reset_email')
        return Response({'error': 'Ocurrió un error al enviar el correo electrónico'}, status=500)
    return Response({'success': 'Correo electrónico de restablecimiento de contraseña enviado exitosamente'}, status=200)

@api_view(['POST'])
def reset_password(request):
    try:
        uid = force_str(urlsafe_base64_decode(request.data['uid']))
        token = request.data['token']
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        ErrorLog('', 'Invalid Token', 'El enlace para restablecer la contraseña no es válido', '/reset_password')
        return JsonResponse({'error': 'El enlace para restablecer la contraseña no es válido'}, status=401)

    if default_token_generator.check_token(user, token):
        try:
            new_password = request.data['newPassword']
        except KeyError:
            ErrorLog('', 'Missing Password', 'No se proporcionó una nueva contraseña', '/reset_password')
            return JsonResponse({'error': 'No se proporcionó una nueva contraseña'}, status=402)
        user.set_password(new_password)
        user.save()
        InfoLog(user.email, 'Password Reset', 'Contraseña restablecida con éxito', '/reset_password')
        return JsonResponse({'message': 'Contraseña restablecida con éxito'}, status=200)
    else:
        return JsonResponse({'error': 'El enlace para restablecer la contraseña no es válido'}, status=403)


@api_view(['POST'])
def save_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        new_password = data.get('password')

        try:
            user = User.objects.get(username=email)
            user.set_password(new_password)
            return JsonResponse({'message': 'Password updated successfully'}, status=200)
        except User.DoesNotExist:
            return JsonResponse({'message': 'User does not exist'}, status=404)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
@api_view(['GET'])
def autocomplete_search_items(request, query):
    print('search_items -> query:', query)

    results = []

    models_to_search = [
        (Item, ['title', 'material_type', 'signature'])
    ]

    for model, fields in models_to_search:
        for field in fields:
            filter_kwargs = {f"{field}__icontains": query}
            model_results = model.objects.filter(**filter_kwargs)[:5]  # Limitar a 25 resultados
            for obj in model_results:
                results.append({'id': obj.id, 'name': str(obj)})
    return JsonResponse(results, safe=False)

@api_view(['GET'])
def search_items(request, search):
    query = search
    print('search_items -> query:', query)

    results = []

    models_to_search = [
        (Item, ['title', 'material_type', 'signature'])
    ]

    for model, fields in models_to_search:
        for field in fields:
            filter_kwargs = {f"{field}__icontains": query}
            model_results = model.objects.filter(**filter_kwargs)[:25]  # Limitar a 25 resultados
            for obj in model_results:
                results.append({'id': obj.id, 'name': str(obj)})
    return JsonResponse(results, safe=False)

@api_view(['POST'])
def save_csv(request):
    saves = 0
    json_data = json.loads(request.body)
    userAdmin = get_object_or_404(UserProfile, email=json_data.get('email_admin'))
    center = userAdmin.center
    role = get_object_or_404(Role, name='alumne')
    if userAdmin.role.name != 'bibliotecari' and userAdmin.role.name != 'admin':
        return JsonResponse({'error': 'email_admin no coincideix amb un usuari admin'}, status=400)
    user_profiles_data = json_data.get('user_profiles_csv', [])
    errors = []
    if request.method == 'POST':
        for profile_data in user_profiles_data:
            error = False
            name = profile_data.get('nom', '')
            surname = profile_data.get('cognom1', '')
            surname2 = profile_data.get('cognom2', '')
            email = profile_data.get('email', '')
            phone = profile_data.get('telefon', '')
            cycle = profile_data.get('curs', '')
            id_register = str(profile_data.get('id_register', ''))
            
            if not name or not surname or any(char.isdigit() for char in name) or any(char.isdigit() for char in surname):
                error = True
                errors.append({'error':'El nom i el cognom del registre '+ id_register+' no poden estar buits ni contindre numeros'})

        
            if surname2 and any(char.isdigit() for char in surname2):
                error = True
                errors.append({'error':'El segon cognom del registre '+ id_register+' no pot  contindre cap número'})

        
            try:
                validate_email(email)
            except ValidationError:
                error = True
                errors.append({'error':'El email del registre '+ id_register+' no es valid'})

            if User.objects.filter(username=email).exists():
                if UserProfile.objects.filter(email=email,name=name,surname=surname,surname2=surname2,phone=phone,cycle=cycle).exists():
                    error = True
                else:
                    error = True
                    errors.append({'error':'ERROR al registre '+ id_register+': ja existeix un usuari amb email '+email})

            if UserProfile.objects.filter(email=email).exists():
                if UserProfile.objects.filter(email=email,name=name,surname=surname,surname2=surname2,phone=phone,cycle=cycle).exists():
                    error = True
                else:
                    error = True
                    errors.append({'error':'ERROR al registre '+ id_register+': ja existeix un usuari amb email '+email})


            if phone:
                if not any(char.isdigit() for char in phone):
                    error = True
                    errors.append({'error': 'El telefon del registre ' + id_register + ' ha de contidre només números'})



            if not cycle:
                error = True
                errors.append({'error':'El curs del registre '+ id_register+' no pot estar buit'})

            if not error:
                saves += 1
                user = User.objects.create_user(username=email, email=email, password="biblioteca")
                user_profile = UserProfile.objects.create(
                    user=user,
                    name=name,
                    surname=surname,
                    surname2=surname2,
                    email=email,
                    phone=phone,
                    cycle=cycle,
                    center=center,
                    role=role
                )
                user_profile.save()
            
        
        return JsonResponse({'message':str(saves)+' usuaris afegits correctament','errors':errors}, status=201)
    else:
        return JsonResponse({'error': 'Only POST requests are allowed'}, status=400)

@api_view(['POST'])
def make_loan(request):
    json_data = json.loads(request.body)
    user_profile = get_object_or_404(UserProfile, email=json_data.get('email'))
    item_copy_id = json_data.get('item_copy_id')
    return_date = json_data.get('return_date')  

    item_copy = get_object_or_404(ItemCopy, pk=item_copy_id, status="Available")
    item_copy.status = 'Loaned'
    item_copy.save()
    
    loan_date = timezone.now().date()  

    loan = Loan.objects.create(
        user=user_profile,
        copy=item_copy,
        loan_date=loan_date,
        return_date=return_date
    )

    return JsonResponse({'message': 'Préstamo creado exitosamente'}, status=200)

def obtain_item_copies(request, idItem):
    item_copies = ItemCopy.objects.filter(item_id=idItem)
    copies_data = []
    for copy in item_copies:
        copy_data = {
            'id': copy.id,
            'status': copy.status,
            'center_name': copy.center.name if copy.center else None,  # Obtener el nombre del centro si existe
            'item_id':idItem,
            'id_copy':copy.id_copy
        }
        copies_data.append(copy_data)
    return JsonResponse({'copies': copies_data})

@api_view(['GET'])
def get_user_by_email(request, email):
    print('search_items -> query:', email)

    results = []

    users_to_search = [
        (UserProfile, ['email'])
    ]

    for model, fields in users_to_search:
        for field in fields:
            filter_kwargs = {f"{field}__icontains": email}
            model_results = model.objects.filter(**filter_kwargs)
            model_results = model_results.order_by('-email')[:5]  # Sort by email in descending order
            for obj in model_results:
                results.append({'id': obj.id, 'email': str(obj.email)})
                if len(results) >= 5:
                    return JsonResponse(results, safe=False)
    
    return JsonResponse(results, safe=False)  # Return the results even if less than 5 users are found
    