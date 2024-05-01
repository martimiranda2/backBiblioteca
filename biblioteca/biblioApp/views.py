import json,base64,os,re
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from django.core.files.base import ContentFile
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

from .models import Book, CD, Item, Dispositive, Log, User, Role, UserProfile, ItemCopy

from datetime import timedelta,datetime
from rest_framework_simplejwt.settings import api_settings
api_settings.ACCESS_TOKEN_LIFETIME = timedelta(minutes=15)
api_settings.REFRESH_TOKEN_LIFETIME = timedelta(days=1)




def get_user_image(request, user_id):
    if request.method == 'GET':
        try:
            user = User.objects.get(pk=user_id)
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
        
        if user_admin is not None and user_change is not None:
            role_admin = user_admin.role.name
            if role_admin == 'bibliotecari':
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
def search_items_availables(request):
    query = request.GET.get('item', '')
    print('search_items -> query:', query)

    results = []

    models_to_search = [
        (Item, ['title', 'material_type', 'signature'])
    ]

    for model, fields in models_to_search:
        for field in fields:
            filter_kwargs = {f"{field}__icontains": query}
            model_results = model.objects.filter(**filter_kwargs)[:5]
            for obj in model_results:
                if obj.loan_available:
                    if ItemCopy.objects.filter(item=obj, status='Available').exists():
                        results.append({'id': obj.id, 'name': str(obj)})
                        if len(results) >= 5:
                            return JsonResponse(results, safe=False)

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

        # Authenticate the user
        userP = UserProfile.objects.filter(email=email)

        if userP.exists():
            user_profile = userP.first()
            if authenticate(username=user_profile.user.username, password=password):
                token = get_token_by_email_and_password(email, password)
                InfoLog(user_profile, 'new_login', 'Usuario autenticado exitosamente', '/new_login')
                return JsonResponse({'message': 'User Authenticated successfully', 'token': token})
            else:
                WarningLog(None, 'new_login', 'Credenciales incorrectas', '/new_login')
                return JsonResponse({'message': 'Credenciales incorrectas'}, status=401)
        else:
            WarningLog(None, 'new_login', 'Credenciales incorrectas', '/new_login')
            return JsonResponse({'message': 'Incorrect credentials'}, status=401)

    else:
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
        user_data = json.loads(request.body)
        try:
            user_profile = get_object_or_404(UserProfile, email=user_data.get('email_user'))
            
            if 'email_change' in user_data:
                user_profile.email = user_data.get('email_change')
            if 'first_name' in user_data:
                user_profile.name = user_data.get('first_name')
            if 'surname' in user_data:
                user_profile.surname = user_data.get('surname')
            if 'surname2' in user_data:
                user_profile.surname2 = user_data.get('surname2')

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
        (Item, ['title', 'material_type', 'signature'])
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


            if UserProfile.objects.filter(email=email).exists():
                if UserProfile.objects.filter(email=email,name=name,surname=surname,surname2=surname2,phone=phone,cycle=cycle).exists():
                    error = True
                else:
                    error = True
                    errors.append({'error':'El email del registre '+ id_register+' ja existeix com a usuari'})


            if phone:
                if not any(char.isdigit() for char in phone):
                    error = True
                    errors.append({'error': 'El telefon del registre ' + id_register + ' ha de contidre només números'})



            if not cycle:
                error = True
                errors.append({'error':'El curs del registre '+ id_register+' no pot estar buit'})

            if not error:
                saves += 1
                user = User.objects.create_user(username=name+surname, email=email, password="biblioteca")
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
    saves = 0
    json_data = json.loads(request.body)
    userAdmin = get_object_or_404(UserProfile, email=json_data.get('email_admin'))
    return