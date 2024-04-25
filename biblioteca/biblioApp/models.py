from django.db import models
from django.contrib.auth.models import User


class Role(models.Model):
    name = models.CharField(max_length=50 , verbose_name="Nom del rol")


    class Meta:
        verbose_name = "Rol"
        verbose_name_plural = "Rols"


    def __str__(self):
        return self.name


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE , verbose_name="Usuari")
    email = models.EmailField(unique=True, verbose_name="Correu electrònic")
    name = models.CharField(max_length=100 , verbose_name="Nom")
    surname = models.CharField(max_length=100 , verbose_name="Cognom")
    surname2 = models.CharField(max_length=100 , verbose_name="Segon cognom (opcional)", blank=True, null=True)
    dni =  models.CharField(max_length=9, unique=True,blank=True, null=True, verbose_name='DNI')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, verbose_name="Rol d'usuari")
    date_of_birth = models.DateField(verbose_name="Data de naixement")
    center = models.CharField(max_length=100 , verbose_name="Centre al que pertany")
    cycle = models.CharField(max_length=100 , verbose_name="Curs al que pertany")
    image = models.ImageField(upload_to='user_images/', blank=True, null=True , verbose_name="Imatge de perfil")


    class Meta:
        verbose_name = "Perfil d'usuari"
        verbose_name_plural = "Perfils d'usuari"


    def __str__(self):
        return self.user.username






class Item(models.Model):
    title = models.CharField(max_length=100 , verbose_name="Títol del item")    
    material_type = models.TextField(max_length=100, verbose_name="Material del que es composa")  
    signature = models.CharField(max_length=100, verbose_name="Signatura")  


    class Meta:
        verbose_name = "Item del catàlog"
        verbose_name_plural = "Items dels catàlogs"


    def __str__(self):
        return self.title




class Book (Item):
    author = models.CharField(max_length=100 , verbose_name="Autor del item")
    edition_date = models.DateField(verbose_name="Data de l'edició")
    CDU = models.TextField(max_length=100)
    ISBN = models.TextField(max_length=13)
    publisher = models.CharField(max_length=100, verbose_name="Editorial")
    colection = models.CharField(max_length=100, verbose_name="Col·lecció")
    pages = models.PositiveIntegerField(verbose_name="Pàgines")


    class Meta:
        verbose_name = "Llibre"
        verbose_name_plural = "Llibres"


class CD(Item):
    author = models.CharField(max_length=100 , verbose_name="Autor del item")
    edition_date = models.DateField(verbose_name="Data de l'edició")
    discography = models.CharField(max_length=100, verbose_name="Discografía")
    style = models.CharField(max_length=100, verbose_name="Estil")
    duration = models.TimeField(verbose_name="Duració")
   


    class Meta:
        verbose_name = "CD"
        verbose_name_plural = "CD's"


    def __str__(self):
        return self.title


class Dispositive(Item):
    brand = models.CharField(max_length=100, verbose_name="Marca del dispositiu")
    dispo_type = models.CharField(max_length=100, verbose_name="Tipus de dispositiu")


    class Meta:
        verbose_name = "Dispositiu"
        verbose_name_plural = "Dispositius"


    def __str__(self):
        return self.title


class ItemCopy(models.Model):
    item = models.ForeignKey(Item, on_delete=models.CASCADE , verbose_name="Item")
    status = models.CharField(max_length=20, default='Available' , verbose_name="Disponibilitat")
    id_copy = models.CharField(max_length=100, verbose_name="Id del exemplar")


    class Meta:
        verbose_name = "Exemplar del item"
        verbose_name_plural = "Exemplars dels items"


    def __str__(self):
        return self.item.title
 


class Reservation(models.Model): #RESERVA
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, verbose_name="Usuari")
    copy = models.ForeignKey(ItemCopy, on_delete=models.CASCADE, verbose_name="Exemplar")
    reservation_date = models.DateField(auto_now_add=True , verbose_name="Data de la reserva")


    class Meta:
        verbose_name = "Reserva"
        verbose_name_plural = "Reserves"


    def __str__(self):
        return self.name


class Loan(models.Model): #PRESTEC
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, verbose_name="Usuari")
    copy = models.ForeignKey(ItemCopy, on_delete=models.CASCADE, verbose_name="Exemplar")
    loan_date = models.DateField(auto_now_add=True, verbose_name="Data de la solicitud del prèstec")
    return_date = models.DateField(null=True, blank=True, verbose_name="Data del final del prèstec")


    class Meta:
        verbose_name = "Prèstec"
        verbose_name_plural = "Prèstecs"


    def __str__(self):
        return self.name


class Request(models.Model): #PETICIO
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, verbose_name="Usuari")
    request_date = models.DateField(auto_now_add=True, verbose_name="Data de la petició")
    request_text = models.TextField(verbose_name="Descripció de la petició")


    class Meta:
        verbose_name = "Peticions"
        verbose_name_plural = "Petició"


    def __str__(self):
        return self.name


class Log(models.Model):
    user = models.ForeignKey(UserProfile, null=True, blank=True, on_delete=models.CASCADE)
    log_level = models.CharField(max_length=1000)
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=1000)
    route = models.CharField(max_length=100)
    date = models.DateTimeField(auto_now_add=True)
    class Meta:
        verbose_name = "Log"
        verbose_name_plural = "Logs"
    def __str__(self):
        return self.title













