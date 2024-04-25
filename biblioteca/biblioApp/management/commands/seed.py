

import random,datetime
from datetime import datetime, timedelta
from faker import Faker
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from biblioApp.models import Role,UserProfile, Item, Book, CD, Dispositive, ItemCopy, Reservation, Loan, Request, Log


fake = Faker('es_ES')




class Command(BaseCommand):
    help = 'Seed database with initial data'


    def handle(self, *args, **kwargs):
        seed()

def create_rols():
    roles_data = [
        {"name": "admin"},
        {"name": "alumne"},
        {"name": "profesor"},
        {"name": "bibliotecari"},
    ]
    for role_data in roles_data:
        Role.objects.create(**role_data)

def create_users(num_users=100):
    centers = [
    "Institut Escola del Treball de Barcelona",
    "Institut Jaume Balmes de Barcelona",
    "Institut Lluís Vives de Barcelona",
    "Institut Ramon Berenguer IV de Lleida",
    "Institut Jaume Callís i Franqueta de Granollers",
    "Institut Lauro de Sant Boi de Llobregat",
    "Institut Salvador Espriu de Cornellà de Llobregat",
    "Institut Pau Claris de Barcelona",
    "Institut Sant Josep de Calassanç de Barcelona",
    "Institut de Badalona"
    ]  


    cycles = ["1ESO","2ESO","3ESO","4ESO","1Bachillerat","2Bachillerat","Cicle Grau Mitjà Gestió administrativa", "Cicle Grau Mitjà Electromecànica de vehicles automòbils", "Cicle Grau Mitjà Mecanització","Cicle Grau Mitjà Manteniment electromecànic", "Cicle Grau Mitjà Sistemes microinformàtics i xarxes","Cicle Grau Superior Assistència a la direcció", "Cicle Grau Superior Administració i finances", "Cicle Grau Superior Automoció","Cicle Grau Superior Programació de la producció en fabricació mecànica","Cicle Grau Superior Mecatrònica industrial","Cicle Grau Superior Gestió de l'aigua","Cicle Grau Superior Desenvolupament d'aplicacions multiplataforma", "Cicle Grau Superior Desenvolupament d'aplicacions web"]
    role = Role.objects.get(name="alumne")
   
    for _ in range(num_users):
        surname = fake.last_name()
        name = fake.first_name()
        surname2 = fake.last_name() if random.choice([True, False]) else None
        while True:
            username = fake.user_name()
            if not User.objects.filter(username=username).exists():
                break
        dni_digits = ''.join([str(random.randint(0, 9)) for _ in range(8)])
        dni_letter = 'TRWAGMYFPDXBNJZSQVHLCKE'[int(dni_digits) % 23]
        dni = dni_digits + dni_letter
        email = fake.unique.email()
        phone = fake.phone_number()
        password = fake.password()
        center = random.choice(centers)
        cycle = random.choice(cycles)
        user = User.objects.create_user(username=username, email=email, password=password)
       
        UserProfile.objects.create(
            user=user,
            name=name,
            email=email,
            phone=phone,
            surname=surname,
            surname2=surname2,
            dni=dni,
            role=role,
            date_of_birth=fake.date_of_birth(),
            center=center,
            cycle=cycle,
            image=None
        )








def create_books(num_books=100):
 
    publishers = ["Penguin Books", "Vintage Books", "Simon & Schuster", "Random House", "HarperCollins"]
   
    for _ in range(num_books):

        title = fake.catch_phrase()
        author = fake.name()
        publisher = random.choice(publishers)
        edition_date = fake.date_between(start_date='-50y', end_date='today')
        ISBN = fake.isbn10(separator="-")
        collection = fake.word()
        pages = random.randint(50, 500)  
       
       
        title_words = title.split()
        first_word = title_words[0] if title_words else ""
        author_initials = "".join(word[:3] for word in author.split() if word)  
        signature = f"{first_word[:3]}-{author_initials}" if author_initials else f"{first_word[:3]}"
       
 
        CDU = random.randint(1000000000000, 9999999999999)
       
       
        Book.objects.create(title=title,author=author,edition_date=edition_date,CDU=CDU,ISBN=ISBN,publisher=publisher,colection=collection,pages=pages)






def create_cds(num_cds=100):
    discographies = ["Sony Music Entertainment", "Universal Music Group", "Warner Music Group", "EMI Group Limited", "BMG Rights Management", "Atlantic Records"]
    styles = ["Pop", "Rock", "Hip Hop", "Jazz", "Classical", "Electronic", "R&B", "Reggae", "Country", "Folk"]
   
    for _ in range(num_cds):
        author = fake.name()
        edition_date = fake.date_between(start_date='-50y', end_date='today')
        discography = random.choice(discographies)
        style = random.choice(styles)
        title = fake.catch_phrase()
        title_words = title.split()
        first_word = title_words[0] if title_words else ""
        author_initials = "".join(word[:3] for word in author.split() if word)  
        signature = f"{first_word[:3]}-{author_initials}" if author_initials else f"{first_word[:3]}"
        duration_hours = 0  
        duration_minutes = random.randint(0, 10)
        duration_seconds = random.randint(0, 59)
        duration = f"{duration_hours:02d}:{duration_minutes:02d}:{duration_seconds:02d}"
       
       


        CD.objects.create(title=title, author=author, edition_date=edition_date, discography=discography, style=style, duration=duration)


def create_dispositives(num_dispositives=10):
    brands = ["Apple", "Samsung", "Google", "Microsoft", "Sony", "LG", "Lenovo", "HP", "Dell", "Asus"]
    dispo_types = ["Smartphone", "Tablet", "Laptop", "Smartwatch"]
   
    for _ in range(num_dispositives):
        brand = random.choice(brands)
        dispo_type = random.choice(dispo_types)
       
        while True:
            title = fake.catch_phrase()
            if not Item.objects.filter(title=title).exists():
                break
       
       
        Dispositive.objects.create(brand=brand, dispo_type=dispo_type,title=title)




def create_item_copies(num_copies=600):
    items = Item.objects.all()
    for _ in range(num_copies):
        item = random.choice(items)
        status = random.choice(["Available", "Reserved", "Borrowed"])
        id_copy = fake.uuid4()
        ItemCopy.objects.create(item=item, status=status, id_copy=id_copy)

def create_loans(num_loans=200):
    users = UserProfile.objects.all()
    available_copies = ItemCopy.objects.filter(status='Available')

    if len(users) == 0 or len(available_copies) == 0:
        print("No hay usuarios o copias disponibles para generar préstamos.")
        return

    for _ in range(num_loans):
        user = random.choice(users)
        copy = random.choice(available_copies)

        loan_date = datetime.now()

        return_date = loan_date + timedelta(days=14)

        loan = Loan.objects.create(
            user=user,
            copy=copy,
            loan_date=loan_date,
            return_date=return_date
        )

        copy.status = 'Loaned'
        copy.save()




def seed():
    if not Role.objects.exists():
        create_rols()
    create_users()
    create_books()
    create_cds()
    create_dispositives()
    create_item_copies()
    create_loans()


if __name__ == "__main__":
    seed()

