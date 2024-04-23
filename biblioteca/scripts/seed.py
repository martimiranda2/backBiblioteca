
import random
from faker import Faker
from django.contrib.auth.models import User
from biblioApp.models import Role, Item, Book, CD, Dispositive, ItemCopy, Reservation, Loan, Request, Log

fake = Faker()


def create_users(num_users=10):
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
    roles = Role.objects.all()
    
    for _ in range(num_users):
        name = fake.first_name()
        surname = fake.last_name()
        surname2 = fake.last_name() if random.choice([True, False]) else None
        username = fake.user_name()
        email = fake.email()
        password = fake.password()
        role = random.choice(roles)
        center = random.choice(centers)
        cycle = random.choice(cycles)
        
        user = User.objects.create_user(username=username, email=email, password=password)
        User.objects.create(user=user, name=name, surname=surname, surname2=surname2, role=role, date_of_birth=fake.date_of_birth(), center=center, cycle=cycle, image=None)




def create_books(num_books=20):
    titles = ["To Kill a Mockingbird", "1984", "The Great Gatsby", "Pride and Prejudice", "Harry Potter and the Philosopher's Stone", "The Catcher in the Rye", "The Hobbit", "Fahrenheit 451", "Animal Farm", "The Lord of the Rings",
              "Brave New World", "The Catcher in the Rye", "The Fellowship of the Ring", "One Hundred Years of Solitude", "The Hitchhiker's Guide to the Galaxy", "Crime and Punishment", "The Hunger Games", "The Da Vinci Code", "Moby-Dick", "Frankenstein"]
    authors = ["Harper Lee", "George Orwell", "F. Scott Fitzgerald", "Jane Austen", "J.K. Rowling", "J.D. Salinger", "J.R.R. Tolkien", "Ray Bradbury", "George Orwell", "J.R.R. Tolkien",
               "Aldous Huxley", "J.D. Salinger", "J.R.R. Tolkien", "Gabriel Garcia Marquez", "Douglas Adams", "Fyodor Dostoevsky", "Suzanne Collins", "Dan Brown", "Herman Melville", "Mary Shelley"]
    publishers = ["Penguin Books", "Vintage Books", "Simon & Schuster", "Random House", "HarperCollins"]
    
    selected_titles = []
    
    for _ in range(num_books):
        while True:
            title = random.choice(titles)
            if title not in selected_titles:
                selected_titles.append(title)
                break
        
        author = random.choice(authors)
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
        
        item = Item.objects.create(title=title, material_type="Paper", signature=signature)
        
        Book.objects.create(author=author, edition_date=edition_date, CDU=CDU, ISBN=ISBN, publisher=publisher, collection=collection, pages=pages, item=item)



def create_cds(num_cds=20):
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
        
        item = Item.objects.create(title=title, material_type="Plàstic", signature=signature)
        

        CD.objects.create(author=author, edition_date=edition_date, discography=discography, style=style, duration=duration, item=item)

def create_dispositives(num_dispositives=10):
    brands = ["Apple", "Samsung", "Google", "Microsoft", "Sony", "LG", "Lenovo", "HP", "Dell", "Asus"]
    dispo_types = ["Smartphone", "Tablet", "Laptop", "Smartwatch"]
    
    for _ in range(num_dispositives):
        brand = random.choice(brands)
        dispo_type = random.choice(dispo_types)
        
        while True:
            title = fake.catch_phrase()
            if not Dispositive.objects.filter(item__title=title).exists():
                break
        
        item = Item.objects.create(title=title, material_type="Plàstic")
        
        Dispositive.objects.create(brand=brand, dispo_type=dispo_type, item=item)


def create_item_copies(num_copies=60):
    items = Item.objects.all()
    for _ in range(num_copies):
        item = random.choice(items)
        status = random.choice(["Available", "Reserved", "Borrowed"])
        id_copy = fake.uuid4()
        ItemCopy.objects.create(item=item, status=status, id_copy=id_copy)

def seed():
    create_users()
    create_books()
    create_cds()
    create_dispositives()
    create_item_copies()

if __name__ == "__main__":
    seed()
