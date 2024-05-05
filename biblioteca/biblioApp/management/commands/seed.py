

import random,datetime
from datetime import datetime, timedelta
from faker import Faker
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from biblioApp.models import Role,UserProfile,Center, Item, Book, CD, Dispositive, ItemCopy, Reservation, Loan, Request, Log


fake = Faker('es_ES')
titulos_es = {
    "El perro": ["corre felizmente", "ladra a la luna", "persigue su cola"],
    "El gato": ["ronronea suavemente", "juega con un ovillo de lana", "se estira perezosamente"],
    "El pájaro": ["vuela libremente", "canta melodías hermosas", "construye un nido con cuidado"],
    "El niño": ["juega en el parque", "aprende nuevas palabras", "imagina aventuras emocionantes"],
    "La flor": ["baila con el viento", "abre sus pétalos al sol", "perfuma el aire con su aroma"],
    "El río": ["fluye serenamente", "besa las piedras del camino", "refleja el cielo azul"],
    "La montaña": ["se alza majestuosa", "guarda secretos antiguos", "ofrece vistas impresionantes"],
    "La luna": ["brilla en la noche", "observa el mundo dormir", "inspira poesía y romance"],
    "La estrella": ["guiña un ojo desde el firmamento", "ilumina la oscuridad", "concede deseos a los soñadores"],
    "El mar": ["susurra secretos al viento", "acaricia la arena con sus olas", "navega hacia el horizonte"],
    "El sol": ["ilumina el día con su resplandor", "calienta la tierra con su luz", "pinta el cielo de colores al atardecer"],
    "La lluvia": ["refresca la tierra sedienta", "baila sobre los tejados", "nutre la vida con su caída"],
    "El viento": ["susurra historias en las hojas", "acaricia el rostro con su suave brisa", "trae noticias de tierras lejanas"],
    "El bosque": ["susurra misterios en cada rincón", "abriga a los animales con su sombra", "resuena con cantos de aves"],
    "El amor": ["embriaga el corazón con su dulce néctar", "une almas en un abrazo eterno", "despierta emociones profundas"],
    "La amistad": ["brinda apoyo en los momentos difíciles", "comparte risas y lágrimas", "teje lazos que perduran"],
    "La noche": ["envuelve el mundo en su manto oscuro", "inspira sueños y fantasías", "guarda secretos bajo las estrellas"],
    "El fuego": ["enciende pasiones ardientes", "calienta el hogar con su calor", "danza libremente en la oscuridad"],
    "La esperanza": ["ilumina el camino en la oscuridad", "alienta los corazones cansados", "nunca se extingue"],
    "La aventura": ["llama desde el horizonte", "despierta la curiosidad en el alma", "promete experiencias inolvidables"],
    "El trueno": ["retumba en el cielo", "electriza el aire con su energía", "anuncia la llegada de la tormenta"],
    "La montaña": ["se alza majestuosa", "guarda secretos antiguos", "ofrece vistas impresionantes"],
    "La neblina": ["envuelve el paisaje en misterio", "dibuja figuras fantasmales en la distancia", "acaricia la piel con su frescura"],
    "El río": ["serpentea entre los árboles", "canta su canción de agua", "refresca la tierra con su corriente"],
    "El tiempo": ["se desliza silenciosamente", "cuenta historias en las arrugas", "borra y crea recuerdos"],
    "La primavera": ["despierta la vida en la tierra", "pinta los campos de flores", "llena el aire con su perfume"],
    "El otoño": ["pinta el paisaje con colores cálidos", "susurra secretos de cambio en el viento", "prepara el mundo para el descanso del invierno"],
    "El invierno": ["envuelve todo en su manto blanco", "susurra cuentos de hielo y nieve", "congela el tiempo en un abrazo frío"],
    "La vida": ["es un lienzo en blanco esperando ser pintado", "es un viaje lleno de sorpresas", "es una aventura que espera ser vivida"],
    "El destino": ["teje hilos invisibles entre las personas", "escribe historias en las estrellas", "dirige el curso de nuestras vidas"],
    "La pasión": ["ardie en el corazón", "enciende el alma con su fuego", "inspira grandes hazañas"],
    "El silencio": ["habla con el lenguaje de la calma", "encierra secretos en su abrazo", "concede paz al espíritu"],
    "La tormenta": ["trona en el cielo con furia", "lava el mundo con lluvia purificadora", "saca a relucir la fortaleza oculta en el alma"],
    "El arco iris": ["pinta el cielo con sus colores", "une el cielo y la tierra en un abrazo de luz", "es el tesoro al final de la lluvia"],
    "La brisa": ["acaricia la piel con su suavidad", "susurra secretos del mar", "refresca el aire en los días calurosos"],
    "El destino": ["escribe caminos en la arena", "guiña un ojo desde el futuro", "teje historias con hilos de tiempo"],
    "La fe": ["moverá montañas", "iluminará el camino en la oscuridad", "sostendrá el alma en tiempos difíciles"],
    "La libertad": ["es volar sin cadenas", "es bailar bajo la lluvia sin temor", "es ser quien realmente eres"],
    "El recuerdo": ["es un tesoro guardado en el corazón", "es un faro en la noche oscura", "es un puente hacia el pasado"],
    "La sonrisa": ["es el lenguaje universal del amor", "es el sol que ilumina el día más oscuro", "es música para el alma"],
    "La melancolía": ["teje nostalgias en el corazón", "susurra tristezas en el viento", "es un eco del pasado"],
    "La fortuna": ["es un tesoro escondido en el camino", "es una sorpresa en cada esquina", "es la sonrisa de la suerte"],
    "El secreto": ["es la llave del misterio", "es el susurro en la noche", "es la luz en la oscuridad"],
    "El abrazo": ["es el refugio en la tormenta", "es el lazo que une corazones", "es el lenguaje del amor sin palabras"],
    "La tristeza": ["es la lluvia que lava el alma", "es el viento que susurra pesares", "es el ocaso en el horizonte"],
    "El amanecer": ["pinta el cielo con colores de esperanza", "despierta el mundo con su luz dorada", "es el renacer de un nuevo día"],
    "La medianoche": ["es el reino de los sueños", "es el susurro de los secretos", "es el momento de la magia"],
    "El amuleto": ["guarda la suerte en su corazón", "es el protector de los viajeros", "es el talismán de los sueños"],
    "La fantasía": ["es el mundo detrás del espejo", "es el vuelo del dragón en el cielo estrellado", "es el viaje a tierras lejanas"],
    "La aurora boreal": ["pinta el cielo con pinceladas de luz", "es la danza de las estrellas en el firmamento", "es el espectáculo celestial"],
    "El castillo": ["guarda historias en sus muros", "es el reino de los sueños", "es el hogar de la fantasía"],
    "La alondra": ["canta al sol en su vuelo matutino", "es el eco del amanecer en el cielo azul", "es el símbolo de la libertad"],
    "El tesoro": ["guarda riquezas más allá del oro", "es el sueño de los aventureros", "es el misterio de los piratas"],
    "La sabiduría": ["es la luz en la oscuridad", "es el camino hacia la verdad", "es la voz de la experiencia"],
    "El susurro": ["es la canción del viento en los árboles", "es el secreto compartido en la noche", "es el rumor de las estrellas en el cielo"],
    "La promesa": ["es un lazo que une corazones", "es una luz en el horizonte", "es una flor que florece en el jardín del amor"],
    "El eco": ["es la voz del pasado que resuena en el presente", "es el reflejo de los sueños en el agua", "es el eco del corazón en la montaña"],
}

titulos_ca = {
    "El gos": ["corre alegrement", "lliadra a la lluna", "persegueix la seva cua"],
    "El gat": ["ronroneja suavement", "juga amb un ovell de llana", "s'estira despreocupadament"],
    "L'ocell": ["vola lliurement", "canta melodies precioses", "construeix un niu amb cura"],
    "El nen": ["juga al parc", "apren noves paraules", "imagina aventures emocionants"],
    "La flor": ["balla amb el vent", "obre els seus pètals al sol", "perfuma l'aire amb el seu aroma"],
    "El riu": ["flueix serenament", "besa les pedres del camí", "reflexa el cel blau"],
    "La muntanya": ["s'alça majestuosa", "guarda secrets antics", "ofereix vistes impressionants"],
    "La lluna": ["brilla a la nit", "observa el món dormir", "inspira poesia i romance"],
    "L'estrella": ["guiña un ull des del firmament", "il·lumina la foscor", "concedeix desitjos als somiadors"],
    "El mar": ["xiuxiueja secrets al vent", "acaricia la sorra amb les seves ones", "navega cap a l'horitzó"],
    "El sol": ["il·lumina el dia amb el seu resplendor", "escalfa la terra amb la seva llum", "pinta el cel de colors al capvespre"],
    "La pluja": ["refresca la terra sedienta", "balla sobre els teulats", "nutreix la vida amb la seva caiguda"],
    "El vent": ["xiuxiueja històries en les fulles", "acaricia el rostre amb la seva brisa suau", "porta notícies de terres llunyanes"],
    "El bosc": ["xiuxiueja misteris a cada racó", "abraca els animals amb la seva ombra", "resona amb cants d'ocells"],
    "L'amor": ["embriaga el cor amb el seu dolç nèctar", "uneix ànimes en un abraç etern", "desperta emocions profundes"],
    "L'amistat": ["ofereix suport en els moments difícils", "comparteix rialles i llàgrimes", "teixeix llaços que perduren"],
    "La nit": ["envolta el món amb el seu mantell fosc", "inspira somnis i fantasies", "guarda secrets sota les estrelles"],
    "El foc": ["encén passions ardents", "escalfa el llar amb el seu calor", "dansa lliurement a la foscor"],
    "L'esperança": ["il·lumina el camí a la foscor", "alenta els cors cansats", "mai s'extingeix"],
    "L'aventura": ["crida des de l'horitzó", "desperta la curiositat a l'ànima", "promet experiències inoblidables"],
    "El tro": ["retumb al cel amb fúria", "electritza l'aire amb la seva energia", "anuncia l'arribada de la tempesta"],
    "La boira": ["envolta el paisatge en misteri", "dibuixa figures fantasmals a la distància", "acaricia la pell amb la seva frescor"],
    "El rierol": ["serpenteja entre els arbres", "canta la seva cançó d'aigua", "refresca la terra amb la seva corrent"],
    "El temps": ["esllavissa silenciosament", "explica històries en les arrugues", "esborra i crea records"],
    "La primavera": ["desperta la vida a la terra", "pinta els camps de flors", "omple l'aire amb el seu perfum"],
    "La tardor": ["pinta el paisatge amb colors càlids", "xiuxiueja secrets de canvi en el vent", "prepara el món per al descans de l'hivern"],
    "L'hivern": ["envolta tot en el seu mantell blanc", "xiuxiueja contes de gel i neu", "congela el temps en una abraçada freda"],
    "La vida": ["és un llenç en blanc esperant ser pintat", "és un viatge ple de sorpreses", "és una aventura que espera ser viscuda"],
    "El destí": ["teixeix fils invisibles entre les persones", "escriu històries en les estrelles", "dirigeix el curs de les nostres vides"],
    "La passió": ["ard el cor", "encén l'ànima amb el seu foc", "inspira grans fites"],
    "El silenci": ["parla amb el llenguatge de la calma", "enclau secrets en el seu abraç", "concedeix pau a l'esperit"],
    "La tempesta": ["tron al cel amb furor", "renta el món amb pluja purificadora", "treu a relleu la fortalesa oculta en l'ànima"],
    "L'arc de Sant Martí": ["pinta el cel amb els seus colors", "uneix el cel i la terra en una abraçada de llum", "és el tresor al final de la pluja"],
    "La brisa": ["acaricia la pell amb la seva suavitat", "xiuxiueja secrets del mar", "refresca l'aire en els dies calorosos"],
    "La fe": ["mou muntanyes", "il·lumina el camí a la foscor", "sosté l'ànima en temps difícils"],
    "La llibertat": ["és volar sense cadenes", "és ballar sota la pluja sense por", "és ser qui realment ets"],
    "El record": ["és un tresor guardat al cor", "és un fanal a la nit fosca", "és un pont cap al passat"],
    "El somriure": ["és el llenguatge universal de l'amor", "és el sol que il·lumina el dia més fosc"]
    }




class Command(BaseCommand):
    help = 'Seed database with initial data'


    def handle(self, *args, **kwargs):
        seed()


def create_centers():
    num_centros = Center.objects.count()

    if num_centros < 4:
        for i in range(4 - num_centros):
            nombre_centro = fake.company()
            Center.objects.create(name=nombre_centro)

def create_rols():
    roles_data = [
        {"name": "admin"},
        {"name": "biblio"},
        {"name": "user"},
    ]
    for role_data in roles_data:
        Role.objects.create(**role_data)

def create_users(num_users=100):


    cycles = ["1ESO","2ESO","3ESO","4ESO","1Bachillerat","2Bachillerat","Cicle Grau Mitjà Gestió administrativa", "Cicle Grau Mitjà Electromecànica de vehicles automòbils", "Cicle Grau Mitjà Mecanització","Cicle Grau Mitjà Manteniment electromecànic", "Cicle Grau Mitjà Sistemes microinformàtics i xarxes","Cicle Grau Superior Assistència a la direcció", "Cicle Grau Superior Administració i finances", "Cicle Grau Superior Automoció","Cicle Grau Superior Programació de la producció en fabricació mecànica","Cicle Grau Superior Mecatrònica industrial","Cicle Grau Superior Gestió de l'aigua","Cicle Grau Superior Desenvolupament d'aplicacions multiplataforma", "Cicle Grau Superior Desenvolupament d'aplicacions web"]
    role = Role.objects.get(name="alumne")

    center_name = "IES Esteve Terradas I Illa"
    center, created = Center.objects.get_or_create(name=center_name)
   
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
        while True:
            email = fake.unique.email()
            if not User.objects.filter(email=email).exists():
                break
        phone = fake.phone_number()
        password = fake.password()
        center = center
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
        language = random.choice(['ca','es','en'])
        if language=='es':
            sujeto = random.choice(list(titulos_es.keys()))
            predicado = random.choice(titulos_es[sujeto])
            title = sujeto + " " + predicado
        elif language=='en':
            title = fake.catch_phrase()
        elif language=='ca':
            sujeto = random.choice(list(titulos_ca.keys()))
            predicado = random.choice(titulos_ca[sujeto])
            title = sujeto + " " + predicado
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
       
       
        Book.objects.create(title=title,language=language,author=author,edition_date=edition_date,CDU=CDU,ISBN=ISBN,publisher=publisher,colection=collection,pages=pages)






def create_cds(num_cds=100):
    discographies = ["Sony Music Entertainment", "Universal Music Group", "Warner Music Group", "EMI Group Limited", "BMG Rights Management", "Atlantic Records"]
    styles = ["Pop", "Rock", "Hip Hop", "Jazz", "Classical", "Electronic", "R&B", "Reggae", "Country", "Folk"]
   
    for _ in range(num_cds):
        author = fake.name()
        edition_date = fake.date_between(start_date='-50y', end_date='today')
        discography = random.choice(discographies)
        style = random.choice(styles)
        language = random.choice(['ca','es','en'])
        if language=='es':
            sujeto = random.choice(list(titulos_es.keys()))
            predicado = random.choice(titulos_es[sujeto])
            title = sujeto + " " + predicado
        elif language=='en':
            title = fake.catch_phrase()
        elif language=='ca':
            sujeto = random.choice(list(titulos_ca.keys()))
            predicado = random.choice(titulos_ca[sujeto])
            title = sujeto + " " + predicado
        title_words = title.split()
        first_word = title_words[0] if title_words else ""
        author_initials = "".join(word[:3] for word in author.split() if word)  
        signature = f"{first_word[:3]}-{author_initials}" if author_initials else f"{first_word[:3]}"
        duration_hours = 0  
        duration_minutes = random.randint(0, 10)
        duration_seconds = random.randint(0, 59)
        duration = f"{duration_hours:02d}:{duration_minutes:02d}:{duration_seconds:02d}"
       
       


        CD.objects.create(title=title,language=language, author=author, edition_date=edition_date, discography=discography, style=style, duration=duration)


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
    centers = Center.objects.all()
    for _ in range(num_copies):
        item = random.choice(items)
        status = random.choice(["Available"])
        id_copy = fake.uuid4()
        center = random.choice(centers)
        if center:
            ItemCopy.objects.create(item=item, status=status, id_copy=id_copy, center=center)
        else:
            print("No hay centros disponibles para asignar al ItemCopy.")

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
    create_centers()
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

