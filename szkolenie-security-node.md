
# Zalecenia i wytyczne dla bezpiecznych aplikacji i infrastruktury 

## Kontrola nowych bibliotek i podatności
### Sprawdzanie zależności
- ncu (npm-check-updates)
> ostrożnie z przełącznikiem `-u`
- npm audit
- npm audit fix
- instalacja typu clean slate `npm ci`
- dotykanie package-lock.json - czujność
- plik blokady - kopiuj go do repozytorium jeśli naprawdę jesteś tego świadomy, że robiłeś zmiany w konfiguracji, dogrywałeś nowe biblioteki
- aktualizuj często swój system npm komendą `npm i -g npm`
- każde zmiany - git pull - w pliku package.json odnotowywuj u siebie i zrób ponowną instalację pakietów po uprzedni skasowaniu katalogu bibliotek `rimraf node_modules`
- blokuj zależności na koniec projektu komendą `npm shrinkwrap`
- pliku `.npmrc` nie przenosimy do repozytorium

### Nie wierzymy wszystkiemu co w rejestrach NPM-a
- moduł rimrafall ;-)
- sprawdzamy daty modyfikacji
- czy autor jeszcze wspiera swój moduł
- czy moduł nie widnieje na liście podatności 
- czy moduł nie jest `deprecated`
- czy pasuje do technologii - `Type Script` czy `JS`
- jeśli moduł `JS` to jaki typ modułu - `commonjs (CJS)`, `AMD`, `UMD` czy `ESM` - to ważne
- jeśli `Type Script`, czy posiada definicje `@types`  
- czy przeznaczony jest do node.js czy do browsera
- jakie zdanie na temat modułu ma społeczność (ilość pobrań z npm-a)

### Używamy narzędzi ze środka projektu nie globalnie
- `npx abc`
- skrypty - np. `npm run abc`
- `ngx ng run lint` nie `ng run lint`

### Wersja silnika
- istotna wersja **node.js** - pracujemy na `12.18.3 LTS`
- w kontenerze docelowym korzystamy z `node:12.18.3-alpine`
- wersje **nie LTS** nie nadają się na produkcję
- z najnowszej wersji node.js nie korzysta się produkcyjnie
- z wersji nieparzystych nie korzysta się wcale


## Obsługa TLS (SSL)
- nie wprowadzamy do naszych aplikacji obsługi HTTPS - zapewniają to inne mechanizmy zgromadzone "przed" aplikacją jak np. proxy, loadbalancer itp.
- nie wprowadzamy do naszej aplikacji "na sztywno" kluczy i certyfikatów TLS witryny/domeny



## Prawidłowe numerowanie aplikacji
- sprawdzenie wersji aplikacji `npm version`
- po drobnych zmianach w kodzie `npm version patch`
- po znacznej zmianie/funkcjonalności `npm version minor`
- przy całkowitej niekompatybilności w dół `npm version major`
- trzymamy się oznaczeń standardu SemVer
- daszki i tyldy - warto wiedzieć na co załapuje się definicja - Sem Ver Calculator https://semver.npmjs.com/
- przy każdej zmianie - uzupełnienie CHANGELOG.md
- utrzymujemy wpisy w CHANGELOG zgodnie ze standardem - podział na: `Added`, `Changed`, `Removed`, `Fixed`, `Deprecated`, `Security` - opis z datą i wersją

## Pilnowanie trybu instalatora i kodu blokady
- package-lock.json to znaczy, że używamy `npm`
- yarn.lock to zbaczy, że używamy `yarn`
- nie mieszamy instalatorów - jak wgraliśmy `npm i` to nie robimy `yarn add ...`, jak zrobiliśmy `yarn` to nie dodajemy przez `npm i --save ...` lub `npm i --savew-dev ...`


### Pakiety w pliku `package.json` są w dwóch trybach
- devDependecies
- dependecies produkcyjne

### Metadane projektu w `package.json`
- nazwa aplikacji
- wersja aplikacji
- opis aplikacji
- typ licencji
- autor
- współpracownicy  -> `prawa autorskie`
- punkt wejścia aplikacji
- położenie repozytorium
- silnik node.js
- typ projektu
- skrypty



### Decyzja, który pakiet kiedy potrzebny
- produkcja / zawsze 

    `npm i abc --save` 

    lub 

    `yarn add abc`
- development

     `npm i abc --save-dev`
     
    lub
      
    `yarn add abc --dev`

## Na produkcji tylko instalacja produkcyjnych zależności i odpowiednie środowisko
- instalacja produkcyjna **npm**:

    `npm i` i `npm prune --production`
- instalacja produkcyjna **yarn**: 

    `yarn install --production --ignore-scripts --prefer-offline` 
- odpowiednie środowisko dla yarn-a `npm config set scripts-prepend-node-path true`
- środowisko uruchomieniowe produkcyjne 
    `NODE_ENV=production`
- środowisko uruchomieniowe developerskie
    `NODE_ENV=development`

- na produkcji **nie uruchamiamy** aplikacji za pomocą `npm ...` tylko czystej komendy `node ...`


## Zmienne ENV i plik .env
- nie wprowdzamy pliku `.env` do repozytorium **nigdy**
- nie wpisujemy adresów serwerów, loginów, haseł, kluczy, nr portów itp. do środka kodu - wszystko ma być w konfiguracyjnym pliku i pobierane w aplikacji.
np. `export abc=100` jako `process.env.abc` a w pliku `.env` jako 
    ````sh
    abc=100
    ````
- wszystkie możliwe do wykorzystania zmienne w aplikacji wprowadzamy w formie pustej definicji do pliku `env.skeleton` np.
    ```sh
    APPTITLE=
    PORT=
    ....
    ```
- do pliku `.env` i do `env.skeleton` nie wprowadzamy żadnych komentarzy
- do pliku `env.skeleton` nie wprowadzamy żadnych danych/haseł itp. oprócz nazw wszystkich kluczy możliwych do użycia z aplikacją
- nazwa klucza w pliku `.env` nie powinna budzić wątpliwości do czego służy i nie wymagać komentarza

- sprawdzanie poprawności pliku konfiguracji w kodzie

    ```js
    import dotenv from 'dotenv';
    const validconfig = dotenv.config({ path: '.env' });

    if (validconfig.error) {
    throw 'The environment of file (.env) not found...';
    }

    ```
- kontrola potrzebnych zmiennych, bez których aplikacja nie ma sensu się uruchamiać

    ```js
    const cfg = get(validconfig, 'parsed', null);

    // Sprawdzamy wszystkie nasze zmienne, których brak, spowoduje błąd aplikacji przy starcie jak i przy dalszej pracy funkcji w głębi aplikacji

    if (!process.env.PORT || !process.env.APPTITLE || !process.env.JWT_TOKEN ... etc...) {
    throw 'The environment is invalid ...';
    }
    ```
    > <p style="color: red">Jeśli jakikolwiek składnik aplikacji nie działa, aplikacja ma ukończyć działanie.</p>
- Konwertuj dane ze zmiennych ENV - np. cyfry, bo wszystko jest "ciągiem znakowym"
    ```js
     parseInt(process.env.PORT, 10));
    ```


## Ochrona dla Express-a
### Zestaw reguł Helmet
- obsług CSP - *Content-Security-Policy*
- wyłączenie *X-Powered-by*
- hsts *Strict-Transport-Security*
- ieNoOpen *X-Download-Options*
- noCache *Cache-Control*
- noSniff *X-Content-Type-Options*
- frameguard *X-Frame-Options*
- xssFilter *X-XSS-Protection*

Przykład CSP:
```js
import helmet from 'helmet';
...
app.use(
      helmet.contentSecurityPolicy({
        directives: {
          defaultSrc: ['self', 'localhost:*', 'w.x.y.z:*', 'google.com'],
          scriptSrc: ['self', 'localhost:*', 'w.x.y.z:*', 'google.com'],
          styleSrc: ['self', 'localhost:*', 'w.x.y.z:*', 'google.com'],
          fontSrc: ['self', 'localhost:*', 'w.x.y.z:*', 'google.com'],
          imgSrc: ['self', 'localhost:*', 'w.x.y.z:*', 'google.com'],
          connectSrc: ['self', 'localhost:*', 'w.x.y.z:*', 'google.com'],
        },
      }),
    );
...
```
### Zapobieganie przyjmowania klientów/kolejnych zadań podczas zaliczenia błędu
- moduł `stoppable`

### Ochrona przed HTTP Parameter Pollution
```js
import hpp from 'hpp';
...
app.use(hpp());
...

```

### Zestaw reguł Lusca

```js
import lusca from 'lusca';
...
//  Cross Site Request Forgery
app.use(lusca.csrf());

//  Content Security Policy 
app.use(lusca.csp({ /* ... */}));

//  X-FRAME-OPTIONS headers 
app.use(lusca.xframe('SAMEORIGIN'));

// Platform for Privacy Preferences (P3P) 
app.use(lusca.p3p('ABCDEF'));

// HTTP Strict Transport Security
app.use(lusca.hsts({ maxAge: 31536000 }));

// X-XSS-Protection headers 
app.use(lusca.xssProtection(true));

//  X-Content-Type-Options header 
app.use(lusca.nosniff());

//  Referrer-Policy header
app.use(lusca.referrerPolicy('same-origin'));
...
```

### CORS - Cross-Origin Resource Sharing

```js
import cors from 'cors'; 
...
app.use(cors());
...
```

### Kompresja

```js
import compression from 'compression';
...
app.use(compression());
...
```

### Limitowanie danych na wejściu
```js
import * as bodyParser from 'body-parser'; 
...
app.use(bodyParser.json({ limit: '1kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '1kb' }));
...
```
### Bezpieczne ciastka
- zmiana fabrycznej nazwy sesji (nie *connect.sid*)
- ciastko w dostępie HTTPS (*secure*)
- manipulacja tylko z klienta http (*httpOnly*)
- czas życia (*maxAge*)
### Ataki brute force - blokady/dławiki
- rate-limiter-flexible
- koszyk z punktami

    ```js
    const rateLimiter = new RateLimiterMemory({ points: 5, duration: 60 });

        const ratLoginLimiterMiddleware = (req: Request, res: Response, next: NextFunction) => {
        if (req.url.match(/auth/)) {
            rateLimiter
            .consume('login-' + req.ip, 1)
            .then(() => {
                next();
            })
            .catch(() => {
                this.app.logger.warn({
                level: 'verbose',
                message: 'Too Many Requests - Auth point',
                client: req.ip,
                point: req.url,
                dtrack: req.dtrack,
                });
                res.status(429).send('Too Many Requests');
            });
        } else {
            next();
        }

    ```

### Zabezpieczenie CSRF
- csurf
### Ochrona REGEX-ów
- safe-regex

### Ciężkie pliki, pliki statyczne, assetsy
  - przenieś je poza obsługę aplikacji na reverse-proxy
  - rozdziel aplikację od statycznych zasobów frontendowych
  - w procesie budowania aplikacji, zabrać pliki assetsów na katalogi reverse-proxy

### Chroń czas pracy procesora
   - operacja która jest "ciężka" idzie w tło jako fork
   - operacja która sie nie udaje - połączenie z bazą itp. - wyrzuć wyjątek, nie próbuj w nieskończoność, nie wprowadzaj żadnych interwałów
   - nie podtrzymuj sztucznie życia aplikacji
   - gdy operacja zagraża stabilności innych sąsiadujących wątków - wyrzuć wyjątek i zakończ aplikację
   - naruszenie przestrzeni użytkownika - wyrzuć wyjątek i zakończ aplikację

### Zużywaj wszyskie dostępne CPU
   - UV_THREADPOOL_SIZE
   - PM2 lub Kubernetes

### Chroń zasoby pamięci
   - limity sterty i stosu - różnica między 32 a 64-bitowym systemem, różnica względem wersji node.js - [HEAP](https://raw.githubusercontent.com/pwnpsasin/njs_koszalin_2019/39adfb7405df655d2f74e162b842f908ed9ecc7c/EXAMPLES/S02_EX_01/ram_test.js)
   - sterta i stos nie są "z gumy"
   - powiększanie przełącznikami, to nie metoda na problemy z wydajnością
   - ustal granice wytrzymałości aplikacji i poziom akceptowalnego opóźnienia np. 100 klientów na sekundę z czasem odpowiedzi 2 sekundy każdy  - to sytuacja akceptowalna
   - skaluj aplikację, gdy osiąga próg tej akceptowalności


### Przekierowania HTTP świadome
- nie robimy przekierowań na adresy z parametrów wywołania
- doklejamy swoje dane od strony serwera

### System logowania na konsolę
- używaj natywnych rozwiązań typu `Winston` lub `Morgan`
- nie loguj w trakcie pracy do pliku z własną obsługą - opóźniasz pętlę głowną systemu
- stosuj minimalne treści na konsoli
- staraj się loggować tylko błędy i bardzo istotne stany aplikacji - logi "mało gadatliwe"

### Testuj pracę middlewar-ów
- test w `supertest`
- testy jednego/dwóch middlewareów "na raz"
- sprawdzanie statusów HTTP
- sprawdzanie formatu danych zwrotnych
 - sprawdzanie ilości i rodzaju danych


### Obiekt błędu
- używać tylko wbudowanych typów błędów `new Error('Reason')`
- przechwytuj błędy centralnie w całej aplikacji, nie na poziomie poszczególnych funkcji, bibliotek, klas i funkcji pośredniczących


### Separacja aplikacji i serwera Express
- inny plik z instancją serwera i listener na porcie http
- inny plik z core-m aplikacji

### Buforuj żądania
 - na poziomie globalnym
 - na poziomie requestów - np. cache aplikacyjny - [cache in memory](https://github.com/pwnpsasin/njs_koszalin_2019/blob/39adfb7405df655d2f74e162b842f908ed9ecc7c/EXAMPLES/S04_EX_01/cache_in_memory.js) oraz [cache as middleware](https://github.com/pwnpsasin/njs_koszalin_2019/blob/39adfb7405df655d2f74e162b842f908ed9ecc7c/EXAMPLES/S04_EX_01/in_app.js)

### Nagłowki Express
- *ku pamięci* - nazwy są z małych liter - np. X-Custom-Mail to `x-custom-mail` i odczytujemy "tablicowo" jako
```js
abc(req, res,next) => {
  const x = req.headers['x-custom-mail']
  next();
}
```
lub "lodashowo"
```js
import { get } from 'lodash';
const x = get(req.headers, 'x-custom-mail', null)
```
### Badacze bezpieczeństwa
  - ważny czynnki podnoszenia bezpieczeństwa własnej aplikacji
  - utrzymaj z nimi kontakt
  - moduł `express-security.txt` z informacją


### Obsługa przechwytu dokładnych błędów ale nie na produkcji
- nie ujawniamy śladu błędu, zawartości stosu, nazw plików i katalogów, itp.

    ```js
    import errorHandler from 'errorhandler';
    ...
    if (!isProduction) {
    app.use(errorHandler());
    }
    ...
    ```

### Kryptografia
- nie używamy biblioteki `crypto`
- używamy `bcrypt`

### Metody nadpisane np. DELETE - różne wartości systemowe

    ```js
    // override
    app.use(methodOverride('_method')); // In query
    app.use(methodOverride('X-HTTP-Method')); // Microsoft
    app.use(methodOverride('X-HTTP-Method-Override')); // Google/GData
    app.use(methodOverride('X-Method-Override')); // IBM

    ```

[Przykład w użyciu - Express](https://raw.githubusercontent.com/pwnpsasin/njs_koszalin_2019/39adfb7405df655d2f74e162b842f908ed9ecc7c/EXAMPLES/S03_EX_04/views/index.hbs)
### Blokujemy dostęp do punktów API
   - sprawdzamy req.xhr + CSP i CORS
   - nagłówek `X-Requested-With: XMLHttpRequest`
- odrzucamy połączenia od `nie naszych` partnerów komunikacji sieciowej

### Utrzymuj konwencję API REST i zasady CRUD
  - C - create `PUT` / `POST` (DB Insert)
  - R - read `GET` (DB Select)
  - U - update `POST` / `PUT` / `PATCH` (DB Update)
  - D - delete `DELETE` (DB Delete)

  - pilnuj odpowiednich statusów HTTP typu 2xx, 3xx, 4xx, 5xx


### Nie wierzymy nagłówkom
  - to `cudze` dane ;-)
  - poddajemy je oczyszczaniu
  ```js
  Content-Encoding: gzip
  Server: '; DROP TABLE users;---'
  Content-Length: 21300
  ```
### Przypisz każdemu requestowi kod transakcji np. `TransactionId`
- pomocne przy analizie kolejności wywołań asynchronicznych, stanu stosu i sterty
- utrzymujemy ten numer od żądania aż po odpowiedź Klientowi
- łatwo analizować kaskady middlewarów


### Stosuj `HTTP Vary`
```js
HTTP/1.1 200 OK
    Content-Type: text/html
    Vary: User-Agent
    Content-Length: 5710
```
Nagłówek `HTTP Vary` informuje przeglądarkę, że zawartość odpowiedzi różni się w zależności od klienta użytkownika, który pobiera stronę. Jeśli Twój serwer już używa nagłówka HTTP Vary, możesz dodać do wysyłanej listy element User-Agent.

Nagłówek `HTTP Vary` pełni dwie ważne i przydatne funkcje:

- Informuje serwery pamięci podręcznej, których używają dostawcy usług internetowych i inne firmy, że przy podejmowaniu decyzji o wyświetlaniu strony z pamięci podręcznej należy mieć na uwadze klienta użytkownika. Bez nagłówka HTTP Vary serwer pamięci podręcznej może użytkownikom komórek błędnie udostępniać wersję strony HTML na komputery lub odwrotnie.
- Pomaga Googlebotowi szybciej znajdować treści zoptymalizowane pod kątem urządzeń mobilnych. Prawidłowy nagłówek HTTP Vary to jeden ze wskaźników, których używamy podczas indeksowania adresów URL z takimi treściami.

### Stosuj adresy kanoniczne

- Aby określić adres URL, który ma być widoczny w wynikach wyszukiwania. 
- Aby skonsolidować sygnały linków dla podobnych lub zduplikowanych stron. Możliwość konsolidowania informacji o poszczególnych adresach URL (np. linków, które do nich prowadzą) w jednym preferowanym adresie URL upraszcza działanie wyszukiwarek.
- Aby uprościć śledzenie danych w przypadku pojedynczego produktu/tematu. W przypadku dużej liczby różnych adresów URL trudniej jest uzyskać skonsolidowane dane dla poszczególnych fragmentów treści.
- Aby zarządzać materiałami redystrybuowanymi. Jeśli redystrybuujesz treści do publikacji w innych domenach, lepiej, by do rankingu stron był brany pod uwagę preferowany URL.
- Aby nie tracić czasu na indeksowanie duplikatów stron. Googlebot powinien skupić się na jak najdokładniejszym monitorowaniu treści w Twojej witrynie, lepiej więc, żeby indeksował nowe lub zaktualizowane strony, a nie różne ich wersje na komputery i komórki.

### Stosuj tagi w nagłówku typu `noindex` i `nofollow`

### Ogranicz ilość dostępów do newralgicznych punktów systemu np.
- logowanie
- resetowanie hasła
- aktywacja np. pinu
- kontroluj ilość złych odwołań użytkownika i zastosuj dławik w systemie:
  - ilość prób na minutę
  - ilość prób na godzinę
  - ilość prób na dzień
  - ilość prób w większej jednostce czasu np. ostanie 90 dni


## Czyszczenie cache pakietów na obrazach CI/CD 
`yarn cache clean`


## Programowanie

- ### Ucieczki i walidacja w HTML, JS and CSS
  - `escape`
  - biblioteka `validator`

- ### Dane wejściowe są **niepewne**
- ### Dane wyjściowe są **niepewne**
- ### Dane w środku infrastruktury są **niepewne**


- ### Walidacja danych JSON - kontrola schema - biblioteka `joi`

- ### Zaczynaj `{`  w tej samej linii, co nazwa   funkcji lub klasy
    
    ```js
    function abc() {
        // blok kodu
    }
    ```

- ### Pamiętaj o końcu linii
    - zawsze kończ linię znakiem `;` gdzie tylko wskazane
    - nie licz na to, że zrobi to za Ciebie poprawnie interpreter
    - korzystaj z działającego w tle systemu `Prettier`
    - formatuj kod całkowicie przez commitem `npm run format` lub `npm run format:check`

- ### Nazywaj funkcje, nawet te anonimowe
    - pomocne w debugowaniu kodu, przeglądaniu stosu i stertu
    - pomocne w przestrzeni zone.js

- ### Używaj potrójnego przyrównania `===`
    ```js
    '' == '0'           // false
    0 == ''             // true
    0 == '0'            // true

    false == 'false'    // false
    false == '0'        // true

    false == undefined  // false
    false == null       // false
    null == undefined   // true

    ' \t\r\n ' == 0     // true
    ```

- ### Stosuj odpowednie nazewnictwo zmiennych, klas i funkcji
    - funkcje z pierwszej małej litery `function collectNames()`
    - nazwy klas z wielkiej litery `class Parser {}`
    - stałe const pisz z wielkich liter `const PI=3.14`
- ### Używaj `Async Await`, zamiast callback-ów
    - czuwaj na przebiegiem programu `try catch`
    - czuwaj aby funkcja await jako obietnica miała obsługę `.catch(err) => {}` czasami też drugie `then` w formie brakującego w standardzie  `finally` - sprzątanie zmiennych, uchwytów itp.

- ### Używaj funkcji strzałkowej `() = {}`
  - kontroluj kontekst `this`
  - kontroluj zakres zmiennych i funkcji

- ### Używaj świadomie funkcji IIFE (Immediately Invoked Function Expression) - nie nadużywaj
    ```js
    (function () {
        console.log("ale heca!!!");
    })();
    ```

- ### Ochrona wyrażeń regularnych
  - safe-regex

- ### Moduły ładujące dane dynamiczne
  - staraj się nie parametryzować modułów zmiennymi - np. fs.readFile() z parametrem

- ### Pluginy ESLINT-a
  - eslint-plugin-security
  - eslint-plugin-promise

- ### Przestrzegaj ostrzeżeń Linter-a
> Linting nie musi być tylko narzędziem do egzekwowania pedantycznych reguł dotyczących białych znaków, średników lub wyrażeń eval. ESLint zapewnia potężną strukturę do eliminowania szerokiej gamy potencjalnie niebezpiecznych wzorców w kodzie (wyrażenia regularne, sprawdzanie poprawności danych wejściowych itd.). Myślę, że zapewnia nowe, potężne narzędzie, które jest warte rozważenia przez świadomych bezpieczeństwa programistów JavaScript. (Adam Baldwin - VP of Security at npm)

- ### Ochraniaj system przez wstrzykiwaniem złośliwych danych 
  - korzystaj z `KNEX`, `Mongoose` itp.

- ### Losowe dane generuj przy użyciu Node.js
  ```js
  crypto.RandomBytes(size, [callback]
  ```
- ### Pobieraj dane frontendowe z Node
  - assets wgrane z npm-a
  - pliki nie wgrywane "ręcznie" np. Bootstrap pobrany osobiście z sieci i wstawiony do assets

- ### Pilnuj przestrzeni danych REDIS i nazw kluczy (page 0 -15)
    - wybieraj nr bazy / page-a

        ```js
        var redis = require('redis'),
            db = redis.createClient();

            db.select(1, function(err,res){
            // you'll want to check that the select was successful here
            // if(err) return err;
            db.set('key', 'string'); // this will be posted to database 1 rather than db 0
            });
        ```
    - globalnie parametryzuj
        ```js
        app.configure('development', function(){
        // development options go here
        app.set('redisdb', 5);
        });

        app.configure('production', function(){
        // production options here
        app.set('redisdb', 0);
        });
        ```
    - klucze nazywaj inaczej na środowisku devel inaczej na produkcji lub zmieniaj page w zależności od środowiska


- ### Uważaj na referencje, mutacje danych, nieprzewidywalne klonowanie
  - DOMPurify - uważaj na wydajność
  - JSDOM
  - [...[...]]
  - {... {...}}
  - chroń przypisy typu `const { a, b } = obj;`

- ### Operuj na jak najmniejszej ilości danych
  - używaj SELECT na polach na których pracujesz, unikaj `*`
  - nie przeliczaj po `count(*)` tylko `count(1)` lub `count(id)`
  - nie pobieraj pól, których nie potrzebujesz
  - przycinaj i filtruj obiekty
  - nakładaj warunki jak najszybciej, nie na końcu zapytania po kilku operacjach join

 - ### Operując na datach korzystaj z timestamp i epoch
    - nie uwzględniaj strefy czasowej podczas zapisu danych tylko timestamp
    - nie używaj już biblioteki moment.js
    - pamiętaj, że styczeń to 0 a 11 to grudzień przy parsowaniu daty
    - nie zapisuj danych typu `2020-11-09T09:15:40`
 
 - ### Uważaj na operacje na liczbach
   - szczególnie zniennoprzecinkowych `(1.3 * 3) / 3 !== 1.3`
   - uważaj na liczby/ciągi typu `0123`
   - rozmiar pliku json na dysku, to nie rozmiar obiektu w pamięci RAM po jego wczytaniu
   - staraj się w jsonach używać w miarę krótkich nazw pól

- ### Wykonuj minimalną ilość operacji na plikach z dysku
  - buforuj
  - nie czytaj przy każdym request
  - nie pobieraj nazw lub ich części od klienta


- ### Uruchamiaj niebezpieczne dane w klatce
  - moduł `sanbox`
  - podsystem `DOMPurify` i `JSDOM`


- ### Ukrywanie szczegółów błędów przez klientami serwisu

- ### Błędy bez obsługi powtarzania
    - każdy poważny błąd to wywrotka aplikacji `process.exit(errorcode)`
- ### Wyjście z programu z gracją
    - odpowiedni kod wyjścia dla błędu zgodny z POSIX 
    
        `process.exit(132);`
    - błędy prywatne to `128 + własny kod` czyli błąd `132` oznacza `132 - 128 = 4` - "czwarty" błąd prywatny
    - każda funkcja powinna zgłaszać unikalny kod błędu prywatnego - dzięki temu łatwo odnaleźć punkt w kodzie, w którym ten błąd następuje
    - obsługa sygnału `SIGTERM`
    - obsługa synału `SIGINT`
    - obsługa nieprzechwyconych obietnic  `unhandledRejection`  
        ```js
        process
        .on('unhandledRejection', (reason, p) => {
            console.error(reason, 'Unhandled Rejection at Promise', p);
        })
        ```
    - obsługa nieprzechwyconych wyjątków `uncaughtException`  
        ```js
        process
        .on('uncaughtException', err => {
            console.error(err, 'Uncaught Exception thrown');
            process.exit(1);
        });
        ```
    - świadomy *shutdown* aplikacji

        ```js
        function shutdown() {
            console.warn('Server STOP...');
            server.stop();
            process.exit();
        }
        ```
    - *nazwane* funkcje anonimowe - lepsze analizowanie sterty - zamiast

        ```js
            process.on('SIGINT', function () {
                console.info('SIGINT', new Date().toISOString());
                shutdown();
            });

        ```
        to
        ```js
            process.on('SIGINT', function onSigint() {
                console.info('SIGINT', new Date().toISOString());
                shutdown();
            });
        ```
    - informacja na frontonie o niedostępności infrastruktury - w kilku językach, nie ma możliwości graficznej bo to będzie status 503


- ### Debug techniczny aplikacji
  - moduł debug - `require("debug")("abc")`
  - `debug('Punt kontroli %o', obj)`;
  - `export DEBUG=abc`
  - wyniki na konsoli - punktów nie trzeba czyścić z kodu
  - linię poprzedzone nazwą punktu debug `abc`

- ### Debuguj kod za pomocą Chrome V8
  - nie tylko gdy masz błędy
  - sprawdzaj pamięciożerność napisanych funkcji
  - sprawdzaj stan stosu i sterty
  - używaj porównywarki zrzutów
  - używaj profilera V8
  - pamiętaj aby portu diagnostycznego nie otwierać na produkcji
  - sprawdzaj wycieki pamięci, czy zasoby wracają do niskiego poziomu i jak to się ma w czasie

### Puszczaj kilkanaście requestów  - test napisanej przed chwilą funkcji
- sprawdzaj czy nowa funkcja nie wprowadziła drastycznych opóźnień
- symuluj pracę kilentów `ab -n 10 -c 10 http://localhost:3000/api/v2/posts/7`
- zerkaj i reaguj na pogorszenie responsywności aplikacji przy użyciu tego samego faktora "ab"
- reaguj na zwiększone czasy odpowiedzi
- sprawdzaj w logach, czy dane nie przerabiają się "porcjami" [przykład](https://raw.githubusercontent.com/pwnpsasin/njs_koszalin_2019/39adfb7405df655d2f74e162b842f908ed9ecc7c/EXAMPLES/S05_EX_04/szyfruj4a.js)


## Utwórz konserwacyjny punkt końcowy
- /heapdump
- /health
- staraj się nie grzebać diagnostycznie w kontenerze, zrób sobie punkt dostępu developerskiego do pewnych informacji: zużycie pamięci, liczniki, log zdarzeń itp.
- stan życia aplikacji `http://localhost/heartbeat` ze stanem HTTP 200 i OK - potrzebne Kuberentesowi do ustalenia żywotności kapsuły

### Obsługa czarnej listy JWT w Passport
- express-jwt-blacklist [przykład](https://github.com/goldbergyoni/nodebestpractices/blob/master/sections/security/expirejwt.md)

### Tragiczne w skutkach komendy *
> *niekoniecznie tylko bezpieczeństwa, ale również wydajności ;-)
- console.log, console.dir, console.warn
- setTimeout()
- setTimeout(0)
- setInterval()
- setImmediate()
- process.nextTick()
- eval()
- fs.readSync()
- funkcje crypto
- zapomniałem res.send lub next()
- pamiętaj o ewentualnych clearTimeout i clearInterval

### Zwracajcie uwagę na cykl życia Node.js
```js
`Timers`: callbacks from setInterval or setTimeout
`IO` callbacks: callbacks from I/O events
`Idle`: used internally by Node between IO and Poll phases
`Poll`: retrieve new I/O events
`Check`: callbacks from setImmediate execute here
`Close`: handle closed connections like sockets
```

## Bezpieczeństwo developmentu
### Dostęp do rejestrów NPM lub YARN oraz GIT
  - podwójna autoryzacja 
(U2F - FIDO Universal 2nd Factor authentication)
  - każdy deweloper ma inne poświadczenia
  - używa krótkich czasowo tokenów
  - na serwerze projekt nie "podpięty pod gita"
  - aplikacja jako `obraz kontenera`, nie katalog z gitem
  - kontenery nie potrzebują dostępu do git-a

### Zero danych konfiguracji w repozytorium kodu
 - wszystkie newralgiczne dane: adresy ip, nazwy hostów, domen, porty, loginy, hasła, klucze, certyfikaty, nazwy baz danych, tabel bazodanowych - to wszystko powinno znaleźć się poza repozytorium

## Kontener i Node.js
- process na koncie non-root
- limit danych POST w reverse-proxy
- certyfikaty SSL w reverse-proxy
- statyczne dane: html, css, obrazki, pdf-y, xml-e, pliki zip - to wszystko musi znaleźć się w reverse-proxy 
- zabijaj procesy i kontenery w ramach monitoringu infrastruktury
- imituj sztuczne awarie - obserwuj klaster
- limituj pamięć i wielkość sterty i stosu
- limituj pracę rdzeni CPU
- uważaj na ulimity (nie wszystko da się przestawić we wnętrzu kontenera)
- nie uruchamiaj programów w otoczce `sh` lub `bash` lub `npm`
- podejście deklaratywne - `konfiguracja ponad wszystko`
- brak persistance kontenerów
- infrastrukturę `traktujemy jako bydło nie zwierzęta domowe` - kontener sam w sobie nie jest przedmiotem naszej opieki ;-)
- nie przywiązujemy się do konkretnych maszyn
- zarządzamy z węzła Kubernetes - `kubectl`
- nerwalgiczne dane przetrzymujemy w `Secretach Kubernetesa`
- konfigi `.yml` trzymamy w bezpiecznym miejscu
- nie skalujemy maszyn z ręki - z linii poleceń
- monitorujemy wydajnosć - `Prometesz` i `Grafana`
- logi zbieramy do systemów sieciowych np. `Sematext`
- błędy aplikacji od strony przeglądarek Klientów zbieramy sieciowo np. do `Sentry` - i analizujemy - dobre źródło informacji o problemach z aplikacją na różnych urządzeniach.
- symulujemy często awarie infrastruktury.







