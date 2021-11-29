# esia-oauth2
## Модуль для доступа к ЕСИА REST сервису (https://esia.gosuslugi.ru)
Основан на коде esia-connector https://github.com/eigenmethod/esia-connector, лицензия: https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt

### Позволяет:
* Сформировать ссылку для перехода на сайт ЕСИА с целью авторизации
* Завершает процедуру авторизации обменивая временный код на access token
* Опционально может производить JWT (JSON Web Token) валидацию ответа ЕСИА (при наличии публичного ключа ЕСИА)
* Для формирования открепленной подписи запросов, в качестве бэкенда может использоваться
  модуль M2Crypto или openssl через системный вызов (указывается в настройках)
* Выполнять информационные запросы к ЕСИА REST сервису для получения сведений о персоне:
    * Основаная информация
    * Адреса
    * Контактная информация
    * Документы
    * Дети
    * Транспортные средства

### Установка:
```
pip install --upgrade git+https://github.com/sokolovs/esia-oauth2.git
pip install -r https://raw.githubusercontent.com/sokolovs/esia-oauth2/master/requirements.txt
```


### Пример использования в Django

Создайте конфигурационный файл esia.ini следующего содержания:
```
[esia]
### Внимание! Все пути указываются относительно данного файла.
# Базовый адрес сервиса ЕСИА, в данном случае указана тестовая среда
SERVICE_URL: https://esia-portal1.test.gosuslugi.ru

# Идентификатор информационной системы, указывается в заявке на подключение
CLIENT_ID: MYIS01

# Адрес страницы, на которую будет перенаправлен браузер после авторизации в ЕСИА
REDIRECT_URI: http://127.0.0.1:8000/esia/callback/

# Адрес страницы, на которую необходимо перенаправить браузер после логаута в ЕСИА (опционально)
LOGOUT_REDIRECT_URI: http://127.0.0.1:8000

# Список scope через пробел. Указывается в заявке, openid при авторизации обязателен
SCOPE: openid http://esia.gosuslugi.ru/usr_inf

# Используемый крипто бэкенд: m2crypto, openssl (системный вызов)
# или csp (системный вызов утилиты cryptcp из состава КриптоПРО CSP)
CRYPTO_BACKEND: m2crypto

# SHA1 отпечаток сертификата связанного с закрытым ключем, смотреть по выводу certmgr --list
# (необязателен, используется только для csp)
CSP_CERT_THUMBPRINT: 5c84a6a58bbeb6578ff7d26f4ea65b6de5f9f5b8

# Пароль (пин-код) контейнера с закрктым ключем
# (необязателен, используется только для csp)
CSP_CONTAINER_PWD: 12345678
```

В свой urls.py добавьте:
```python
url(r'^esia/login/$', views.esia_login, name='esia_login'),
url(r'^esia/callback/$', views.esia_callback, name='esia_callback'),
```

В свой views.py добавьте:
```python
import json
from django.http import HttpResponseRedirect, HttpResponse
from django.contrib.auth.views import logout
from esia.client import EsiaConfig, EsiaAuth

ESIA_SETTINGS = EsiaConfig('/full/path/to/esia.ini')

def esia_login(request):
    esia_auth = EsiaAuth(ESIA_SETTINGS)
    esia_login_url = esia_auth.get_auth_url()
    return HttpResponseRedirect(esia_login_url)

def esia_logout(request):
    kwargs = {}
    esia_auth = EsiaAuth(ESIA_SETTINGS)
    kwargs['next_page'] = esia_auth.get_logout_url()
    return logout(request, **kwargs)

def esia_callback(request):
    esia_auth = EsiaAuth(ESIA_SETTINGS)
    if request.GET.has_key('error'):
        data = {
            'error': request.GET['error'],
            'error_description': request.GET['error_description'],
        }
    else:
        data = []
        code = request.GET['code']
        state = request.GET['state']
        esia_client = esia_auth.complete_authorization(code, state)
        # Для отключения JWT валидации ответов ЕСИА, можно так:
        # esia_client = esia_auth.complete_authorization(code, state, validate_token=False)

        # Запрос информации о персоне
        main_info = esia_client.get_person_main_info()
        pers_doc = esia_client.get_person_documents()
        pars_addr = esia_client.get_person_addresses()
        pers_contacts = esia_client.get_person_contacts()
        pers_kids = esia_client.get_person_kids()
        pers_trans = esia_client.get_person_transport()

        data.append(main_info)
        data.append(pers_doc)
        data.append(pars_addr)
        data.append(pers_contacts)
        data.append(pers_kids)
        data.append(pers_trans)

    # Просто выводим информацию. Здесь далее должна идти внутренняя логика авторизации
    # вашей информационной системы.
    return HttpResponse(json.dumps(data, cls=json.JSONEncoder, ensure_ascii=False, indent=4),
        content_type='application/json')
```


### Порядок установки

http://pushorigin.ru/cryptopro/cryptcp
https://wiki.astralinux.ru/pages/viewpage.action?pageId=32833902

Предварительно заказчик должен зарегаться на портале госуслуг, зарегать свое приложение, прописать колбеки и конфиги.
Если все ок, то на выходе ему должны прислать доку с ключами + инструкция. И можно начать подключать тестовый режим.


1. Устанавливаем cryptopr csp через центр загрузок https://www.cryptopro.ru/products/csp/downloads  (linux-amd64_deb)
2. Распаковываем. Устанавливаем (`./install.sh`)
3. Делаем алиасы: `export PATH="$(/bin/ls -d /opt/cprocsp/{s,}bin/*|tr '\n' ':')$PATH"` (чтоб не писать каждый раз полный путь к команде)
4. Копируем закрытый ключ (содержит внутри себя кучу файлов. Заканчивается на .000)
5. Теперь необходимо создать контейнер и после связать его с сертификатом.
#### ВАЖНО: все действия с сертификатом делать для того юзера, кто будет запускать скрипт. В моем случае это юзер a1 (он же запускает gunicorn, nginx).

93e4b302.000 - это закрытый ключ
36c6fa72.cer - это сертификат

```
cp -R 93e4b302.000 /var/opt/cprocsp/keys/a1 # Копируем ключ в ключи юзера a1
chmod 600 /var/opt/cprocsp/keys/a1/93e4b302.000 # Ставим права
csptest -keyset -enum_cont -verifycontext -fqcn  # Узнаем реальное название контейнера (после копирования ключа создается контейнер)
(в моем случае это: HDIMAGE\36c6fa72-8df5-40b9-8915-f40d66d8ac73)
certmgr -inst -file 36c6fa72.cer -cont '\\.\HDIMAGE\36c6fa72-8df5-40b9-8915-f40d66d8ac73' # Делаем связку закрытого ключа и сертификата

И после:
opt/cprocsp/bin/amd64/certmgr --list - должен выдать: PrivateKey Link: Yes

```
6. Из последней выше команды берем отпечаток и вставляем его в конфиг esia.ini 
7. Примерный конфиг для тестовых сертификатов (получили от заказчика):
```
[esia]
### Внимание! Все пути указываются относительно данного файла.
# Базовый адрес сервиса ЕСИА, в данном случае указана тестовая среда
SERVICE_URL: https://esia-portal1.test.gosuslugi.ru

# Идентификатор информационной системы, указывается в заявке на подключение
CLIENT_ID: SYSTEM48


# Адрес страницы, на которую будет перенаправлен браузер после авторизации в ЕСИА
REDIRECT_URI: https://api.cov112-48.ru/api/v1/esia/callback/

# Адрес страницы, на которую необходимо перенаправить браузер после логаута в ЕСИА (опционально)
LOGOUT_REDIRECT_URI: https://api.cov112-48.ru/

# Список scope через пробел. Указывается в заявке, openid при авторизации обязателен
SCOPE: mobile openid fullname birthdate gender snils medical_doc email
# Используемый крипто бэкенд: m2crypto, openssl (системный вызов)
# или csp (системный вызов утилиты cryptcp из состава КриптоПРО CSP)
CRYPTO_BACKEND: csp

# SHA1 отпечаток сертификата связанного с закрытым ключем, смотреть по выводу certmgr --list
# (необязателен, используется только для csp)
CSP_CERT_THUMBPRINT: 6b717c75334811eabf79d85e1c271d115ffa474b

# Пароль (пин-код) контейнера с закрктым ключем
# (необязателен, используется только для csp)
CSP_CONTAINER_PWD: 1234567890

```
8. В esia-oauth2 необходимо добавить `-nochain` (utils.py)
```
cmd = (
        "cryptcp -signf -dir {temp_dir} -der -strict -cert -detached -norev -nochain"
        " -thumbprint {thumbprint} -pin {password} {f_in}")
```
Это отключит проверку цепей и не будет вылазить Prompt (Подтверждение)
9. Произвести все настройки esia.ini, залить и запустить
10. Скорее всего, форма госуслуг не появится. Это происходит из-за того, что nginx ругается на слишком большой размер урла. Поэтому в nginx.conf надо добавить:
```
client_max_body_size 20M;
proxy_buffer_size 64k;
proxy_buffers 4 64k;
proxy_busy_buffers_size 64k;
```
11. По идее это все. Далее берем тестовые учетные записи (также должно быть в документации) и пробуем запускать. 
Точно работает:
```
EsiaTest006@yandex.ru
11111111
```
