# -*- coding: utf-8 -*-
# Код основан на пакете esia-connector
# https://github.com/eigenmethod/esia-connector
# Лицензия:
#   https://github.com/eigenmethod/esia-connector/blob/master/LICENSE.txt
# Copyright (c) 2015, Septem Capital
import base64
import datetime
import json
import os, sys
import tempfile
import traceback
from subprocess import Popen, PIPE

import pytz

# sys.path.append(r'/usr/lib')

import pycades

import requests

from .exceptions import CryptoBackendError, HttpError, IncorrectJsonError


def make_request(url, method='GET', headers=None, data=None, verify=True):
    """
    Выполняет запрос по заданному URL и возвращает dict на основе JSON-ответа

    :param str url: URL-адрес
    :param str method: (optional) HTTP-метод запроса, по умолчанию GET
    :param dict headers: (optional) массив HTTP-заголовков, по умолчанию None
    :param dict data: (optional) массив данных передаваемых в запросе,
        по умолчанию None
    :param boolean verify: optional, производить ли верификацию
        ssl-сертификата при запросае
    :return: dict на основе JSON-ответа
    :rtype: dict
    :raises HttpError: если выбрасыватеся исключение requests.HTTPError
    :raises IncorrectJsonError: если JSON-ответ не может быть
        корректно прочитан
    """
    try:
        response = requests.request(
            method, url, headers=headers, data=data, verify=verify)
        response.raise_for_status()
        return json.loads(response.content)
    except requests.HTTPError as e:
        raise HttpError(e)
    except ValueError as e:
        raise IncorrectJsonError(e)


def smime_sign(certificate_file, private_key_file, data, backend='m2crypto'):
    """
    Подписывает данные в формате SMIME с использование sha256.
    В качестве бэкенда используется либо вызов openssl, либо
    библиотека M2Crypto

    :param str certificate_file: путь к сертификату
    :param str private_key_file: путь к приватному ключу
    :param str data: подписываемые данные
    :param str backend: (optional) бэкенд, используемый
        для подписи (m2crypto|openssl)
    :raises CryptoBackendError: если неверно указан backend
    :return: открепленная подпись
    :rtype: str
    """
    if backend == 'm2crypto' or backend is None:
        from M2Crypto import SMIME, BIO

        if not isinstance(data, bytes):
            data = bytes(data)

        signer = SMIME.SMIME()
        signer.load_key(private_key_file, certificate_file)
        p7 = signer.sign(
            BIO.MemoryBuffer(data), flags=SMIME.PKCS7_DETACHED, algo='sha256')
        signed_message = BIO.MemoryBuffer()
        p7.write_der(signed_message)
        return signed_message.read()
    elif backend == 'openssl':
        source_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        source_file.write(data)
        source_file.close()
        source_path = source_file.name

        destination_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        destination_file.close()
        destination_path = destination_file.name

        cmd = (
            'openssl smime -sign -md sha256 -in {f_in} -signer {cert} -inkey '
            '{key} -out {f_out} -outform DER')
        os.system(cmd.format(
            f_in=source_path,
            cert=certificate_file,
            key=private_key_file,
            f_out=destination_path,
        ))

        signed_message = open(destination_path, 'rb').read()
        os.unlink(source_path)
        os.unlink(destination_path)
        return signed_message
    else:
        raise CryptoBackendError(
            'Unknown cryptography backend. Use openssl or m2crypto value.')


def create_detached_gost_cades_bes_signature(file_path, signature_out_path, cert_thumbprint, key_pin:str, check_chain: bool = True):
    """
    Создает отсоединенную электронную подпись формата CAdES-BES для указанного файла
    с использованием ГОСТ Р алгоритмов и библиотеки Pycades.
   
    :param key_pin: Пин-код контейнера закрытого ключа
    :type key_pin: str
    :param file_path: Путь к файлу, который нужно подписать.
    :param signature_out_path: Путь для сохранения файла отсоединенной подписи (обычно .sig или .p7s).
    :param cert_thumbprint: Отпечаток (thumbprint) сертификата ГОСТ Р, который будет использован для подписи.
                                   Отпечаток должен быть указан без пробелов и в верхнем регистре.
    :param check_chain: Проверка цепочки сертификатов
    :type check_chain: bool
    
    :return: True, если подпись успешно создана, иначе False.
    """
    store = None  # Инициализируем store здесь, чтобы он был доступен в блоке finally
    try:
        # 1. Проверка существования файла для подписи
        if not os.path.exists(file_path):
            print(f"Ошибка: Файл для подписи не найден по пути: {file_path}")
            return False
        
        # 2. Инициализация и открытие хранилища сертификатов.
        # Открываем личное хранилище текущего пользователя
        store = pycades.Store()
        store.Open(pycades.CAPICOM_CURRENT_USER_STORE,
                   pycades.CAPICOM_MY_STORE,
                   pycades.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED)
        
        # 3. Поиск и выбор сертификата по отпечатку
        certs = store.Certificates
        if certs.Count == 0:
            print("Ошибка: В хранилище не найдено ни одного сертификата.")
            return False
        
        # Ищем сертификат по отпечатку (SHA1 HASH)
        # Отпечаток должен быть точным, без пробелов, в верхнем регистре.
        found_certs = certs.Find(pycades.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, cert_thumbprint.upper())
        
        if found_certs.Count == 0:
            print(f"Ошибка: Сертификат с отпечатком '{cert_thumbprint}' не найден в хранилище.")
            return False
        
        signer_cert = found_certs.Item(1)  # Берем первый найденный сертификат
        
        # Проверка, что у сертификата есть закрытый ключ
        if not signer_cert.HasPrivateKey():
            print(
                f"Ошибка: Выбранный сертификат (Subject: {signer_cert.SubjectName}, Thumbprint: {signer_cert.Thumbprint}) не имеет связанного закрытого ключа.")
            return False
        
        print(
            f"Используется сертификат: {signer_cert.SubjectName}, Выдан: {signer_cert.IssuerName}, Действителен до: {signer_cert.ValidToDate}")
        
        # 4. Создание объекта подписанта (Signer)
        signer = pycades.Signer()
        signer.Certificate = signer_cert
        signer.CheckCertificate = check_chain  # Включить проверку цепочки сертификатов (опционально, но рекомендуется)
        # Алгоритмы хеширования и подписи обычно определяются автоматически на основе сертификата ГОСТ Р.
        # При необходимости можно указать явно, например, для объекта CAdESCOM.CPSigner:
        # signer.HashAlgorithm = "1.2.643.7.1.1.2.2" # OID для ГОСТ Р 34.11-2012 (256 бит)
        # signer.Options = pycades.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN # Включить всю цепочку в подпись
        signer.KeyPin = key_pin
        
        # 5. Подготовка данных для подписи (SignedData)
        signed_data = pycades.SignedData()
        
        # Чтение содержимого файла в бинарном режиме
        with open(file_path, 'r') as f:
            file_content_bytes = f.read()
        
        # signed_data.ContentEncoding = pycades.CADESCOM_BASE64_TO_BINARY
        # message_bytes = api_key.encode("utf-8")
        # base64_message = base64.b64encode(message_bytes)
        # signedData.Content = base64_message.decode("utf-8")
        
        # Загружаем содержимое файла. Pycades ожидает бинарные данные (bytes).
        signed_data.Content = file_content_bytes
        
        # 6. Создание отсоединенной подписи CAdES-BES
        # Метод SignCades(Signer, CadesType, Detached, EncodingType)
        # Signer: объект подписанта
        # CadesType: тип подписи (pycades.CADES_BES, pycades.CADES_T, etc.)
        # Detached: True для отсоединенной подписи, False для присоединенной
        # EncodingType: формат вывода подписи (pycades.ENCODE_BASE64 или pycades.ENCODE_BINARY)
        signature_base64 = signed_data.SignCades(signer,
                                                 pycades.CADESCOM_CADES_BES,
                                                 True,  # True для отсоединенной подписи
                                                 pycades.CADESCOM_ENCODE_BASE64)  # Подпись в формате Base64
        
        # 7. Сохранение подписи в отдельный файл
        with open(signature_out_path, 'w') as sig_file:
            sig_file.write(signature_base64)
        
        print(f"Отсоединенная подпись CAdES-BES успешно создана и сохранена в файл: {signature_out_path}")
        return True
    
    except Exception as e:
        print(f"Критическая ошибка при создании подписи: {e}")
        # error_info = pycades.LastError()
        # if error_info:
        #     print(f"Код ошибки КриптоПро: {error_info.Code:#08x} ({error_info.Message})")
        return False
    finally:
        if store:
            store.Close()

def csp_sign(thumbprint, password, data):
    """
    Подписывает данные с использованием ГОСТ Р 34.10-2012 открепленной подписи.
    В качестве бэкенда используется утилита cryptcp из ПО КриптоПРО CSP.

    :param str thumbprint: SHA1 отпечаток сертификата, связанного
        с зкарытым ключем
    :param str password: пароль для контейнера закрытого ключа
    :param str data: подписываемые данные
    """
    temp_dir = tempfile.gettempdir()
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as source_file:
        source_file.write(data)
    source_path = source_file.name


    # cmd = (
    #     "cryptcp -sign -nochain -der -nocert -pin {password} "
    #     "{f_in} {f_out} -thumbprint {thumbprint} 2>&1 >/dev/null")

    # Create detached PKCS#7 sinature
    # csptest -sfsign -sign -detached -in signed_file.txt -out sign.p7b \
    #   -my 16d9487839b629f327c659a854d5283e24accc2d -password 1

    # Verify detached PKCS#7 sinature
    # csptest -sfsign -verify -detached -in signed_file.txt \
    #   -signature sign.p7b -my 16d9487839b629f327c659a854d5283e24accc2d

    # cryptcp -signf -dir "/tmp" -der -strict -cert -detached -thumbprint "$thumbprint" -pin "$pin" "/tmp/message"

    cmd = (
        f"/opt/cprocsp/bin/amd64/cryptcp -signf -dir {temp_dir} -der -strict -cert -detached -thumbprint {thumbprint}  -nochain -pin {password} {source_path}")
       
    proc = Popen(
            cmd,
            shell=True,
            stdout=PIPE, stderr=PIPE
    )
    proc.wait()  # дождаться выполнения
    hash_res = proc.communicate()
    
    f_out = f'{source_path}.sgn'
    f_out2 = f'{source_path}2.sgn'
    try:
        with open(f_out, "rb") as f:
            signed_message = f.read()
    except Exception as e:
        print(traceback.format_exc())
    
    # todo change to True for prod
    res_cades = create_detached_gost_cades_bes_signature(source_path, f_out2, thumbprint, password, False)
    
    try:
        with open(f_out2, "rb") as f:
            signed_message2 = f.read()
    except Exception as e:
        print(traceback.format_exc())

    tr = signed_message == signed_message2
    
    os.unlink(source_path)
    os.unlink(f_out)

    return signed_message2


def sign_params(params, settings, backend='csp'):
    """
    Подписывает параметры запроса и добавляет в params ключ client_secret.
    Подпись основывается на полях: `scope`, `timestamp`, `client_id`, `state`.

    :param dict params: параметры запроса
    :param EsiaSettings settings: настройки модуля ЕСИА
    :param str backend: (optional) бэкенд используемый
        для подписи (m2crypto|openssl|csp)
    :raises CryptoBackendError: если неверно указан backend
    :return: подписанные параметры запроса
    :rtype: dict
    """
    plaintext = f"{params.get('client_id', '')}{params.get('scope', '')}org_inf{params.get('timestamp', '')}{params.get('state', '')}{params.get('redirect_uri')}"
    # client_id
    #  scope;
    #  scope_org;
    #  timestamp;
    #  state;
    #  redirect_uri.
    
    # plaintext = params.get('scope', '') + params.get('timestamp', '') + \
    #     params.get('client_id', '') + params.get('state', '')
    if backend == 'csp':
        raw_client_secret = csp_sign(
            settings.csp_cert_thumbprint,
            settings.csp_container_pwd, plaintext)
    else:
        raw_client_secret = smime_sign(
            settings.certificate_file, settings.private_key_file,
            plaintext, backend)
    params.update(
        client_secret=raw_client_secret.decode('utf-8'),
        # client_secret=base64.urlsafe_b64encode(raw_client_secret).decode('utf-8'),
    )
    return params


def get_timestamp():
    """
    Возвращает текущую дату и время в строковом представлении с указанем зоны
    в формате пригодном для использования при взаимодействии с ЕСИА

    :return: текущая дата и время
    :rtype: str
    """
    return datetime.datetime.now(pytz.utc).\
        strftime('%Y.%m.%d %H:%M:%S %z').strip()
