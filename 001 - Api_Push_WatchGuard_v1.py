import requests
import json
import colors
import datetime, time
import base64
import sys
import socket, platform

### ******************************************************************************************************************************************************************************
### Datos del usuario a enviar el PUSH
usuario = 'nombre de usuario del AD'
password = 'password del usuario del AD'
### ******************************************************************************************************************************************************************************
### Datos de la API proporcionados por WatchGuard
API_KEY = 'you API WatchGuard Key'
id_de_la_cuenta = 'your WatchGuard account ID'
id_del_recurso  = 'your WatchGuard resource ID'
ID_de_acceso_RW = 'your WatchGuard access ID with RW privileges'
Pass_de_acceso_RW = 'your WatchGuard access ID password for the RW privileges access ID'
                                            
var_debug = False ### Cambiar a True para modo verbose

print(colors.bcolors.HEADER + "*****************************************" + colors.bcolors.ENDC)
print(colors.bcolors.HEADER + "*****************************************" + colors.bcolors.ENDC)
print(colors.bcolors.HEADER + "==>> INICIO      _/\\_/\\_/\\_/\\_/\\_/\\_/\\_/\\" + colors.bcolors.ENDC)

### ******************************************************************************************************************************************************************************
def base_64_encoder(str_ID , str_Pass):    ### Este función convierte el usuario y password de la API a base64(usu:pass), necesario para ENVIAR LA PETICIÓN DE AUTENTICACIÓN (POST)

    message = str_ID + ':' + str_Pass

    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    return (base64_message)

### ******************************************************************************************************************************************************************************
### 1º Paso: enviar una petición de autenticación a la API

headers = { "accept" : "application/json", "Authorization" : "Basic " + base_64_encoder(ID_de_acceso_RW,Pass_de_acceso_RW) , "Content-Type" : "application/x-www-form-urlencoded" }
payload =  "grant_type=client_credentials&scope=api-access" 
url = "https://api.deu.cloud.watchguard.com/oauth/token/"

print(colors.bcolors.OKGREEN + "==>> PETICIÓN DE AUTENTICACIÓN ENVIADA (POST)" + colors.bcolors.ENDC)

if(var_debug):
    print("URL 1.......: " + colors.bcolors.OKBLUE + url + colors.bcolors.ENDC)
    print("Headers 1...: " + colors.bcolors.OKBLUE + str(headers) + colors.bcolors.ENDC)
    print("Payload 1...: " + colors.bcolors.OKBLUE + payload + colors.bcolors.ENDC)

r = requests.post(url, data=payload, headers=headers)
HandShake_1 = json.loads(r.content)

print(colors.bcolors.OKGREEN + "<<== PETICIÓN DE AUTENTICACIÓN RECIBIDA" + colors.bcolors.ENDC)

if (str(r) == '<Response [200]>'):
    print("Respuesta => " + colors.bcolors.RED + str(r) + colors.bcolors.ENDC + ' [OK]')
elif (str(r) == '<Response [400]>'):
    print("Respuesta => " + colors.bcolors.RED + str(r) + colors.bcolors.ENDC + ' ' + HandShake_1['Message'])
    print( colors.bcolors.FAIL + '\n****************************************************************************************************************' + colors.bcolors.ENDC)
    print( colors.bcolors.FAIL + '**'+ colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.FAIL + ' ERROR '  + colors.bcolors.UNDERLINE +
           'EN EL ID DE ACCESO (USUARIO DE LA API) O EN EL PASSWORD DE ACCESO (PASS DE LA API)' + colors.bcolors.ENDC + colors.bcolors.FAIL + ' **' + colors.bcolors.ENDC)
    print( colors.bcolors.FAIL + '****************************************************************************************************************' + colors.bcolors.ENDC)
    sys.exit(1)


if(var_debug):
    ahora = datetime.datetime.now()
    hora_de_expiracion = ahora + datetime.timedelta(seconds = HandShake_1['expires_in'])

    print("Tóken de acceso........: " + colors.bcolors.OKBLUE + HandShake_1['access_token'] + colors.bcolors.ENDC)
    print("Tipo de Tóken..........: " + colors.bcolors.OKBLUE + str(HandShake_1['token_type']) + colors.bcolors.ENDC )
    print("Tiempo de expiración...: " + colors.bcolors.OKBLUE + str(HandShake_1['expires_in']) + colors.bcolors.ENDC + " segundos, de "+ colors.bcolors.WARNING + str(ahora) + colors.bcolors.ENDC+ " hasta " + colors.bcolors.WARNING + str(hora_de_expiracion) + colors.bcolors.ENDC+ colors.bcolors.ENDC)
    print("Scope..................: " + colors.bcolors.OKBLUE + HandShake_1['scope'] + colors.bcolors.ENDC)

### ******************************************************************************************************************************************************************************
### 2º Paso: con el Bearer Token obtenido en el paso 1, montamos una petición de envío de PUSH a la API

origin_ip_address = requests.get('https://checkip.amazonaws.com').text.rstrip()
machine_name = platform.node()
os_version = platform.platform()
full_domain_name = socket.getfqdn()
url2 = "https://api.deu.cloud.watchguard.com/rest/authpoint/authentication/v1/accounts/" + id_de_la_cuenta + "/resources/" + id_del_recurso + "/transactions/"
headers2 = {"Authorization": str("Bearer " + HandShake_1['access_token']), "Content-Type": "application/json", "WatchGuard-API-Key": API_KEY}
payload2 = {"login": usuario, "password": password, "type": "PUSH", "originIpAddress": '\nIP PUBLICA: ' + str(origin_ip_address),"clientInfoRequest": {"machineName": '\nEQUIPO: ' + machine_name,"osVersion": '\nS.O.:' + os_version, "domain": '\nDOMINIO LOCAL: ' + full_domain_name + '\n'}	}

print(colors.bcolors.OKGREEN + "==>> PETICIÓN DE PUSH ENVIADA (POST)" + colors.bcolors.ENDC)

if(var_debug):
    print("URL 2.......: " + colors.bcolors.OKBLUE + url2 + colors.bcolors.ENDC)
    print("Headers 2...: " + colors.bcolors.OKBLUE + str(headers2) + colors.bcolors.ENDC)
    print("Payload 2...: " + colors.bcolors.OKBLUE + str(payload2) + colors.bcolors.ENDC)

r2 = requests.post(url2, data=json.dumps(payload2), headers=headers2)

HandShake_2 = json.loads(r2.content)

print(colors.bcolors.OKGREEN + "<<== PETICIÓN DE PUSH RECIBIDA" + colors.bcolors.ENDC)

if (var_debug):
    print("Handshake_2.......: " + colors.bcolors.OKBLUE + str(HandShake_2) + colors.bcolors.ENDC)
    print("r2................: " + colors.bcolors.OKBLUE + str(r2) + colors.bcolors.ENDC)

if (str(r2) == '<Response [200]>'):
    print("Respuesta => " + colors.bcolors.RED + str(r2) + colors.bcolors.ENDC + ' [OK]')
    if (var_debug):
        print("TransactionId..........: " + colors.bcolors.OKBLUE + HandShake_2['transactionId'] + colors.bcolors.ENDC) 

elif ((str(r2) == '<Response [403]>') or (str(r2) == '<Response [404]>')):
    if ('title' in HandShake_2):
        print("Respuesta => " + colors.bcolors.RED + str(r2) + colors.bcolors.ENDC + ' ' + HandShake_2['title'] + colors.bcolors.HEADER + ' (' + HandShake_2['detail'] + ')' + colors.bcolors.ENDC)
    elif ('message' in HandShake_2):
        print("Respuesta => " + colors.bcolors.RED + str(r2) + colors.bcolors.ENDC + ' ' + HandShake_2['message'])
    
    print( colors.bcolors.FAIL + '\n*******************************************************************************' + colors.bcolors.ENDC)
    print( colors.bcolors.FAIL + '**'+ colors.bcolors.ENDC + ' Resultado final: ' + colors.bcolors.FAIL + colors.bcolors.UNDERLINE +
        'ERROR' + colors.bcolors.ENDC + ', por uno de los siguientes motivos:                ' + colors.bcolors.FAIL + '**\n')
    print( colors.bcolors.FAIL + '\t\t\t-USUARIO O CONTRASEÑA INCORRECTOS (BAD LOGIN)')
    print( colors.bcolors.FAIL + '\t\t\t-APIKEY INVÁLIDA')
    print( colors.bcolors.FAIL + '\t\t\t-ID DE LA CUENTA INCORRECTA')
    print( colors.bcolors.FAIL + '\t\t\t-CUENTA API SIN PRIVILEGIOS DE RW')
    print( colors.bcolors.FAIL + '*******************************************************************************' + colors.bcolors.ENDC)
    sys.exit(1)
elif (str(r2) == '<Response [400]>'):
    print("Respuesta => " + colors.bcolors.RED + str(r2) + colors.bcolors.ENDC + ' [INESPERADA] ¿BAD ID ACCOUNT OR ID RESOURCE?')
    sys.exit(1)
else:
    print("Respuesta => " + colors.bcolors.RED + str(r2) + colors.bcolors.ENDC + ' [INESPERADA]')
    sys.exit(1)


### ******************************************************************************************************************************************************************************
### Paso 3º: con el authorization-id obtenido en el paso 2, hacemos consultas de "estado" de la petición para controlar elmomento en que el usuario acepta o deniega el permiso
###          del mensaje PUSH que le habrá llegado a su móvil

url3 = "https://api.deu.cloud.watchguard.com/rest/authpoint/authentication/v1/accounts/" + id_de_la_cuenta + "/resources/" + id_del_recurso + "/transactions/" + HandShake_2['transactionId'] + "/"
headers3 = {"Authorization": str("Bearer " + HandShake_1['access_token']), "Content-Type": "application/json", "WatchGuard-API-Key": API_KEY}

print(colors.bcolors.OKGREEN + "==>> PETICIÓN DE ESTADO DEL PUSH ENVIADA (GET)" + colors.bcolors.ENDC)

if(var_debug):
    print("URL 3.......: " + colors.bcolors.OKBLUE + url3 + colors.bcolors.ENDC)
    print("Headers 3...: " + colors.bcolors.OKBLUE + str(headers3) + colors.bcolors.ENDC)

r3 = requests.get(url3, headers=headers3)
HandShake_3 = json.loads(r3.content)

print(colors.bcolors.OKGREEN + "<<== PETICIÓN DE ESTADO DEL PUSH RECIBIDA" + colors.bcolors.ENDC)
print("Respuesta => " + colors.bcolors.RED + str(r3) + colors.bcolors.ENDC + ' [WG] ' + HandShake_3['title'])

if (var_debug):
    print("Var. r3.......: " + colors.bcolors.OKBLUE + str(r3) + colors.bcolors.ENDC)
    print("Type.r3.......: " + colors.bcolors.OKBLUE + str(type(r3)) + colors.bcolors.ENDC)
    print("r3.content....: " + colors.bcolors.OKBLUE + str(r3.content) + colors.bcolors.ENDC)
    print("HandShake_3...: " + colors.bcolors.OKBLUE + str(HandShake_3) + colors.bcolors.ENDC)

final_result = 0

if (str(r3) == '<Response [202]>'):
    intentos = 0
    
    while ((intentos <= 180) and (str(r3) == '<Response [202]>')):
        intentos += 1
        time.sleep(1)

        print(colors.bcolors.OKGREEN + "==>> PETICIÓN DE ESTADO DEL PUSH ENVIADA (GET)" + colors.bcolors.ENDC)
        r3 = requests.get(url3, headers=headers3)
        HandShake_3 = json.loads(r3.content)

        print(colors.bcolors.OKGREEN + "<<== PETICIÓN DE ESTADO DEL PUSH RECIBIDA" + colors.bcolors.ENDC)

        if (var_debug):
            print("Var. r3.......: " + colors.bcolors.OKBLUE + str(r3) + colors.bcolors.ENDC)
            print("Type.r3.......: " + colors.bcolors.OKBLUE + str(type(r3)) + colors.bcolors.ENDC)
            print("r3.content....: " + colors.bcolors.OKBLUE + str(r3.content) + colors.bcolors.ENDC)
            print("HandShake_3...: " + colors.bcolors.OKBLUE + str(HandShake_3) + colors.bcolors.ENDC)
        
        if (str(r3) == '<Response [202]>'):
            print("Tiempo : " + colors.bcolors.OKBLUE + str(intentos) + colors.bcolors.ENDC +
                " segundos. STATUS : " + colors.bcolors.WARNING + str(HandShake_3['status']) + colors.bcolors.ENDC + 
                " ==>> " + colors.bcolors.FAIL + HandShake_3['title'] + colors.bcolors.HEADER + ' (' + HandShake_3['detail'] + ')' + colors.bcolors.ENDC)
        elif (str(r3) == '<Response [200]>'):
            print("Tiempo : " + colors.bcolors.OKBLUE + str(intentos) + colors.bcolors.ENDC +
              " segundos. STATUS : " + colors.bcolors.WARNING + str(HandShake_3['pushResult']) + colors.bcolors.ENDC )
            final_result = 1
        elif (str(r3) == '<Response [403]>'):
            print("Tiempo : " + colors.bcolors.OKBLUE + str(intentos) + colors.bcolors.ENDC +
              " segundos. STATUS : " + colors.bcolors.WARNING + str(HandShake_3['status']) + colors.bcolors.ENDC +
              " ==>> " + colors.bcolors.FAIL + HandShake_3['title'])
            final_result = 2
        else:        
            print("Tiempo : " + colors.bcolors.OKBLUE + str(intentos) + colors.bcolors.ENDC + " segundos. STATUS : " + colors.bcolors.FAIL + 'ERROR EN LA RESPUESTA' + colors.bcolors.ENDC )
            final_result = 0

### ******************************************************************************************************************************************************************************
### Paso 4º: con la respuesta del paso 3, sabremos si el usuario ha aceptado o denegado la notificación PUSH o si ha habido un error

if (final_result == 0):
    print( colors.bcolors.WARNING + '\n******************************************************************************' + colors.bcolors.ENDC)
    print( colors.bcolors.WARNING + '**' + colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.WARNING +
           'ERROR EN EL PROCESO DE AUTENTICACIÓN O TIEMPO AGOTADO  **' + colors.bcolors.ENDC)
    print( colors.bcolors.WARNING + '******************************************************************************' + colors.bcolors.ENDC)
elif(final_result == 1):
    print( colors.bcolors.OKGREEN + '\n*****************************************************************************' + colors.bcolors.ENDC)
    print( colors.bcolors.OKGREEN + '**' + colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.OKGREEN +
           'USUARIO AUTENTICADO SATISFACTORIAMENTE (PUSH APPROVED) **' + colors.bcolors.ENDC)
    print( colors.bcolors.OKGREEN + '*****************************************************************************' + colors.bcolors.ENDC)
elif(final_result == 2):
    print( colors.bcolors.FAIL + '\n*******************************************************************************' + colors.bcolors.ENDC)
    print( colors.bcolors.FAIL + '**'+ colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.FAIL + ' USUARIO '  + colors.bcolors.UNDERLINE +
           'NO AUTENTICADO SATISFACTORIAMENTE (PUSH DENIED)' + colors.bcolors.ENDC + colors.bcolors.FAIL + ' **' + colors.bcolors.ENDC)
    print( colors.bcolors.FAIL + '*******************************************************************************' + colors.bcolors.ENDC)
else:
    print( colors.bcolors.WARNING + '\n******************************************************************************' + colors.bcolors.ENDC)
    print( colors.bcolors.WARNING + '**' + colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.WARNING +
           ' ERROR NO ESPECIFICADO                                 **' + colors.bcolors.ENDC)
    print( colors.bcolors.WARNING + '******************************************************************************' + colors.bcolors.ENDC)

### ******************************************************************************************************************************************************************************
### END
