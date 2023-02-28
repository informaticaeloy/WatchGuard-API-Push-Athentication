### ******************************************************************************************************************************************************************************
### ESTA ES LA V2 DEL SCRIPT. REALIZA EL MISMO PROCESO QUE EL V1 PERO HACE LA COMPROBACIÓN EN EL AD DE SI LA CONTRASEÑA DEL USUARIO A ENVIAR EL PUSH
### ESTÁ CADUCADA. DE SER ASÍ, PRUEBA A HABILITARLA PARA HACER EL ENVÍO DEL PUSH Y LUEGO VUELVE A ESTABLECER SU ESTADO EN CADUCADA
### ******************************************************************************************************************************************************************************
import requests
import json
import colors
import datetime, time
import base64
import sys
import socket, platform

from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException, LDAPBindError

var_debug = True ### Cambiar a True para modo verbose

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
### ******************************************************************************************************************************************************************************
# Datos del usuario administrador con permisos para acceder al AD y datos de conexión y búsqueda del LDAP
usu_admin_ldap = 'usuario del AD con derecho de RW'
pass_admin_ldap = 'password del usuario del AD con derecho de RW'
domain_usu_ldap = 'dominio'
server_uri = f"ldap://<IP del servidor LDAP" 
search_base = 'CN=' + usuario + ',OU=NIVEL3,OU=NIVEL2,OU=NIVEL1,DC=DOMINIO,DC=loc'
                                            
### ******************************************************************************************************************************************************************************
def base_64_encoder(str_ID , str_Pass):    ### Este función convierte el usuario y password de la API a base64(usu:pass), necesario para ENVIAR LA PETICIÓN DE AUTENTICACIÓN (POST)

    message = str_ID + ':' + str_Pass

    message_bytes = message.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    return (base64_message)

### ******************************************************************************************************************************************************************************
def connect_ldap_server():

    print(colors.bcolors.OKGREEN + '==>> Entro en CONN [connect_ldap_server()]' + colors.bcolors.ENDC)
    try:
        server = Server(server_uri, get_info=ALL)
        print('Server STATUS: ', end=' ')
        print(colors.bcolors.OKBLUE + str(server) + colors.bcolors.ENDC)
        # username and password can be configured during openldap setup
        connection = Connection(server,          
                                user='{0}\\{1}'.format(domain_usu_ldap, usu_admin_ldap), 
                                password=pass_admin_ldap)
        bind_response = connection.bind() # Returns True or False 
    except LDAPBindError as e:
        connection = e
    print(colors.bcolors.FAIL + 'Intentando establecer la conexión con los siguientes parámetros:' + colors.bcolors.ENDC)
    
    print('URI....: ' + colors.bcolors.OKBLUE + server_uri + colors.bcolors.ENDC)
    print('User...: ' + colors.bcolors.OKBLUE + '{0}\\{1}'.format(domain_usu_ldap, usu_admin_ldap) + colors.bcolors.ENDC)
    print('Pass...: ' + colors.bcolors.OKBLUE + pass_admin_ldap + colors.bcolors.ENDC)
    if(bind_response == True):
        print(colors.bcolors.OKGREEN + 'Conexión establecida correctamente con LDAP' + colors.bcolors.ENDC)
    elif(bind_response == False):
        print(colors.bcolors.RED + 'ERROR estableciendo la conexión' + colors.bcolors.ENDC)
    
    print(colors.bcolors.OKGREEN + '<<== Salgo de CONN [connect_ldap_server()]' + colors.bcolors.ENDC)
    return (connection)

### ******************************************************************************************************************************************************************************  
def __cambia_PwdLastSet__(origen):
    print(colors.bcolors.OKGREEN + '==>> Entro en CAMBIA PASS [__cambia_PwdLastSet__()]' + colors.bcolors.ENDC)
    ldap_conn = connect_ldap_server()
    if (var_debug):
        print('Search_Base.....:', end=' ')
        print(colors.bcolors.OKBLUE + search_base + colors.bcolors.ENDC)
    try:
        # only the attributes specified will be returned
        ldap_conn.search(search_base, '(objectclass=person)', attributes=['displayName', 'mail', 'userAccountControl','sAMAccountName', 'pwdLastSet'])
        #ldap_conn.search(search_base=search_base, '(objectclass=person)',
        #                 attributes=['cn','sn','pwdLastSet','uidNumber'])
        # search will not return any values.
        # the entries method in connection object returns the results 
        results = ldap_conn.entries
    except LDAPException as e:
        results = e

    if (var_debug):
        print('Resultado de CONN :', end=' ')
        print(colors.bcolors.OKBLUE + str(results) + colors.bcolors.ENDC)
    mifecha = ldap_conn.entries[0].pwdLastset
    
    if (var_debug):
        print('Fecha de caducidad de la contraseña : ', end=' ')
        print (colors.bcolors.OKBLUE + str(mifecha) + colors.bcolors.ENDC)

    if (origen == 1): ### Si origen == 1, es que vengo de la comprobación del error 403 en __segundo_handshake__()
        if(str(ldap_conn.entries[0].pwdLastSet) ==  '1601-01-01 00:00:00+00:00'):
            print(colors.bcolors.WARNING + 'Contraseña CADUCADA. Procediendo a habilitarla momentáneamente' + colors.bcolors.ENDC)
            ldap_conn.modify(search_base,
                 {'pwdLastSet': [(MODIFY_REPLACE, [-1])]}) # Con el -1, activa la contraseña (la "descaduca")
            if (var_debug):
                print('Resultado del cambio: ', end=' ')
                print(colors.bcolors.RED + ldap_conn.result['description'] + colors.bcolors.ENDC)
                print(colors.bcolors.OKGREEN + '<<== Salgo de CAMBIA PASS' + colors.bcolors.ENDC)
            print(colors.bcolors.FAIL + 'Contraseña cambiada a NO CADUCADA' + colors.bcolors.ENDC)
            print('Intentando nuevamente la validación de contraseña y envío de token ' + colors.bcolors.OKGREEN + 'ahora que la contraseña está habilitada' + colors.bcolors.ENDC)
            return(1) ### Devulevo 1 al flujo del programa para repetir de nuevo la llamada a ___segundo_handshake__(), ahora que la contraseña está habilitada
        else:
            print(colors.bcolors.RED + 'Contraseña NO CADUCADA. La contraseña introducida por el usuario es incorrecta' + colors.bcolors.ENDC)
            print(colors.bcolors.OKGREEN + '<<== Salgo de CAMBIA PASS' + colors.bcolors.ENDC)
            return(2) ### Devuelvo 2 al flujo del programa para indicar que la contraseña no estaba caducada, por lo que el error 403 se debió a una contraseña introducida no válida
    elif(origen == 2): ### Si origen == 2, vuelvo a dejar la contraseña caducada
        ldap_conn.modify(search_base,
             {'pwdLastSet': [(MODIFY_REPLACE, [0])]}) # Con el 0, desactiva la contraseña (la caduca)
        print(colors.bcolors.RED + 'Dejo la contraseña Cambiada a SI caducada' + colors.bcolors.ENDC)

### ******************************************************************************************************************************************************************************    
def __main__():
    ### ******************************************************************************************************************************************************************************
    ### 1º Paso: enviar una petición de autenticación a la API
    print(colors.bcolors.HEADER + "*****************************************" + colors.bcolors.ENDC)
    print(colors.bcolors.HEADER + "*****************************************" + colors.bcolors.ENDC)
    print(colors.bcolors.HEADER + "==>> INICIO      _/\\_/\\_/\\_/\\_/\\_/\\_/\\_/\\" + colors.bcolors.ENDC)

### ******************************************************************************************************************************************************************************
def __primer_handshake__():
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

    return(HandShake_1)

### ******************************************************************************************************************************************************************************
def __segundo_handshake__(HandShake_1):
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
            return(1) ### Devuelvo 1 al flujo del programa para indicar que ha habido un problema con la contraseña. Puede ser errónea o estar caducada
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

    return(HandShake_2)

### ******************************************************************************************************************************************************************************
def __tercer_handshake__(HandShake_2):
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
    
        while ((intentos <= 10) and (str(r3) == '<Response [202]>')):
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

    return (final_result)

### ******************************************************************************************************************************************************************************
def __resultado_final__(final_result):
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
    elif(final_result == 3):
        print( colors.bcolors.FAIL + '\n*******************************************************************************' + colors.bcolors.ENDC)
        print( colors.bcolors.FAIL + '**'+ colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.FAIL + ' ERROR - '  + colors.bcolors.UNDERLINE +
               'CONTRASEÑA INCORRECTA' + colors.bcolors.ENDC + colors.bcolors.FAIL + ' **' + colors.bcolors.ENDC)
        print( colors.bcolors.FAIL + '*******************************************************************************' + colors.bcolors.ENDC)
    else:
        print( colors.bcolors.WARNING + '\n******************************************************************************' + colors.bcolors.ENDC)
        print( colors.bcolors.WARNING + '**' + colors.bcolors.ENDC + ' Resultado final: '+ colors.bcolors.WARNING +
               ' ERROR NO ESPECIFICADO                                 **' + colors.bcolors.ENDC)
        print( colors.bcolors.WARNING + '******************************************************************************' + colors.bcolors.ENDC)

### ******************************************************************************************************************************************************************************
### INICIO DEL FLUJO DEL PROGRAMA
### ******************************************************************************************************************************************************************************
__main__()
HandShake_1 = __primer_handshake__()
HandShake_2 = __segundo_handshake__(HandShake_1)

if(var_debug):
    print('Qué tipo de variable es HandShake_2 ?.........:', end=' ')
    print(type(HandShake_2))

### Si la función __segundo_handshake__() devuleve un int, es que ha dado fallo por contraseña. Puede ser incorrecta o estar caducada
### Llamamos a __cambia_PwdLastSet__() para comprobar si la contraseña está habilitada (en este caso el erro habrá sido por contraseña errónea) o 
###  si la contraseña está caducada (en este caso procedemos a habilitarla y volvemos a lanzar __segundo_handshake__() . Si vuelve a fallar con 
###   la contraseña habilitada es que es errónea, en caso contrario es simplemente que estaba caducada)
if(type(HandShake_2) == int): 
    print(colors.bcolors.HEADER + 'Llamo a CAMBIO PASS' + colors.bcolors.ENDC)
    resultado_cambio_pass = __cambia_PwdLastSet__(1) ### Llamamos a esta función con (1) para habilitar la contraseña caducada
    print(colors.bcolors.HEADER + 'Resultado Cambio Pass ' + str(resultado_cambio_pass) + colors.bcolors.ENDC)
    if(resultado_cambio_pass == 1): ### La contraseña estaba caducada y se ha habilitado
        print(colors.bcolors.HEADER + 'Llamo a SEGUNDO HANDSHAKE con handshake valiendo : ' + colors.bcolors.ENDC)
        print(colors.bcolors.OKCYAN + str(HandShake_1) + colors.bcolors.ENDC)
        HandShake_2 = __segundo_handshake__(HandShake_1)  
        if (type(HandShake_2) == int):
            print(colors.bcolors.WARNING + 'Imposible continuar: ' + colors.bcolors.FAIL + 'LA CONTRASEÑA ES INCORRECTA' + colors.bcolors.ENDC)
            __cambia_PwdLastSet__(2) ### Llamamos a esta función con (2) para caducar la contraseña, ya que el problema es que es incorrecta la contraseña y 
                                     ### además esta caducada. La hemos descaducado para hacer la consulta y el error era que es incorrecta. Lo dejamos como estaba
            final_result = 3 
        else:
            if (var_debug):
                print(colors.bcolors.HEADER + 'Segundo HandsShake nos devuleve :' + colors.bcolors.ENDC)
                print(colors.bcolors.OKCYAN + str(HandShake_2) + colors.bcolors.ENDC)
                print(type(HandShake_2))    
                print(colors.bcolors.HEADER + 'Llamo a TERCER HANDSHAKE con handshake valiendo : ' + colors.bcolors.ENDC)
                print(colors.bcolors.OKCYAN + str(HandShake_2) + colors.bcolors.ENDC)
            final_result = __tercer_handshake__(HandShake_2)
            if (var_debug):
                print(colors.bcolors.OKCYAN + 'TERCER hANDsHAKE NOS DEVUELVE ' + colors.bcolors.ENDC)
                print(colors.bcolors.OKCYAN + str(final_result) + colors.bcolors.ENDC)
    elif(resultado_cambio_pass == 2): ### La contraseña es incorrecta
        print(colors.bcolors.WARNING + 'Imposible continuar: ' + colors.bcolors.FAIL + 'LA CONTRASEÑA ES INCORRECTA' + colors.bcolors.ENDC)
        final_result = 3 
    else:
        final_result = 4 ### Algo ha fallado, controlamos el posible error
else:
    final_result = __tercer_handshake__(HandShake_2)

__resultado_final__(final_result)

print(colors.bcolors.HEADER + '*********\nBYE!!!\n*********' + colors.bcolors.ENDC)
### ******************************************************************************************************************************************************************************
### END
