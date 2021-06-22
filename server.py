import socket
from Okamoto_Uchiyama import *
import time
import pickle
import binascii


# Número de bits el cual tendrán las llaves
prime = 1200

if (len(sys.argv)>1):
    m=str(sys.argv[1])
if (len(sys.argv)>2):
    prime=int(sys.argv[2])

# Se generan las llaves publicas y privadas
n,g,h,p,q=gen_key(prime) 

print('###########################################')
print("==Public key====",'\n')
print("n=",n,'\n')
print("g=",g,'\n')
print("h=",h,'\n')
print("==Private key (%d-bit prime)===" %prime)
print("p=",p,'\n')
print("q=",q,'\n')
print('###########################################')
print('\n\n\n')

# Se inicializa socket
sckt = socket.socket()
# Se asocia la direccion y puerto
sckt.bind(('localhost',8000))
# Permite la entrada de un cliente a la vez
sckt.listen(1)

while True:
    T_incial = time.time()

    # Acepta al cliente
    conexion, adress = sckt.accept()
    print("nueva conexion establecida",'\n')
    print(conexion)

    # Envía las tres llaves publicas
    conexion.send(str(n).encode('ascii'))
    time.sleep(1)
    conexion.send(str(g).encode('ascii'))
    time.sleep(1)
    conexion.send(str(h).encode('ascii'))

    # Crea el arreglo donde se guardará lo recibido por cliente
    ciphers_received = []
    data = ''

    while True:
        # Se recibe mensaje cifrado
        data = conexion.recv(2042)
        # Se extrae el largo del mensaje recibido
        data_len = int(data[:10])
        # Se verifica que el largo de el mensaje coincida con el valor enviado en el encabezado
        if len(data) - 10 == data_len:
            # Se verifica si es el mensaje de término, si lo es, se sale del loop for
            if str(pickle.loads(data[10:])) == 'end':
                break
            # Se agrega el mensaje cifrado a el arreglo, sin el encabezado
            ciphers_received.append(str(pickle.loads(data[10:])))
        else:
            print('Error al recibir: '+ str(pickle.loads(data[10:])))
    print('Se recibió toda la información!','\n')
    data_array = []


    # Se recorre el arreglo
    for line in range(len(ciphers_received)):

        cipher_str = ciphers_received[line]
        # El cifrado se transforma a entero
        cipher = int(cipher_str)
        # Se descifra con una de las llaves públicas y una de las privadas
        hash_bytes = decrypt(cipher, p, g)
        # Se decodifican y se corta trunca a un tamaño de 128, tamaño del output del algoritmo hash
        try:
            hash = binascii.hexlify(hash_bytes)[:128]
            data_array.append(str(hash))
        except:
            print('Error al decodificar')
        

    with open('data_recieved.txt', 'w') as file:
        for item in data_array:
            item = item[2:130]
            file.write('%s\n' % item)


    print('Terminó el proceso, hashes guardados en el archivo hash_client_end.txt','\n')
    # Se termina la conexión con el cliente
    T_final = time.time()
    conexion.close()
    
    T_conn = T_final - T_incial
    print("Conexión terminada, tiempo desde inicio de la conexión: " + str(T_conn))
    # Se cierra el servidor
    sckt.close()
    break

