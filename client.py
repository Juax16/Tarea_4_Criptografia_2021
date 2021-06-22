import socket
import pickle
import os
import time
from Okamoto_Uchiyama import *
from Cryptodome.Hash import SHA3_512
import binascii



# Comandos de Hashcat para los archivos 1-5
cmd1 = 'cd hashcat-6.2.2 & .\hashcat.exe -m 0 -a 0 -D 2 --outfile-format=2 -o ..\\op1.txt ..\\Hashes\\archivo_1 ..\\diccionarios\\diccionario_1.dict ..\\diccionarios\\diccionario_2.dict'
cmd2 = 'cd hashcat-6.2.2 & .\hashcat.exe -m 10 -a 0 -D 2 --outfile-format=2 -o ..\\op2.txt ..\\Hashes\\archivo_2 ..\\diccionarios\\diccionario_1.dict ..\\diccionarios\\diccionario_2.dict'
cmd3 = 'cd hashcat-6.2.2 & .\hashcat.exe -m 10 -a 0 -D 2 --outfile-format=2 -o ..\\op3.txt ..\\Hashes\\archivo_3 ..\\diccionarios\\diccionario_1.dict ..\\diccionarios\\diccionario_2.dict'
cmd4 = 'cd hashcat-6.2.2 & .\hashcat.exe -m 1000 -a 0 -D 2 --outfile-format=2 -o ..\\op4.txt ..\\Hashes\\archivo_4 ..\\diccionarios\\diccionario_1.dict ..\\diccionarios\\diccionario_2.dict'
cmd5 = 'cd hashcat-6.2.2 & .\hashcat.exe -m 1800 -a 0 -D 2 --outfile-format=2 -o ..\\op5.txt ..\\Hashes\\archivo_5 ..\\diccionarios\\diccionario_1.dict ..\\diccionarios\\diccionario_2.dict'

# Se ejecuta cada comando
t1 = time.time()    
os.system(cmd1)
t2 = time.time()
os.system(cmd2)
t3 = time.time()
os.system(cmd3)
t4 = time.time()
os.system(cmd4)
t5 = time.time()
os.system(cmd5)
t6 = time.time()

# Se calcula el tiempo demorado de cada crackeo
t_cmd1 = t2 - t1
t_cmd2 = t3 - t2
t_cmd3 = t4 - t3
t_cmd4 = t5 - t4
t_cmd5 = t6 - t5

print("T cmd1: "+ str(t_cmd1))
print("T cmd2: "+ str(t_cmd2))
print("T cmd3: "+ str(t_cmd3))
print("T cmd4: "+ str(t_cmd4))
print("T cmd5: "+ str(t_cmd5))

# Se inicilaiza sockets
sckt = socket.socket()

T_incial = time.time()

# Se conecta al servidor
sckt.connect(('localhost', 8000))
# Recibe las tres llaves públicas
rec1 = sckt.recv(3000)
time.sleep(1)
rec2 = sckt.recv(3000)
time.sleep(1)
rec3 = sckt.recv(3000)

# Las decodifica a ASCII
dec1 = rec1.decode('ascii')
dec2 = rec2.decode('ascii')
dec3 = rec3.decode('ascii')

# Las convierte a enteros
pblc_key_n = int(dec1)
pblc_key_g = int(dec2)
pblc_key_h = int(dec3)

print("Llaves recibidas")
print("n = " + str(pblc_key_n))
print("g = " + str(pblc_key_g))
print("h = " + str(pblc_key_h))

# Arreglo con el nombre de los archivos contenedores de las contraseñas
files = ['op1.txt','op2.txt','op3.txt','op4.txt','op5.txt']

# Se recorre el arreglo files
for file in files:
    # Se abre el archivo file correspondiente a en cada iteración
    fl = open(file, 'r')
    # Se recorre el archivo
    tt = 0

    for lines in fl:
        # Se extrae una linea
        line = lines.strip()
        # Se verifica que no sea un espacio en blanco o un salto de línea
        if line != '' and line != '\n':
            # Se codifica cada linea a utf-8 (por defecto)
            data = line.encode()
            # Se aplica hash SHA3-512
            ti = time.time_ns()
            hash_obj = SHA3_512.new(data)
            tf = time.time_ns() 
            tt = tt + tf - ti
            # Se guarda el output en hexadecimal
            hash_hex = hash_obj.hexdigest() 
            # Se cifra el hash con Okamoto-Uchiyama, utilizando las llaves públicas
            # EL hash pasa de hexadecimal a bytes
            cipher = encrypt(binascii.unhexlify(hash_hex), pblc_key_n, pblc_key_g, pblc_key_h)
            # Se transforma en string
            cipher_str = str(cipher)
            # Se utiliza pickle para convertir el cifrado a bytes
            data_to_send = pickle.dumps(cipher)
            # Se le agrega un encabezado de largo 10 con el largo del mensaje a enviar
            data_2 = bytes(f'{len(data_to_send):<{10}}', 'utf-8') + data_to_send
            # Se envia al servidor
            sckt.send(data_2)       
    print("Tiempo de demora en hashear del %s = %d nanosegundos" %(file ,tt))

# Se envía un mensaje de término
end_msg = 'end'
data_to_send = pickle.dumps(end_msg)
data_2 = bytes(f'{len(data_to_send):<{10}}', 'utf-8') + data_to_send
sckt.send(data_2)
# Se cierra la conexión
sckt.close()

T_final = time.time()
T_conn = T_final - T_incial

print("Tiempo de conexión: " + str(T_conn))
