import sys
from scapy.all import *
from threading import Thread

# Variable global para controlar el ciclo infinito
exit_flag = False

# Función para capturar y analizar paquetes HTTP
def capture_http():
    print("Iniciando captura de solicitudes HTTP... (Presiona 'q' para regresar al menú)")
    while not exit_flag:
        packets = sniff(filter="tcp and port 80", count=1)
        for packet in packets:
            print("Solicitud HTTP detectada:")
            print(packet.show())
            print("")

# Función para capturar y analizar paquetes FTP
def capture_ftp():
    print("Iniciando captura de solicitudes FTP... (Presiona 'q' para regresar al menú)")
    while not exit_flag:
        packets = sniff(filter="tcp and port 21", count=1)
        for packet in packets:
            print("Solicitud FTP detectada:")
            print(packet.show())
            print("")

# Función para capturar y analizar paquetes TFTP
def capture_tftp():
    print("Iniciando captura de solicitudes TFTP... (Presiona 'q' para regresar al menú)")
    while not exit_flag:
        packets = sniff(filter="udp and port 69", count=1)
        for packet in packets:
            print("Solicitud TFTP detectada:")
            print(packet.show())
            print("")

# Función para mostrar el menú de selección
def menu():
    print("Selecciona el tipo de tráfico a monitorear:")
    print("1. HTTP")
    print("2. FTP")
    print("3. TFTP")
    print("4. Salir")
    choice = input("Ingrese el número de opción: ")
    return choice

# Función para esperar la tecla 'q' y regresar al menú
def wait_for_input():
    global exit_flag
    while True:
        key = input()
        if key == "q":
            exit_flag = True
            break

# Programa principal
def main():
    while True:
        choice = menu()
        if choice == "1":
            exit_flag = False
            capture_thread = Thread(target=capture_http)
            input_thread = Thread(target=wait_for_input)
            capture_thread.start()
            input_thread.start()
            capture_thread.join()
        elif choice == "2":
            exit_flag = False
            capture_thread = Thread(target=capture_ftp)
            input_thread = Thread(target=wait_for_input)
            capture_thread.start()
            input_thread.start()
            capture_thread.join()
        elif choice == "3":
            exit_flag = False
            capture_thread = Thread(target=capture_tftp)
            input_thread = Thread(target=wait_for_input)
            capture_thread.start()
            input_thread.start()
            capture_thread.join()
        elif choice == "4":
            print("Saliendo del programa...")
            sys.exit()
        else:
            print("Elección inválida. Por favor, selecciona una opción válida.")

if _name_ == "_main_":
    main()
