#!/usr/bin/env python

import scapy.all as scapy
import time

def scan_fast(ip):
	scapy.arping(ip)

def scan(ip): #Scam utilizando Broadcast afim de varrer toda a rede interna
	requisicao = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF") #Mac de Broadcast
	requisicao_broadcast = broadcast/requisicao
	enviados_lista, recebidos_lista = scapy.srp(requisicao_broadcast, timeout=1) #Gera uma lita com pacotes enviados e recebidos
	#psrc , hwsrc
	for hosts in enviados_lista:
		#print(hosts[1].show) / Campos de interesse = psrc = IP , hwsrc = Mac
		print(hosts[1].psrc + "\t\t\t" + hosts[1].hwsrc)
		print("----- X ------- X ------- X -----")

def criar_lista_MacSeguro(ip, arquivo):
	requisicao = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
	requisicao_broadcast = broadcast/requisicao
	enviados_lista, recebidos_lista = scapy.srp(requisicao_broadcast, timeout=1)
	for hosts in enviados_lista:
		arquivo.write(hosts[1].hwsrc)
		arquivo.write("\n")
		#Pega os Mac's que estão dentrod a rede e adiciona como seguro

def  verifica_Macs(ip, arquivo):
	aux = 0 
	requisicao = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
	requisicao_broadcast = broadcast/requisicao
	enviados_lista, recebidos_lista = scapy.srp(requisicao_broadcast, timeout=1)
	
	for hosts in enviados_lista:
		if str(hosts[1].hwsrc+"\n") in arquivo:
			aux = 1  #Aux só é alterado pra 1 caso encontre o Mac dentrod a lista
		if aux == 0:
			print("\nMac fora da lista acessou a sua rede : " + hosts[1].hwsrc + " - " + hosts[1].psrc )     	


ip = "192.168.100.1/24"
arquivo = open("Macs.txt","r+")
lista_mac = []
for linhas in arquivo:
	lista_mac.append(linhas)
arquivo.close()

#criar_lista_MacSeguro(ip,arquivo)
while(1):
	verifica_Macs(ip,lista_mac)
	time.sleep(10)
