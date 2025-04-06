# 📦 Protocoles de Transfert de Fichiers : FTP, SFTP, FTPS, TFTP

## 🧭 Table des matières

- [📦 Protocoles de Transfert de Fichiers : FTP, SFTP, FTPS, TFTP](#-protocoles-de-transfert-de-fichiers--ftp-sftp-ftps-tftp)
- [🔐 Protocoles de Communication Sécurisée : SSH, Telnet, RDP](#-protocoles-de-communication-sécurisée--ssh-telnet-rdp)
- [📡 Protocoles de Monitoring & Supervision : SNMP, Syslog, NetFlow, sFlow](#-protocoles-de-monitoring--supervision--snmp-syslog-netflow-sflow)
- [🧭 Protocoles de Routage : OSPF, BGP, RIP, EIGRP, IS-IS](#-protocoles-de-routage--ospf-bgp-rip-eigrp-is-is)
- [🔒 Protocoles VPN & Tunnels : IPsec, L2TP, PPTP, GRE](#-protocoles-vpn--tunnels--ipsec-l2tp-pptp-gre)
- [🛡️ Protocoles de Sécurité Réseau : 8021x, RADIUS, TACACS+](#-protocoles-de-sécurité-réseau--8021x-radius-tacacs)
- [🎙️ Protocoles Voix & Communication : SIP, RTP, RTCP, H.323](#-protocoles-voix--communication--sip-rtp-rtcp-h323)
- [📬 Protocoles de Messagerie : SMTP, POP3, IMAP](#-protocoles-de-messagerie--smtp-pop3-imap)
- [🔎 Protocoles de Découverte & Résidentiels : mDNS, SSDP, LLDP, NetBIOS](#-protocoles-de-découverte--résidentiels--mdns-ssdp-lldp-netbios)
- [📦 Protocoles de Transport Fondamentaux : TCP, UDP, ICMP, IGMP](#-protocoles-de-transport-fondamentaux--tcp-udp-icmp-igmp)


### 💡 Avant de commencer, qu’est-ce qu’une RFC ?
Les RFC (Request For Comments) sont des documents normatifs publiés par l’IETF (Internet Engineering Task Force). 

Ce sont des standards officiels ou historiques qui définissent les protocoles réseau, leur fonctionnement, leurs messages, leur syntaxe, etc.

➡ Par exemple, FTP est défini dans la RFC 959, TFTP dans la RFC 1350, et SFTP est spécifié via l’extension SSH dans les drafts IETF.
Quand je cite une RFC, cela signifie que le comportement du protocole est standardisé et reconnu officiellement.

## 🧱 FTP – File Transfer Protocol

Le protocole FTP, défini dans la RFC 959, est l’un des plus anciens mécanismes de transfert de fichiers. 

Il fonctionne selon un modèle client-serveur et repose sur une architecture double canal : un canal de commande (port TCP 21) et un canal de données (port TCP 20 ou dynamique en mode passif). 

Cela signifie que le client envoie des commandes (comme `LIST`, `RETR`, `STOR`) sur un canal et reçoit ou envoie les fichiers via un second.

### ⚠️ Limite majeure : les données et les identifiants transitent en clair. Cela rend FTP vulnérable à l’interception (sniffing), au spoofing, et aux attaques de type "man-in-the-middle".
### 🔍 Exemple : un développeur web utilisant FileZilla pour téléverser un site sur un serveur FTP hébergé.
### ✅ Commande terminal (client FTP) :
```bash 
ftp 192.168.1.100
```

Tu tapes cette commande dans un terminal Linux. Elle ouvre une session FTP avec l’adresse IP du serveur. 

Ensuite, tu entreras un login et un mot de passe. Tu peux ensuite utiliser ls, get fichier.txt, put fichier.txt, etc.

### 🛠️ Cas pratique Docker :
```bash 
docker run -d --name ftp-server -p 21:21 -p 30000-30009:30000-30009 \
    -e FTP_USER=test -e FTP_PASS=test123 \
    -e PASV_MIN_PORT=30000 -e PASV_MAX_PORT=30009 \
    stilliard/pure-ftpd
```
Lance un serveur FTP en conteneur avec l’utilisateur test:test123. Tu peux t’y connecter avec ftp localhost.

## 🔐 FTPS – FTP Secure (avec SSL/TLS)
Pour répondre aux faiblesses de sécurité du FTP, on a développé FTPS, qui encapsule le protocole FTP classique dans une couche SSL/TLS. 

Il en existe deux variantes :

- FTPS implicite : la connexion est automatiquement chiffrée dès le début (port TCP 990).

- FTPS explicite : la connexion débute en clair, puis passe au mode sécurisé avec la commande AUTH TLS (sur le port 21).

### 🔐 Grâce à FTPS, les échanges sont protégés via certificats numériques, assurant confidentialité et authenticité.
### 👨‍🏫 Exemple concret : une banque échangeant des rapports de conformité via un serveur FTPS avec certificats client.
### ✅ Commande terminal (tester serveur FTPS) :
```bash
openssl s_client -connect ftps.exemple.com:990
```
Cela teste la négociation TLS. Tu verras le certificat envoyé et la réussite ou l’échec du chiffrement.
🛠️ Cas pratique Docker :
```bash
docker run -d -p 21:21 -p 990:990 -p 30000-30009:30000-30009 \
    -e FTP_USER=ftpsuser -e FTP_PASS=securepass \
    stilliard/pure-ftpd:latest
```

Le serveur FTPS est actif sur les ports 21 et 990. Utilise FileZilla en mode FTPS explicite pour t’y connecter.

## 🛡️ SFTP – SSH File Transfer Protocol

À ne pas confondre avec FTPS, le SFTP est un protocole complètement distinct, basé sur SSH (port TCP 22). 

Contrairement à FTP/FTPS, il ne sépare pas les commandes des données. 

Il encapsule tout dans un flux SSH unique, offrant à la fois authentification forte (via mot de passe ou clés publiques) et chiffrement intégral du canal de bout en bout.

### ⚙️ SFTP est souvent utilisé dans les systèmes Unix/Linux (OpenSSH) et offre des fonctionnalités avancées : renommage atomique, permissions Unix, reprise de transfert, etc.
### 🔐 Exemple : un administrateur système accédant à un serveur Linux via sftp ou un script scp automatisé de sauvegarde quotidienne.
### ✅ Commande terminal :
```bash
sftp user@192.168.1.150
```

Connecte-toi avec un compte SSH. Tu peux utiliser get, put, ls, cd. Tout est chiffré.
### 🛠️ Cas pratique Docker (SFTP) :
```bash
docker run -d -p 22:22 -e SFTP_USERS="user:password" atmoz/sftp
```
Lance un conteneur SFTP avec le compte user:password. Tu peux t’y connecter avec sftp user@localhost.

## 📡 TFTP – Trivial File Transfer Protocol

Le TFTP est une version simplifiée et minimale de `FTP`, défini dans la RFC 1350. 

Il fonctionne sur UDP (port 69), ce qui le rend extrêmement léger, mais sans authentification ni chiffrement. TFTP utilise une séquence très limitée de commandes (`RRQ`, `WRQ`, `DATA`, `ACK`, `ERROR`), rendant son usage restreint à des cas précis.

### ⚙️ Il est très utilisé dans les environnements d’infrastructure : démarrage réseau via PXE Boot, mise à jour de firmware pour switchs/routeurs, dépôts de configuration d’équipements.
### 🧪 Exemple : un switch Cisco qui récupère sa configuration initiale via un serveur TFTP lors du boot.
### ✅ Commande terminal :
```bash
tftp localhost
> get fichier.conf
```


Tu te connectes à un serveur TFTP (port 69) et télécharges un fichier. Tout est non sécurisé et sans login.
### 🛠️ Cas pratique Docker (TFTP) :
```bash
docker run -d --name tftp -p 69:69/udp -v /tmp/tftp:/var/tftpboot \
    alpine:latest sh -c "apk add --no-cache tftp-hpa && in.tftpd -L -s /var/tftpboot"
```
Ce conteneur lance un TFTP. Place un fichier dans /tmp/tftp/ pour y accéder via TFTP depuis ton hôte.

## 📊 Synthèse comparative des protocoles de transfert de fichiers

| Protocole | Sécurité | Transport | Authentification           | Port(s)                        | Utilisation typique                   |
|-----------|----------|-----------|-----------------------------|--------------------------------|----------------------------------------|
| **FTP**   | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red) | 📦 TCP      | 🔓 Login en clair              | `21` (commande), `20` (données)        | 🌐 Web hosting, anciens scripts        |
| **FTPS**  | ![TLS](https://img.shields.io/badge/Chiffré_TLS-✅-green)    | 📦 TCP      | 🔐 Login + certificat SSL      | `21` (explicite), `990` (implicite)   | 🏢 B2B sécurisé, conformité            |
| **SFTP**  | ![SSH](https://img.shields.io/badge/Chiffré_SSH-✅-green)    | 📦 TCP      | 🔐 Login SSH / clé             | `22`                                  | 🖥️ Serveur Linux, backup              |
| **TFTP**  | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red) | 📡 UDP      | ❌ Aucun                       | `69`                                  | ⚙️ Firmware, PXE, équipements         |

___ 

# 🔐 Protocoles de Communication Sécurisée : SSH, Telnet, RDP

Les protocoles de communication sécurisée sont utilisés pour administrer à distance des équipements et serveurs dans des environnements réseau. 

Ils offrent différents niveaux de sécurité, d’interopérabilité et d’accessibilité. Les trois principaux sont :
- `SSH` (Secure Shell) : standard moderne, chiffré et robuste
- `Telnet` : protocole ancien, non sécurisé, encore utilisé pour certains tests
- `RDP` (Remote Desktop Protocol) : accès graphique à distance, principalement pour Windows

> Ces protocoles ont été normalisés dans différentes RFC ou implémentations propriétaires, et sont essentiels à maîtriser pour tout administrateur système et réseau.

## 🛡️ SSH – Secure Shell

SSH est un protocole sécurisé de communication distant, utilisé pour accéder à des serveurs de manière chiffrée (port TCP 22). 

Il remplace Telnet en offrant authentification par mot de passe ou clé publique, chiffrement du trafic, tunneling sécurisé, transfert de fichiers (SCP, SFTP) et redirection de ports.

### 💡 Basé sur un modèle client-serveur, SSH garantit confidentialité, intégrité et authenticité à travers des algorithmes modernes : RSA, ECDSA, Ed25519.
### 🔐 Exemple : un administrateur se connecte à un serveur Ubuntu pour le mettre à jour ou redémarrer un service via ssh.
### ✅ Commande terminal :
```bash
ssh admin@192.168.1.10
```
Tu ouvres une session distante sécurisée sur le serveur 192.168.1.10 avec l'utilisateur admin. Tout ce que tu tapes est chiffré.

### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 2222:22 --name ssh-server rastasheep/ubuntu-sshd
```
Ce conteneur lance un serveur SSH. Tu peux t’y connecter avec :
```bash
ssh root@localhost -p 2222
# Mot de passe : root
```

## ⚠️ Telnet – Terminal Network

Telnet (port TCP 23) permet une communication texte à distance, mais sans chiffrement. 

Les identifiants et les commandes passent en clair, rendant Telnet dangereux en production. 

Toutefois, il reste utile pour tester un port ouvert ou simuler une requête.

### 📺 Anciennement utilisé pour l’administration réseau, aujourd’hui remplacé par SSH dans 99 % des cas.
### 🧪 Exemple : un admin vérifie qu’un serveur web écoute sur le port 80 :
```bash
telnet 192.168.1.20 80
```
### ✅ Commande terminal (client telnet) :
```bash
telnet 192.168.1.10 23
```
Tu te connectes à distance sur le port 23. Tu verras s'afficher un login, mais tout est en clair.
### 🛠️ Cas pratique Docker :
```bash
docker run -d --name telnetd -p 2323:23 erichough/nethack-telnet
```
Ce conteneur propose une session Telnet sur le port 2323. Tu peux tester avec :
```bash
telnet localhost 2323
```
(ça lance un jeu… mais fonctionne comme Telnet ! 😄)

## 🖥️ RDP – Remote Desktop Protocol

RDP est un protocole propriétaire développé par Microsoft pour permettre l’accès graphique distant à un environnement Windows. 

Il fonctionne sur TCP 3389 et parfois en UDP également.

### 💡 Il prend en charge :
- Redirection de périphériques USB
- Authentification réseau (NLA)
- Chiffrement TLS
- Compression visuelle pour optimiser la bande passante
### 🎯 Exemple : un technicien support accède à distance au poste d’un utilisateur via mstsc.exe sous Windows ou Remmina sous Linux.
### ✅ Commande terminal Linux :
```bash
xfreerdp /v:192.168.1.30 /u:Administrateur /p:MonMotDePasse
```
Se connecte à un poste Windows distant via une interface graphique.
### 🛠️ Cas pratique VMware :
- Crée une VM Windows Server ou Windows 10
- Active RDP :
    - Panneau de configuration > Système > Accès à distance
    - Coche "Autoriser les connexions à distance"
    - Ouvre le port 3389 dans le pare-feu
- Puis connecte-toi depuis ta machine hôte avec :
```bash
mstsc.exe
```
Et tape l’IP de la VM pour ouvrir une session graphique.

## 📊 Synthèse comparative des protocoles d'accès distant 

| Protocole | Sécurité | Interface | Authentification | Port | Utilisation |
|-----------|----------|-----------|------------------|------|-------------|
| **SSH**    | ![Chiffré](https://img.shields.io/badge/Chiffré-✅-green) | 🖥️ Terminal  | 🔐 Login / clé RSA         | `22`   | 🔧 Admin serveur Linux, tunnels       |
| **Telnet** | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red) | 🖥️ Terminal  | 🔓 Login (en clair)         | `23`   | 🧪 Tests réseau, équipements anciens  |
| **RDP**    | ![Chiffré](https://img.shields.io/badge/Chiffré-✅-green) | 🖼️ Graphique | 👤 Compte Windows / NLA     | `3389` | 💻 Accès à distance Windows           |


___

# 📡 Protocoles de Monitoring & Supervision : SNMP, Syslog, NetFlow, sFlow

Un réseau bien configuré ne suffit pas. 

Il faut le surveiller en temps réel, détecter les anomalies, les lenteurs, les saturations… et anticiper les pannes. 

C’est là qu’interviennent les protocoles de monitoring & supervision.

Ces protocoles collectent, rapportent et diffusent des informations techniques sur l’état du réseau, des serveurs, des équipements, des flux et des logs. 

Ils permettent d’alimenter des outils comme `Zabbix`, `Grafana`, `PRTG`, `LibreNMS`, `ELK`, etc.

## 📊 SNMP – Simple Network Management Protocol

SNMP est un protocole standardisé (RFC 1157, RFC 1905) qui permet de collecter des métriques et états depuis des équipements réseau (`switchs`, `routeurs`, `serveurs`, `imprimantes`…). 

Il repose sur une structure appelée MIB (Management Information Base) et fonctionne via des OID (Object Identifier).

Il existe 3 versions :
- `SNMPv1 / v2c` : communautaires (ex : "public", "private")
- `SNMPv3` : sécurisé (chiffrement + authentification)
- `SNMP` utilise deux canaux :
    - `Polling` : le manager interroge régulièrement (snmpget, snmpwalk)
    - `Trap` : l’équipement envoie une alerte en temps réel
### ✅ Commande terminal (ex : récupérer uptime) :
```bash
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.3.0
```
Cette commande interroge un routeur sur son temps de fonctionnement (uptime) avec la communauté public.
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 161:161/udp --name snmpd nouchka/snmpd
```
Conteneur SNMP prêt à l’emploi. 

Tu peux le sonder avec :
```bash
snmpwalk -v2c -c public localhost.
```


## 🧾 Syslog – System Logging Protocol

Syslog (RFC 5424) est un protocole permettant aux équipements, serveurs ou applications d’envoyer leurs journaux système à un serveur centralisé. 

Il utilise `UDP 514` ou `TCP 514`, et structure les logs en niveaux de priorité (emergency, error, info…).

Les logs sont texte brut, compatibles avec des outils comme :
- `Rsyslog`
- `syslog-ng`
- `journald`
- `Graylog`
- `ELK`
- `Loki`
- `Splunk`
### 🎯 Exemple : un pare-feu envoie ses logs à un serveur syslog central pour être analysé et archivé.
### ✅ Commande terminal (générer un log local) :
```bash
logger -p local0.notice "Test de supervision SNMP"
```
Cela envoie un log syslog de niveau "notice" avec la balise "local0".
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 514:514/udp -v /tmp/syslog:/var/log/syslog --name syslog-server balabit/syslog-ng
```
Un serveur syslog minimal. Tu peux rediriger des logs depuis ta machine ou une autre VM vers ce conteneur.

## 📶 NetFlow – Cisco Flow Monitoring

NetFlow est un protocole propriétaire développé par Cisco, qui analyse les flux réseau IP (qui parle à qui, combien, quand, comment). Il capture :
- `IP source/destination`
- `Ports`, `protocole`
- `Volume de données`
- `Durée du flux`
### 📦 Chaque flux est exporté vers un collecteur NetFlow, comme nfdump, ntopng, PRTG, SolarWinds, etc.
Il existe plusieurs versions (`v5`, `v9`, `IPFIX`). NetFlow fonctionne généralement sur UDP 2055.
### ✅ Commande terminal (collecte passive avec nfdump) :
```bash
nfcapd -l /tmp/netflow -p 2055
```
Lancer un collecteur NetFlow sur UDP 2055 qui sauvegarde les flux dans /tmp/netflow.
### 🛠️ Cas pratique Docker (NetFlow) :
```bash
docker run -d -p 2055:2055/udp --name netflow-collector dreibh/netflow-tools
```
Tu peux envoyer des flux NetFlow depuis une VM Linux configurée avec softflowd ou fprobe.

## 📊 sFlow – Sampled Flow

sFlow est une alternative à NetFlow, mais plus légère. 

Il échantillonne le trafic (ex : 1 paquet sur 1000) au lieu de tout capturer, ce qui le rend adapté aux grands réseaux, datacenters ou très gros volumes.

Il collecte également des statistiques de performance, trames `Ethernet`, états `SNMP`, etc. C’est un protocole stateless basé sur `UDP 6343`.


### ✅ Commande terminal (capture avec sflowtool) :
```bash
sflowtool -p 6343
```
Démarre un collecteur sFlow. Tu verras les trames analysées ligne par ligne.
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 6343:6343/udp --name sflow-collector sflow/sflowtool
```
Lance un collecteur sFlow prêt à recevoir des échantillons depuis un switch, VM ou simulateur réseau.

## 📊 Synthèse comparative des protocoles de supervision réseau (version visuelle)

| Protocole | Sécurité                             | Fonction principale           | Transport     | Utilisé pour                          | Port(s)   |
|-----------|--------------------------------------|-------------------------------|---------------|----------------------------------------|-----------|
| **SNMP**   | ![v3 Chiffré](https://img.shields.io/badge/v3-Chiffré-green)   | 📊 Collecte d’états/métriques | 📡 UDP         | 📈 Monitoring actif & passif           | `161/162` |
| **Syslog** | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)    | 🗂️ Centralisation de logs      | 🔄 UDP / TCP   | 📝 Journalisation d’événements         | `514`     |
| **NetFlow**| ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)    | 🔎 Analyse des flux IP         | 📡 UDP         | 📶 Monitoring de trafic                 | `2055`    |
| **sFlow**  | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)    | 🧪 Échantillonnage léger       | 📡 UDP         | 🚀 Supervision rapide grands réseaux    | `6343`    |

___

# 🌐 Protocoles de Routage : OSPF, BGP, RIP, EIGRP, IS-IS

Les protocoles de routage permettent aux routeurs et équipements d’échanger automatiquement les routes IP d’un réseau à l’autre, sans configuration manuelle statique.

Il existe deux grandes familles :
- IGP (Interior Gateway Protocol) : à l’intérieur d’un AS (Autonomous System) – ex : OSPF, RIP, EIGRP, IS-IS
- EGP (Exterior Gateway Protocol) : entre AS – ex : BGP

Ces protocoles sont essentiels pour la convergence réseau, l’équilibrage de charge, la redondance et la résilience des infrastructures d’entreprise et d’Internet.

## 🧭 OSPF – Open Shortest Path First

OSPF (RFC 2328 pour v2, RFC 5340 pour v3) est un protocole IGP à état de liens, hiérarchisé en zones, utilisant l’algorithme Dijkstra (SPF) pour calculer le chemin le plus court basé sur un coût métrique (bandwidth, etc.).


- 🔹 Supporte VLSM, CIDR, authentification, convergence rapide
- 🔹 Fonctionne par LSA (Link-State Advertisements) échangés avec les voisins
- 🔹 Utilise l’IP protocole 89
### ✅ Commande terminal Cisco :
```bash
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
```
Active OSPF sur l’interface correspondant à 192.168.1.X dans l’area 0.
### 🛠️ Cas pratique GNS3 ou EVE-NG :
Utilise deux routeurs Cisco virtuels, connectés via une interface eth. Configure OSPF sur chacun.


## 🌐 BGP – Border Gateway Protocol

BGP (RFC 4271) est le protocole de routage d’Internet. 

Il est utilisé pour le routage inter-AS, très scalable, basé sur des politiques et non sur une métrique automatique.

- 🔹 Utilise TCP 179 pour la session
- 🔹 Chaque route est associée à un AS_PATH, LOCAL_PREF, MED, etc.
- 🔹 Fonctionne en eBGP (entre AS) ou iBGP (au sein d’un AS)
### ✅ Commande terminal Cisco :
```bash
router bgp 65001
 neighbor 192.168.1.2 remote-as 65002
 network 10.0.0.0 mask 255.255.255.0
```
Crée une session BGP avec un autre AS (65002), et annonce le réseau 10.0.0.0/24.
### 🛠️ Cas pratique Docker :
```bash
docker run -d --name frr --network host frrouting/frr
```
Lance un conteneur FRRouting. Configure BGP avec :
```bash
vtysh
conf t
router bgp 65001
 neighbor 192.168.1.2 remote-as 65002
```

## 🌀 RIP – Routing Information Protocol
RIP (RFC 1058 pour v1, RFC 2453 pour v2) est un protocole à vecteur de distance, très simple, mais obsolète. 

Il choisit le chemin avec le moins de sauts (hops). Limité à 15 sauts, convergence lente.
- 🔹 Utilise UDP 520
- 🔹 Envoie sa table toutes les 30 secondes
- 🔹 V2 supporte subnetting et multicast
### ✅ Commande Cisco :
```bash
router rip
 version 2
 network 192.168.1.0
```
Active RIP v2 sur 192.168.1.X

### 🛠️ Cas pratique Docker avec Quagga (RIP) :
```bash
docker run -d --name quagga -e ENABLE_RIP=yes -p 520:520/udp networkop/quagga
```

## 🔁 EIGRP – Enhanced Interior Gateway Routing Protocol

EIGRP est un protocole Cisco propriétaire, hybride entre vecteur de distance et état de lien. 

Il utilise DUAL (Diffusing Update Algorithm) pour déterminer le meilleur et backup route.
- 🔹 Utilise l’IP protocole 88
- 🔹 Calcule la métrique en fonction de bande passante, délai, charge, fiabilité
- 🔹 Ne supporte pas de zones comme OSPF
### ✅ Commande Cisco :
```bash
router eigrp 100
 network 192.168.1.0
```
Active EIGRP pour AS 100 sur 192.168.1.X
### 🛠️ Cas pratique : uniquement sur IOS ou CML (Cisco Modeling Labs)

## 🧱 IS-IS – Intermediate System to Intermediate System

IS-IS est un protocole IGP comme OSPF, utilisé surtout par les FAI, dans les réseaux très stables. 

Fonctionne sur le protocole CLNS, pas sur IP directement.
- 🔹 Hiérarchisé en niveau 1 et 2 (équivalent aux zones OSPF)
- 🔹 Très scalable et rapide en convergence
- 🔹 Fonctionne sans IP au niveau de la découverte
### ✅ Commande Juniper ou Cisco :
```bash
router isis
 net 49.0001.1921.6800.1001.00
```
Définit un identifiant NET unique pour le routeur
### 🛠️ Cas pratique avec JunOS (VM Juniper) ou Cisco IOS XR

## 📊 Synthèse comparative des protocoles de routage (version visuelle)

| Protocole | Hiérarchie                          | Type             | Métrique                   | Port / Protocole | Usage typique                       |
|-----------|-------------------------------------|------------------|----------------------------|------------------|--------------------------------------|
| **OSPF**   | ✅ Zones                             | 🧭 IGP            | 📏 Coût (bandwidth)         | IP Proto `89`    | 🏢 Réseau entreprise                 |
| **BGP**    | ❌ Non                               | 🌐 EGP            | 🧩 Politique (AS_PATH)      | TCP `179`        | 🌍 Internet, FAI, multi-AS          |
| **RIP**    | ❌ Non                               | 📡 IGP            | 🔁 Nombre de sauts          | UDP `520`        | 🕸️ Réseaux legacy, simple           |
| **EIGRP**  | ❌ Non                               | ⚙️ IGP (Cisco)     | ⏱️ Bande passante, délai     | IP Proto `88`    | 🛠️ Réseaux Cisco homogènes          |
| **IS-IS**  | ✅ L1 / L2                           | 🧭 IGP            | 💡 Largeur de bande         | 📦 CLNS          | 🧵 Backbone opérateurs              |

___

# 🔒 Protocoles VPN & Tunnels : IPsec, L2TP, PPTP, GRE

Les VPN (Virtual Private Networks) permettent de créer un tunnel sécurisé entre deux hôtes ou deux réseaux distants via Internet, comme s’ils étaient physiquement connectés. 

Ils assurent :
- Confidentialité (chiffrement)
- Authenticité (authentification des pairs)
- Intégrité (non altération des données)
- Encapsulation (tunneling IP dans IP)

Les tunnels peuvent être chiffrés (IPsec, L2TP/IPsec, PPTP) ou simples (GRE).
### 🔐 IPsec – Internet Protocol Security
IPsec (RFC 4301+) est la norme industrielle VPN. Il fonctionne en mode tunnel (réseau à réseau) ou mode transport (hôte à hôte). 

Il est composé de deux phases :
- IKE (Internet Key Exchange) → négociation cryptographique
- ESP (Encapsulating Security Payload) ou AH (Authentication Header)
### 🔐 IPsec protège les paquets IP avec chiffrement (AES, 3DES) et intégrité (SHA, HMAC)
### 🧩 Supporté nativement par Windows, Linux, Cisco, Fortinet, etc.
### ✅ Commande (Linux - StrongSwan) :
```bash
ipsec up vpn-tunnel
```
Active une connexion VPN IPsec définie dans /etc/ipsec.conf.
### 🛠️ Cas pratique Docker (IPsec site-to-site) :
IPsec n’est pas trivial en Docker à cause des modules kernel. Préfère une VM Debian avec StrongSwan :
```bash
apt install strongswan
```
# Édite /etc/ipsec.conf et ipsec.secrets puis :
```bash
ipsec restart && ipsec up vpn
```

## 🧰 L2TP – Layer 2 Tunneling Protocol

L2TP (RFC 2661) est un protocole de tunnel de niveau 2 (liaison), souvent couplé à IPsec pour chiffrer les données (L2TP/IPsec). 

Il encapsule les paquets dans UDP 1701 et offre des sessions PPP sur un tunnel IP.
### 📦 Utilisé pour les VPN clients Windows natifs, notamment dans les entreprises.
### ✅ Commande (client Linux) :
```bash
nmcli connection up l2tp-vpn
```
Lance une connexion L2TP/IPsec pré-configurée dans NetworkManager.
### 🛠️ Cas pratique VM :
VM Ubuntu/Debian avec xl2tpd + strongswan
ou serveur VPN Windows (RRAS) avec L2TP/IPsec

## ⚠️ PPTP – Point-to-Point Tunneling Protocol
PPTP est un protocole VPN ancien, basé sur GRE + TCP 1723. 

Il offre une encapsulation PPP mais aucune sécurité sérieuse. 

Le chiffrement MPPE est faible et les authentifications MS-CHAPv1/v2 sont cassées.
### ⛔ Déconseillé en production, utilisé parfois pour compatibilité ou tests simples.
### ✅ Commande (Linux) :
```bash
pptpsetup --server vpn.exemple.com --username user --password pass
```
### 🛠️ Cas pratique :
Utiliser une VM Windows avec serveur PPTP ou un container Linux avec pptpd. Exemple image :
```bash
docker run -d --privileged --name pptp -p 1723:1723 mobtitude/docker-pptp
```

## 🚇 GRE – Generic Routing Encapsulation
GRE est un protocole de tunneling non sécurisé (RFC 2784). 

Il permet d’encapsuler n’importe quel protocole L3 dans IP (ex : IPv6 sur IPv4). 

Très léger, il est souvent combiné à IPsec pour la sécurité.
### 📍 Utilisé pour OSPF entre sites, MPLS, VPN statiques
### 🔢 Utilise le protocole IP 47
### ✅ Commande (Linux) :
```bash
ip tunnel add gre1 mode gre remote 192.168.1.2 local 192.168.1.1 ttl 255
ip link set gre1 up
ip addr add 10.10.10.1/30 dev gre1
```
Crée un tunnel GRE entre deux machines Linux
### 🛠️ Cas pratique Docker :
GRE nécessite l’accès kernel → préférez 2 VMs Ubuntu :
### Sur VM1
```bash
ip tunnel add gre1 mode gre remote VM2-IP local VM1-IP
```
### Sur VM2
```bash
ip tunnel add gre1 mode gre remote VM1-IP local VM2-IP
```
## 📊 Synthèse comparative des protocoles VPN et de tunneling (version visuelle)

| Protocole     | Sécurité                          | Chiffrement      | Transport     | Port(s)              | Usage typique                         |
|---------------|-----------------------------------|------------------|---------------|-----------------------|----------------------------------------|
| **IPsec**       | ![Fort](https://img.shields.io/badge/Sécurité-Forte-brightgreen)      | 🔐 Oui (ESP)       | 🌐 IP direct   | UDP `500` / `4500`     | 🛰️ Site à site, mobile VPN             |
| **L2TP/IPsec**  | ![Moyen](https://img.shields.io/badge/Sécurité-Moyenne-yellow)        | 🔐 Via IPsec       | 📡 UDP         | UDP `1701` + `500/4500` | 📱 VPN client Windows / Mobile         |
| **PPTP**        | ![Faible](https://img.shields.io/badge/Sécurité-Faible-orange)        | 🔒 MPPE            | 🔄 TCP + GRE   | TCP `1723` + IP `47`    | 🧩 Obsolète, compatibilité Windows     |
| **GRE**         | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)           | ❌ Aucun           | 🌐 IP          | IP `47`                | 🧪 Tunnel simple, OSPF, labos          |

___

# 🛡️ Protocoles de Sécurité Réseau : 802.1X, RADIUS, TACACS+

Dans un environnement réseau sécurisé, il ne suffit pas d’être connecté pour avoir accès : il faut contrôler, authentifier et tracer chaque tentative de connexion. 

C’est ce que permettent ces trois protocoles :
- 802.1X : contrôle d’accès au niveau des ports
- RADIUS : authentification centralisée pour utilisateurs et équipements
- TACACS+ : contrôle d’accès granulaire, souvent utilisé pour les administrateurs

Ces protocoles sont complémentaires, et sont utilisés ensemble dans les architectures sécurisées.

## 🧷 802.1X – Port-Based Network Access Control

802.1X (IEEE 802.1X) est un protocole d’authentification réseau au niveau du port Ethernet ou Wi-Fi. 

Il repose sur un modèle à 3 rôles :
- Supplicant : l’utilisateur ou appareil (ex. PC)
- Authenticator : le switch ou point d’accès
- Server : le serveur d’authentification (souvent RADIUS)

## 💡 802.1X utilise EAP (Extensible Authentication Protocol) pour transporter l’identité et les certificats, mots de passe ou jetons.
## 🎯 Très utilisé dans les entreprises, écoles, hôtels : tu branches un PC → pas d’accès sans authentification.
## ✅ Commande de vérification Cisco :
```bash
show authentication sessions interface Gi1/0/1
```
Montre l’état 802.1X sur le port du switch : Authorized ou Unauthenticated.
### 🛠️ Cas pratique avec VM + FreeRADIUS + Switch :
- Une VM Debian avec freeradius
- Un switch ou simulateur (GNS3/EVE-NG)
Active 802.1X sur l’interface et pointe vers RADIUS :
```bash
dot1x system-auth-control
interface Gi1/0/1
 authentication port-control auto
```

## 🌐 RADIUS – Remote Authentication Dial-In User Service

RADIUS (RFC 2865) est un protocole d’authentification, autorisation et accounting (AAA) utilisé pour valider les utilisateurs ou équipements. 

Il fonctionne sur :
- UDP 1812 (authentification)
- UDP 1813 (accounting)

Il centralise l’authentification pour :
- VPNs
- Wi-Fi entreprise
- 802.1X
- Portail captif

### 💡 Il échange des Access-Request, Access-Accept et Access-Reject.
### ✅ Commande test (Linux avec radtest) :
```bash
radtest alice password localhost 0 testing123
```
Vérifie qu’un utilisateur alice peut s’authentifier auprès du serveur RADIUS (ici localhost).
### 🛠️ Cas pratique Docker (FreeRADIUS) :
```bash
docker run -d --name freeradius -p 1812:1812/udp -p 1813:1813/udp freeradius/freeradius-server
```
Configure /etc/raddb/clients.conf et /etc/raddb/users pour ajouter utilisateurs et clients (ex : switchs, APs).

## 🔒 TACACS+ – Terminal Access Controller Access-Control System Plus

TACACS+ (protocole Cisco) est une alternative à RADIUS, plus orientée contrôle des sessions admin et logs de commandes.
Il fonctionne sur :
- `TCP 49`
Et permet de dissocier authentification, autorisation et accounting (AAA)
### 💡 Avantage : tu peux dire qu’un admin peut faire show mais pas reload. Tu loggues chaque commande tapée sur les routeurs.
### 🎯 Idéal dans les environnements critiques avec des équipements Cisco (ou compatibles).
### ✅ Commande Cisco :
```bash
aaa new-model
tacacs-server host 192.168.1.10 key MonSecret
aaa authentication login default group tacacs+ local
```
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 49:49/tcp --name tacacs-server ciscotalos/tac_plus
```
Tu peux configurer /etc/tac_plus.conf pour déclarer tes utilisateurs et permissions.

## 📊 Synthèse comparative des protocoles d'authentification réseau (version visuelle)

| Protocole   | Rôle principal                     | Transport     | Port   | Authentifie quoi ?                   | Particularité                                               |
|-------------|------------------------------------|---------------|--------|--------------------------------------|-------------------------------------------------------------|
| **802.1X**   | 🔐 Contrôle d’accès port            | 🔗 EAP over LAN | N/A    | 🖧 Appareils réseau                   | 🛠️ Nécessite switch + serveur RADIUS                        |
| **RADIUS**   | 🧭 Auth centralisée AAA             | 📡 UDP         | `1812` | 👥 Utilisateurs, VPN, Wi-Fi           | ⚡ Léger, répandu, non orienté admin                         |
| **TACACS+**  | 🛡️ Auth et autorisation admin       | 🔄 TCP         | `49`   | 👨‍💼 Admins, équipements Cisco         | 📋 Détaille et trace les commandes admin (oriented CLI)     |

___

# 🎙️ Protocoles Voix & Communication : SIP, RTP, RTCP, H.323

Les protocoles de voix sur IP (VoIP) permettent de transporter la voix, la vidéo et les signaux de communication en temps réel sur des réseaux IP.
On distingue deux types :
- 📞 Signaling (signalisation) : établir, modifier, terminer les appels (ex : SIP, H.323)
- 📡 Transport média : transporter la voix/vidéo (RTP), et la superviser (RTCP)

Ces protocoles sont utilisés dans :
- Téléphonie IP (IPBX, softphones)
- Centres d'appels
- Conférences audio/vidéo
- WebRTC, visioconférences, Teams/Zoom

## ☎️ SIP – Session Initiation Protocol
SIP (RFC 3261) est le standard ouvert pour l’établissement, la modification et la terminaison des appels VoIP. 

Il fonctionne en mode texte (style HTTP) sur :
- `UDP` ou `TCP 5060`
- `TLS 5061` (SIPS)
### 💬 SIP utilise des messages INVITE, ACK, BYE, REGISTER, etc., pour :
- Initier une session
- Négocier les codecs
- Terminer l’appel
### 🔐 Peut être couplé à TLS pour chiffrer la signalisation, et à SRTP pour le média.
### ✅ Commande terminal (voir en CLI SIP) :
`sngrep`

Affiche en temps réel les appels SIP capturés sur ton interface réseau (super outil CLI !)
### 🛠️ Cas pratique Docker (serveur SIP) :
```bash
docker run -d -p 5060:5060/udp -p 10000-20000:10000-20000/udp --name sip asterisk/asterisk
```
Lance un serveur Asterisk SIP. Configure un softphone (Zoiper, Linphone) pour t’y connecter avec un compte SIP.

## 🎧 RTP – Real-time Transport Protocol

RTP (RFC 3550) est utilisé pour transporter les flux audio et vidéo (VoIP, visioconf, streaming).
Il est déclenché par SIP ou H.323, mais ne nécessite pas de connexion préalable.
### 💡 Fonctionne sur des ports UDP dynamiques pair/impair, souvent 10000–20000.
### 📦 Contient : codec (G.711, G.729, Opus…), timestamp, numéro de séquence
### ✅ Capture réseau (Wireshark) :
Filtre :
```bash
rtp || udp.port >= 10000 && udp.port <= 20000
```
Te montre les flux RTP en cours, tu peux écouter les conversations avec Wireshark (→ lecture RTP stream)
### 🛠️ Cas pratique :
- Lance deux softphones (Zoiper) sur deux machines
- Connecte-les au serveur SIP (Asterisk ou FreePBX)
- Passe un appel → observe le RTP


## 📈 RTCP – Real-time Control Protocol
RTCP est le compagnon de RTP. Il ne transporte pas de voix, mais fournit :
- `Latence`
- `Jitter`
- `Pertes de paquets`
- `Qualité de service (QoS)`
Il utilise le port suivant celui de RTP (ex : si RTP sur 10000, RTCP sur 10001).
### 💬 RTCP envoie des rapports périodiques (Sender/Receiver Reports) entre les pairs pour surveiller la qualité.
### ✅ Commande de capture :
```bash
tcpdump udp port 10001
```
Observe les paquets RTCP envoyés pendant un appel.
### 🛠️ Cas pratique :
- Même setup SIP+RTP
- Active la capture réseau (Wireshark)
- Cherche les messages RTCP SR, RR, SDES, etc.


## 🎥 H.323 – ITU Protocol Suite for Multimedia Communication
H.323 est une ancienne suite de protocoles VoIP définie par l’UIT-T avant SIP.
Elle est plus lourde, mais encore utilisée dans :
- Visioconférences d’entreprise
- Infrastructure Cisco, Avaya, etc.

Fonctionne via plusieurs sous-protocoles :
- H.225 : signalisation d’appel
- H.245 : négociation des médias
- RTP : transport de la voix
### 🧠 Supporte aussi T.120 (data), H.261 (vidéo), G.711, G.729 (audio)
### ✅ Commande de test :
Wireshark → filtre :
```bash
h225 || h245
```
### 🛠️ Cas pratique :
Utilise une VM avec Ekiga ou Linphone en mode H.323
Configure un IPBX compatible H.323 (comme FreePBX ou 3CX avec interopérabilité)

## 📊 Synthèse comparative des protocoles VoIP et multimédia (version visuelle)

| Protocole | Sécurité                            | Rôle                    | Port(s)                       | Transport     | Utilisé dans...                        |
|-----------|-------------------------------------|--------------------------|-------------------------------|---------------|-----------------------------------------|
| **SIP**    | ![TLS](https://img.shields.io/badge/Sécurité-via_TLS-green)      | 📞 Signalisation            | `5060` (UDP/TCP), `5061` (TLS) | ✉️ Texte      | ☎️ IPBX, softphones, WebRTC              |
| **RTP**    | ![Aucune](https://img.shields.io/badge/Sécurité-Faible_or_SRTP-orange) | 🎙️ Transport voix          | `10000–20000+` (UDP pair)      | 🧱 Binaire     | 📡 Tous appels VoIP / vidéo             |
| **RTCP**   | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)      | 📊 Supervision QoS          | RTP+1 (UDP impair)             | 🧱 Binaire     | 📈 Qualité d’appel, statistiques        |
| **H.323**  | ![Optionnel](https://img.shields.io/badge/Sécurité-TLS_en_option-yellow) | 📦 Signalisation + média   | `1720` + dynamiques            | 🧱 Binaire     | 🖥️ Conférence, visio legacy             |


___

# 📬 Protocoles de Messagerie : SMTP, POP3, IMAP

Les protocoles de messagerie servent à envoyer, recevoir et gérer les e-mails.

Chaque protocole a un rôle bien défini dans l’écosystème mail :
- SMTP → envoyer les messages
- POP3 → recevoir les messages et les supprimer du serveur
- IMAP → recevoir et gérer les messages sur le serveur

Les protocoles mail sont normalisés via des RFC et s’appuient sur des ports bien connus, souvent chiffrés en TLS/SSL dans les environnements modernes.

## 📤 SMTP – Simple Mail Transfer Protocol
SMTP (RFC 5321) est le protocole d’envoi de mail entre clients et serveurs ou entre serveurs.

Il fonctionne de manière push (émetteur vers destinataire).

### 🔢 Ports :
- `25` → serveur à serveur (non chiffré ou STARTTLS)
- `587` → client authentifié (soumis)
- `465` → SMTP chiffré (SSL/TLS implicite)
### 🧠 Utilise une séquence textuelle :
`EHLO`, `MAIL` `FROM`, `RCPT` `TO`, `DATA`, `QUIT`
### ✅ Commande terminal (envoi SMTP brut) :
```bash
telnet smtp.gmail.com 587
# Puis tape manuellement :
EHLO test.local
MAIL FROM:<ton@domaine.com>
RCPT TO:<cible@exemple.com>
DATA
Subject: Test SMTP

Ceci est un test.
.
QUIT
```
Tu peux simuler un envoi SMTP sans client mail.
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 25:25 -p 587:587 --name postfix mailhog/postfix
```
Serveur Postfix minimal. Associe-le à Mailhog pour voir les mails en réception dans une UI.


## 📥 POP3 – Post Office Protocol v3
POP3 (RFC 1939) est un protocole de réception qui télécharge les mails et les supprime du serveur.

Il fonctionne en mode pull, simple, peu adapté au multi-appareil.

### 🔢 Ports :
- `110` : non chiffré
- `995` : SSL/TLS (implicite)
### 💡 Utilisé dans des scénarios : messagerie simple, environnement à bande passante limitée, clients mails locaux (Thunderbird, Outlook…).
### ✅ Commande POP3 (test simple avec Telnet) :
```bash
telnet mail.exemple.com 110
USER utilisateur
PASS motdepasse
LIST
RETR 1
QUIT
```
Tu te connectes directement au serveur POP3, listes les mails, et récupères le 1er.
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 110:110 -p 995:995 --name dovecot popstabled/dovecot
```
Conteneur Dovecot prêt à accepter des connexions POP3. Assure-toi que le user est défini dans la conf.

## 📂 IMAP – Internet Message Access Protocol

IMAP (RFC 3501) permet d’accéder aux mails sans les télécharger, tout en gardant la synchronisation sur plusieurs appareils.

### 🔢 Ports :
- `143` : non chiffré
- `993` : SSL/TLS
### 💡 Tu peux :

- Lire, déplacer, supprimer des mails
- Créer des dossiers
- Gérer les états (lu, non lu, marqué…)
### 📦 C’est le standard moderne utilisé par Gmail, Outlook, webmail, smartphones, etc.
### ✅ Commande IMAP (test avec OpenSSL) :
```bash
openssl s_client -connect mail.exemple.com:993
# Puis tape :
a login utilisateur motdepasse
a list "" "*"
a select INBOX
a fetch 1 body[]
```
Tu vois les messages, tu les lis, tu navigues dans les dossiers IMAP.
### 🛠️ Cas pratique Docker (Dovecot IMAP) :
```bash
docker run -d -p 143:143 -p 993:993 --name imap dovecot/dovecot
```

Même conteneur que POP3, supporte les deux protocoles. Configure les boîtes aux lettres dans /etc/dovecot/.

## 📊 Synthèse comparative des protocoles de messagerie (version visuelle)

| Protocole | Sécurité                              | Rôle                     | Mode   | Ports                | Spécificité                                       |
|-----------|---------------------------------------|--------------------------|--------|----------------------|---------------------------------------------------|
| **SMTP**   | ![STARTTLS](https://img.shields.io/badge/Sécurité-STARTTLS_/_TLS-yellowgreen) | 📤 Envoi de mails         | 📬 Push | `25` / `587` / `465` | ✉️ Texte brut → relay ou livraison                 |
| **POP3**   | ![SSL/TLS](https://img.shields.io/badge/Sécurité-TLS_/_SSL-blue)             | 📥 Réception unique       | 📥 Pull | `110` / `995`        | 🗑️ Supprime localement après lecture              |
| **IMAP**   | ![SSL/TLS](https://img.shields.io/badge/Sécurité-TLS_/_SSL-blue)             | 📬 Réception + gestion    | 📥 Pull | `143` / `993`        | 📂 Dossiers, statuts, multi-devices               |

___

# 🔎 Protocoles de Découverte & Résidentiels : mDNS, SSDP, LLDP, NetBIOS

Ces protocoles servent à découvrir automatiquement des équipements, services ou noms d’hôtes dans un réseau local.

Ils sont indispensables dans les environnements sans DNS ou DHCP centralisé, ou pour automatiser l’inventaire et le dépannage.

Utilisés dans :
- Bureaux et entreprises
- Réseaux résidentiels (IoT, imprimantes, NAS)
- Déploiement de switches, bornes Wi-Fi, caméras IP

## 🌐 mDNS – Multicast DNS

mDNS (RFC 6762) est une version de DNS qui fonctionne en multicast local. 

Il résout les noms se terminant par .local, sans avoir besoin d’un serveur DNS.

### 💡 Utilisé par Apple Bonjour, Avahi (Linux), Chromecast, imprimantes, etc.
### 🔢 Utilise UDP port 5353, adresse multicast 224.0.0.251
### 🔍 Requêtes envoyées à tous les appareils du LAN. Chaque appareil répond pour lui-même.
### ✅ Commande terminal (Linux) :
```bash
avahi-browse -a
```
Affiche tous les services mDNS visibles (ex : imprimantes, services HTTP, AirPlay…)
### 🛠️ Cas pratique Docker :
```bash
docker run -d --network=host --name avahi-disco --privileged holgerfriedrich/avahi
```
Lance un daemon mDNS dans ton réseau pour simuler un appareil .local.

## 📺 SSDP – Simple Service Discovery Protocol (UPnP)

SSDP est utilisé pour découvrir les services UPnP dans les réseaux résidentiels (télévisions, imprimantes, NAS, box).

### 🧠 Basé sur HTTP-like via UDP port 1900, adresse multicast 239.255.255.250
### 💬 Fonctionne avec des requêtes M-SEARCH, auxquelles les appareils répondent en unicast avec leur description.
### 📦 Utilisé dans :
- DLNA, Plex
- Xbox, SmartTV, Windows Media
- Routeurs et box Internet
### ✅ Commande terminal :
```bash
gssdp-discover
```
Liste tous les périphériques répondant aux requêtes SSDP.
### 🛠️ Cas pratique Docker :
```bash
docker run -d --network=host --name ssdp-discover larsks/ssdp
```
Lance un simulateur ou analyseur SSDP dans ton LAN.

## 🔗 LLDP – Link Layer Discovery Protocol
LLDP (IEEE 802.1AB) est un protocole standard pour découvrir ses voisins de liaison directe (liaison Ethernet).

Contrairement à mDNS/SSDP, LLDP est utilisé pour l’inventaire réseau côté admin (équipements professionnels, switches, serveurs).

### 🔢 Fonctionne sur trame Ethernet directe, EtherType 0x88cc
### 💡 Envoie des TLV (Type-Length-Value) contenant :
- Nom de l’équipement
- Port
- Description
- VLAN, capacité, OSI Layer support
### ✅ Commande Linux (paquet lldpd) :
```bash
lldpctl
```
Affiche tous les voisins découverts via LLDP sur les interfaces réseau.
### 🛠️ Cas pratique Docker :
```bash
docker run -d --privileged --network=host --name lldpd lldpd/lldpd
```
Simule un switch ou un serveur avec LLDP actif. Utilise `lldpctl` ou `Wireshark` pour observer.


## 💾 NetBIOS – Network Basic Input Output System
NetBIOS est un protocole ancien utilisé dans les réseaux Windows pour :
- Résoudre les noms d’ordinateur (avant DNS)
- Partager fichiers et imprimantes
- Gérer les groupes de travail

### 📡 Utilise les ports :
- UDP 137 (Nom)
- UDP 138 (Datagram)
- TCP 139 (Session)
### 💬 Résolution via broadcast LAN, non sécurisé.
### 📛 Encore utilisé dans certaines imprimantes, équipements, ou pour rétrocompatibilité SMBv1.
### ✅ Commande Windows :
```bash
nbtstat -A 192.168.1.10
```
### ✅ Commande Linux :
```bash
nmblookup <nom-machine>
```
### 🛠️ Cas pratique Docker :
```bash
docker run -d --name samba -p 137-139:137-139/udp dperson/samba -p
```
Conteneur Samba activant NetBIOS + partage réseau dans un LAN.

## 📊 Synthèse comparative des protocoles de découverte réseau (version visuelle)

| Protocole  | Sécurité                                | Rôle                     | Port(s)          | Transport   | Utilisation                        |
|------------|-----------------------------------------|--------------------------|------------------|-------------|------------------------------------|
| **mDNS**     | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)              | 🌐 Résolution noms locaux | UDP `5353`       | 📡 Multicast | `.local`, imprimantes               |
| **SSDP**     | ![Faible](https://img.shields.io/badge/Sécurité-Faible-orange)           | 🛰️ Découverte de services | UDP `1900`       | 📡 Multicast | 🧩 DLNA, UPnP, TV, IoT              |
| **LLDP**     | ![L2 only](https://img.shields.io/badge/Sécurité-L2_only-green)          | 🧭 Découverte directe L2  | EtherType `88cc` | 🔌 Ethernet  | 🏢 Inventaire réseau pro            |
| **NetBIOS**  | ![Très faible](https://img.shields.io/badge/Sécurité-Très_faible-red)    | 🧾 Nom d’hôte + partages  | UDP `137-139`    | 📢 Broadcast | 🖥️ SMB, anciens réseaux Windows     |

___

# 📦 Protocoles de Transport Fondamentaux : TCP, UDP, ICMP, IGMP

Les protocoles de transport assurent la livraison des données entre les hôtes sur un réseau IP.

Ils opèrent entre la couche réseau (IP) et la couche application dans le modèle OSI.

Chaque protocole a ses propres avantages, cas d’usage et limitations.


## 🔁 TCP – Transmission Control Protocol

TCP (RFC 793) est un protocole orienté connexion. 

Il garantit que :
- Les données sont reçues dans l’ordre
- Il n’y a pas de perte
- Les paquets sont retransmis en cas d’erreur

### 🔹 Utilisé pour : HTTP, HTTPS, FTP, SSH, SMTP, IMAP, etc.
### 🔹 Fonctionne en établissant un 3-way handshake :
- `SYN` → demande de connexion
- `SYN-ACK` → réponse du serveur
- `ACK` → confirmation du client

### 🔢 Port utilisé : variable selon l'application (ex : `80`, `443`, `22`)
### ✅ Commande terminal (état des connexions) :
```bash
ss -t -a
```
Liste toutes les connexions TCP actives ou en attente.
### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 8080:80 --name web nginx
curl localhost:8080
```
Crée une connexion TCP sur le port 80 entre ton client curl et le conteneur Nginx.


## 📡 UDP – User Datagram Protocol
UDP (RFC 768) est un protocole sans connexion, donc :
- Très rapide, léger
- Aucune garantie de livraison ou d’ordre
- Pas de retransmission automatique

### 🔹 Utilisé pour : DNS, RTP, DHCP, SNMP, TFTP, jeux en ligne, VoIP
### 💡 UDP est idéal pour les applications temps réel où un léger taux de perte est acceptable.
### 🔢 Port utilisé : dépend du service (ex : 53, 161, 69, etc.)
### ✅ Commande terminal :
```bash
ss -u -a
```
Affiche les sockets UDP en écoute.

### 🛠️ Cas pratique Docker :
```bash
docker run -d -p 69:69/udp --name tftp almir/tftp
tftp localhost
get fichier.txt
```
Transfert de fichier via UDP sans session persistante.


## 🛰️ ICMP – Internet Control Message Protocol

ICMP (RFC 792) est un protocole de contrôle, utilisé pour :
- Diagnostiquer les problèmes réseau
- Signaler des erreurs (ex : unreachable, time exceeded)
- Vérifier l’accessibilité avec ping
### 💡 Ne transporte pas de données utilisateur.

Utilise l’IP protocole 1 (pas de ports).
### 📡 Messages typiques :
- Type 0 : Echo Reply
- Type 3 : Destination Unreachable
- Type 8 : Echo Request
### ✅ Commande terminal (ping) :
```bash
ping 8.8.8.8
```
Envoie un paquet ICMP Type 8 à Google DNS et attend un Type 0 en réponse.
### 🛠️ Cas pratique Docker :
```bash
docker run -d --rm --name alpineping alpine sleep 1000
docker exec alpineping ping -c 4 1.1.1.1
```
Ping depuis un conteneur pour tester ICMP.


## 📺 IGMP – Internet Group Management Protocol
IGMP (RFC 3376) permet à un hôte de :
- Rejoindre ou quitter un groupe multicast
- Recevoir uniquement les flux multicast nécessaires
### 📍 Utilisé pour : IPTV, vidéoconférences, Webcast, distribution d’OS (PXE)
### 🧠 Fonctionne entre les hôtes et le routeur multicast du réseau
### 🔢 IP protocole : 2
### 💡 Messages typiques :
- Membership Report
- Leave Group
- Query
### ✅ Commande terminal :
```bash
netstat -gn
```
Affiche les groupes multicast joints.
### 🛠️ Cas pratique (simulateur d’IGMP) :
Sur deux VMs dans le même réseau :
```bash
ip maddr add 224.0.0.1 dev eth0
```
Rejoint un groupe multicast pour simuler un client IPTV.


## 📊 Synthèse comparative des protocoles de transport et de diagnostic réseau (version visuelle)

| Protocole | Fiabilité                           | Connexion | Cas d’usage                        | Ports      | Outils typiques                        |
|-----------|-------------------------------------|-----------|------------------------------------|------------|----------------------------------------|
| **TCP**     | ✅ ![Fiable](https://img.shields.io/badge/Fiabilité-Fiable-brightgreen)      | 🔗 Oui      | 🌐 Web, 🔐 SSH, 📧 Mail, 📁 FTP         | Variable   | 🛠️ `curl`, `ss -t`, `Wireshark`         |
| **UDP**     | ❌ ![Non Fiable](https://img.shields.io/badge/Fiabilité-Non_Fiable-orange)   | 🔓 Non      | 🧠 DNS, 📞 VoIP, 🎮 Jeux, 📤 TFTP       | Variable   | ⚙️ `ss -u`, `tftp`, `Wireshark`         |
| **ICMP**    | ❔ ![N/A](https://img.shields.io/badge/Fiabilité-N/A-lightgrey)              | ⚪ N/A      | 🧪 Diagnostic (`ping`, `trace`)       | Aucun      | 🧰 `ping`, `traceroute`, `tcpdump`      |
| **IGMP**    | ❔ ![N/A](https://img.shields.io/badge/Fiabilité-N/A-lightgrey)              | ⚪ N/A      | 📺 Multicast (TV, visio)              | Aucun      | 🧮 `netstat -gn`, `ip maddr`            |

___

# 📚 Récap des Synthèses Comparatives des Protocoles Réseau

## 🔎 Sommaire

1. [📁 Protocoles de Transfert de Fichiers](#-protocoles-de-transfert-de-fichiers)
2. [🔐 Protocoles d'Accès Distant](#-protocoles-daccès-distant)
3. [📡 Protocoles de Supervision Réseau](#-protocoles-de-supervision-réseau)
4. [🧭 Protocoles de Routage](#-protocoles-de-routage)
5. [🔒 Protocoles VPN et Tunneling](#-protocoles-vpn-et-tunneling)
6. [🛂 Protocoles d'Authentification Réseau](#-protocoles-dauthentification-réseau)
7. [📞 Protocoles VoIP et Multimédia](#-protocoles-voip-et-multimédia)
8. [🔍 Protocoles de Découverte Réseau](#-protocoles-de-découverte-réseau)
9. [📬 Protocoles de Messagerie](#-protocoles-de-messagerie)
10. [📶 Protocoles de Transport et Diagnostic](#-protocoles-de-transport-et-diagnostic)

---

## 📁 Protocoles de Transfert de Fichiers

| Protocole | Sécurité | Transport | Authentification           | Port(s)                        | Utilisation typique                   |
|-----------|----------|-----------|-----------------------------|--------------------------------|----------------------------------------|
| **FTP**   | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red) | 📦 TCP | 🔓 Login en clair              | `21` (commande), `20` (données)        | 🌐 Web hosting, anciens scripts        |
| **FTPS**  | ![TLS](https://img.shields.io/badge/Chiffré_TLS-✅-green) | 📦 TCP | 🔐 Login + certificat SSL      | `21` (explicite), `990` (implicite)   | 🏢 B2B sécurisé, conformité            |
| **SFTP**  | ![SSH](https://img.shields.io/badge/Chiffré_SSH-✅-green) | 📦 TCP | 🔐 Login SSH / clé             | `22`                                  | 🖥️ Serveur Linux, backup              |
| **TFTP**  | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red) | 📡 UDP | ❌ Aucun                       | `69`                                  | ⚙️ Firmware, PXE, équipements         |

---

## 🔐 Protocoles d'Accès Distant

| Protocole | Sécurité | Interface | Authentification         | Port  | Utilisation                        |
|-----------|----------|-----------|---------------------------|-------|------------------------------------|
| **SSH**   | ![Chiffré](https://img.shields.io/badge/Chiffré-✅-green) | 🖥️ Terminal  | 🔐 Login / clé RSA           | `22`    | 🔧 Admin serveur Linux, tunnels       |
| **Telnet**| ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red) | 🖥️ Terminal  | 🔓 Login (en clair)          | `23`    | 🧪 Tests réseau, équipements anciens  |
| **RDP**   | ![Chiffré](https://img.shields.io/badge/Chiffré-✅-green) | 🖼️ Graphique | 👤 Compte Windows / NLA      | `3389`  | 💻 Accès à distance Windows           |

---

## 📡 Protocoles de Supervision Réseau

| Protocole | Sécurité | Fonction principale           | Transport     | Utilisé pour                          | Port(s)   |
|-----------|----------|-------------------------------|---------------|----------------------------------------|-----------|
| **SNMP**   | ![v3 Chiffré](https://img.shields.io/badge/v3-Chiffré-green)   | 📊 Collecte d’états/métriques | 📡 UDP         | 📈 Monitoring actif & passif           | `161/162` |
| **Syslog** | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)    | 🗂️ Centralisation de logs      | 🔄 UDP / TCP   | 📝 Journalisation d’événements         | `514`     |
| **NetFlow**| ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)    | 🔎 Analyse des flux IP         | 📡 UDP         | 📶 Monitoring de trafic                 | `2055`    |
| **sFlow**  | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)    | 🧪 Échantillonnage léger       | 📡 UDP         | 🚀 Supervision rapide grands réseaux    | `6343`    |

---

## 🧭 Protocoles de Routage

| Protocole | Hiérarchie | Type             | Métrique                   | Port / Protocole | Usage typique                       |
|-----------|------------|------------------|----------------------------|------------------|--------------------------------------|
| **OSPF**   | ✅ Zones   | 🧭 IGP            | 📏 Coût (bandwidth)         | IP Proto `89`    | 🏢 Réseau entreprise                 |
| **BGP**    | ❌ Non     | 🌐 EGP            | 🧩 Politique (AS_PATH)      | TCP `179`        | 🌍 Internet, FAI, multi-AS          |
| **RIP**    | ❌ Non     | 📡 IGP            | 🔁 Nombre de sauts          | UDP `520`        | 🕸️ Réseaux legacy, simple           |
| **EIGRP**  | ❌ Non     | ⚙️ IGP (Cisco)     | ⏱️ Bande passante, délai     | IP Proto `88`    | 🛠️ Réseaux Cisco homogènes          |
| **IS-IS**  | ✅ L1 / L2 | 🧭 IGP            | 💡 Largeur de bande         | 📦 CLNS          | 🧵 Backbone opérateurs              |

---

## 🔒 Protocoles VPN et Tunneling

| Protocole     | Sécurité | Chiffrement      | Transport     | Port(s)              | Usage typique                         |
|---------------|----------|------------------|---------------|-----------------------|----------------------------------------|
| **IPsec**       | ![Fort](https://img.shields.io/badge/Sécurité-Forte-brightgreen)      | 🔐 Oui (ESP)       | 🌐 IP direct   | UDP `500` / `4500`     | 🛰️ Site à site, mobile VPN             |
| **L2TP/IPsec**  | ![Moyen](https://img.shields.io/badge/Sécurité-Moyenne-yellow)        | 🔐 Via IPsec       | 📡 UDP         | UDP `1701` + `500/4500` | 📱 VPN client Windows / Mobile         |
| **PPTP**        | ![Faible](https://img.shields.io/badge/Sécurité-Faible-orange)        | 🔒 MPPE            | 🔄 TCP + GRE   | TCP `1723` + IP `47`    | 🧩 Obsolète, compatibilité Windows     |
| **GRE**         | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)           | ❌ Aucun           | 🌐 IP          | IP `47`                | 🧪 Tunnel simple, OSPF, labos          |

---

## 🛂 Protocoles d'Authentification Réseau

| Protocole   | Rôle principal                     | Transport     | Port   | Authentifie quoi ?                   | Particularité                                               |
|-------------|------------------------------------|---------------|--------|--------------------------------------|-------------------------------------------------------------|
| **802.1X**   | 🔐 Contrôle d’accès port            | 🔗 EAP over LAN | N/A    | 🖧 Appareils réseau                   | 🛠️ Nécessite switch + serveur RADIUS                        |
| **RADIUS**   | 🧭 Auth centralisée AAA             | 📡 UDP         | `1812` | 👥 Utilisateurs, VPN, Wi-Fi           | ⚡ Léger, répandu, non orienté admin                         |
| **TACACS+**  | 🛡️ Auth et autorisation admin       | 🔄 TCP         | `49`   | 👨‍💼 Admins, équipements Cisco         | 📋 Détaille et trace les commandes admin (oriented CLI)     |

---

## 📞 Protocoles VoIP et Multimédia

| Protocole | Sécurité | Rôle                    | Port(s)                       | Transport     | Utilisé dans...                        |
|-----------|----------|--------------------------|-------------------------------|---------------|-----------------------------------------|
| **SIP**    | ![TLS](https://img.shields.io/badge/Sécurité-via_TLS-green)      | 📞 Signalisation            | `5060` (UDP/TCP), `5061` (TLS) | ✉️ Texte      | ☎️ IPBX, softphones, WebRTC              |
| **RTP**    | ![Aucune](https://img.shields.io/badge/Sécurité-Faible_or_SRTP-orange) | 🎙️ Transport voix          | `10000–20000+` (UDP pair)      | 🧱 Binaire     | 📡 Tous appels VoIP / vidéo             |
| **RTCP**   | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)      | 📊 Supervision QoS          | RTP+1 (UDP impair)             | 🧱 Binaire     | 📈 Qualité d’appel, statistiques        |
| **H.323**  | ![Optionnel](https://img.shields.io/badge/Sécurité-TLS_en_option-yellow) | 📦 Signalisation + média   | `1720` + dynamiques            | 🧱 Binaire     | 🖥️ Conférence, visio legacy             |

---

## 🔍 Protocoles de Découverte Réseau

| Protocole  | Sécurité | Rôle                     | Port(s)          | Transport   | Utilisation                        |
|------------|----------|--------------------------|------------------|-------------|------------------------------------|
| **mDNS**     | ![Aucune](https://img.shields.io/badge/Sécurité-Aucune-red)              | 🌐 Résolution noms locaux | UDP `5353`       | 📡 Multicast | `.local`, imprimantes               |
| **SSDP**     | ![Faible](https://img.shields.io/badge/Sécurité-Faible-orange)           | 🛰️ Découverte de services | UDP `1900`       | 📡 Multicast | 🧩 DLNA, UPnP, TV, IoT              |
| **LLDP**     | ![L2 only](https://img.shields.io/badge/Sécurité-L2_only-green)          | 🧭 Découverte directe L2  | EtherType `88cc` | 🔌 Ethernet  | 🏢 Inventaire réseau pro            |
| **NetBIOS**  | ![Très faible](https://img.shields.io/badge/Sécurité-Très_faible-red)    | 🧾 Nom d’hôte + partages  | UDP `137-139`    | 📢 Broadcast | 🖥️ SMB, anciens réseaux Windows     |

---

## 📬 Protocoles de Messagerie

| Protocole | Sécurité | Rôle                     | Mode   | Ports                | Spécificité                                       |
|-----------|----------|--------------------------|--------|----------------------|---------------------------------------------------|
| **SMTP**   | ![STARTTLS](https://img.shields.io/badge/Sécurité-STARTTLS_/_TLS-yellowgreen) | 📤 Envoi de mails         | 📬 Push | `25` / `587` / `465` | ✉️ Texte brut → relay ou livraison                 |
| **POP3**   | ![SSL/TLS](https://img.shields.io/badge/Sécurité-TLS_/_SSL-blue)             | 📥 Réception unique       | 📥 Pull | `110` / `995`        | 🗑️ Supprime localement après lecture              |
| **IMAP**   | ![SSL/TLS](https://img.shields.io/badge/Sécurité-TLS_/_SSL-blue)             | 📬 Réception + gestion    | 📥 Pull | `143` / `993`        | 📂 Dossiers, statuts, multi-devices               |

---

## 📶 Protocoles de Transport et Diagnostic

| Protocole | Fiabilité | Connexion | Cas d’usage                        | Ports      | Outils typiques                        |
|-----------|-----------|-----------|------------------------------------|------------|----------------------------------------|
| **TCP**     | ✅ ![Fiable](https://img.shields.io/badge/Fiabilité-Fiable-brightgreen)      | 🔗 Oui      | 🌐 Web, 🔐 SSH, 📧 Mail, 📁 FTP         | Variable   | 🛠️ `curl`, `ss -t`, `Wireshark`         |
| **UDP**     | ❌ ![Non Fiable](https://img.shields.io/badge/Fiabilité-Non_Fiable-orange)   | 🔓 Non      | 🧠 DNS, 📞 VoIP, 🎮 Jeux, 📤 TFTP       | Variable   | ⚙️ `ss -u`, `tftp`, `Wireshark`         |
| **ICMP**    | ❔ ![N/A](https://img.shields.io/badge/Fiabilité-N/A-lightgrey)              | ⚪ N/A      | 🧪 Diagnostic (`ping`, `trace`)       | Aucun      | 🧰 `ping`, `traceroute`, `tcpdump`      |
| **IGMP**    | ❔ ![N/A](https://img.shields.io/badge/Fiabilité-N/A-lightgrey)              | ⚪ N/A      | 📺 Multicast (TV, visio)              | Aucun      | 🧮 `netstat -gn`, `ip maddr`            |

