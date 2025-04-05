# LEARN-PROTOCOLS

## 📦 Protocoles de Transfert de Fichiers : FTP, SFTP, FTPS, TFTP

### 📚 Qu’est-ce qu’une RFC ?
Les RFC (Request For Comments) sont des documents normatifs publiés par l’IETF (Internet Engineering Task Force). Ce sont des standards officiels ou historiques qui définissent les protocoles réseau, leur fonctionnement, leurs messages, leur syntaxe, etc.

➡ Par exemple, FTP est défini dans la RFC 959, TFTP dans la RFC 1350, et SFTP est spécifié via l’extension SSH dans les drafts IETF.
Quand je cite une RFC, cela signifie que le comportement du protocole est standardisé et reconnu officiellement.

## 🧱 FTP – File Transfer Protocol
Le protocole FTP, défini dans la RFC 959, est l’un des plus anciens mécanismes de transfert de fichiers. Il fonctionne selon un modèle client-serveur et repose sur une architecture double canal : un canal de commande (port TCP 21) et un canal de données (port TCP 20 ou dynamique en mode passif). Cela signifie que le client envoie des commandes (comme LIST, RETR, STOR) sur un canal et reçoit ou envoie les fichiers via un second.

### ⚠️ Limite majeure : les données et les identifiants transitent en clair. Cela rend FTP vulnérable à l’interception (sniffing), au spoofing, et aux attaques de type "man-in-the-middle".
### 🔍 Exemple : un développeur web utilisant FileZilla pour téléverser un site sur un serveur FTP hébergé.
### ✅ Commande terminal (client FTP) :
```bash 
ftp 192.168.1.100
```

Tu tapes cette commande dans un terminal Linux. Elle ouvre une session FTP avec l’adresse IP du serveur. Ensuite, tu entreras un login et un mot de passe. Tu peux ensuite utiliser ls, get fichier.txt, put fichier.txt, etc.
### 🛠️ Cas pratique Docker :
```bash 
docker run -d --name ftp-server -p 21:21 -p 30000-30009:30000-30009 \
    -e FTP_USER=test -e FTP_PASS=test123 \
    -e PASV_MIN_PORT=30000 -e PASV_MAX_PORT=30009 \
    stilliard/pure-ftpd
```
Lance un serveur FTP en conteneur avec l’utilisateur test:test123. Tu peux t’y connecter avec ftp localhost.

## 🔐 FTPS – FTP Secure (avec SSL/TLS)
Pour répondre aux faiblesses de sécurité du FTP, on a développé FTPS, qui encapsule le protocole FTP classique dans une couche SSL/TLS. Il en existe deux variantes :
FTPS implicite : la connexion est automatiquement chiffrée dès le début (port TCP 990).
FTPS explicite : la connexion débute en clair, puis passe au mode sécurisé avec la commande AUTH TLS (sur le port 21).

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

À ne pas confondre avec FTPS, le SFTP est un protocole complètement distinct, basé sur SSH (port TCP 22). Contrairement à FTP/FTPS, il ne sépare pas les commandes des données. Il encapsule tout dans un flux SSH unique, offrant à la fois authentification forte (via mot de passe ou clés publiques) et chiffrement intégral du canal de bout en bout.

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

Le TFTP est une version simplifiée et minimale de FTP, défini dans la RFC 1350. Il fonctionne sur UDP (port 69), ce qui le rend extrêmement léger, mais sans authentification ni chiffrement. TFTP utilise une séquence très limitée de commandes (RRQ, WRQ, DATA, ACK, ERROR), rendant son usage restreint à des cas précis.

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

## 📊 Synthèse comparative :
Protocole	Sécurité	Transport	Usage typique	Authentification	Port
FTP	❌ Aucune	TCP	Web hosting, anciens scripts	Login en clair	21 (commande), 20 (données)
FTPS	✅ TLS	TCP	B2B sécurisé, conformité	Login + certificat SSL	21 (explicite), 990 (implicite)
SFTP	✅ SSH	TCP	Serveur Linux, backup	Login SSH / clé	22
TFTP	❌ Aucune	UDP	Firmware, PXE, équipements	❌ Aucun	69


