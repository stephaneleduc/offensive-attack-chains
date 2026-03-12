# NTLM Relay & Delegation Abuse → Domain Compromise

## 📖 Présentation du contexte

Un accès initial est obtenu sur TARGET_IP avec un compte à privilèges limités (LOW_PRIV_USER).

La machine compromise est le contrôleur de domaine du domaine LAB.DOMAIN.

Lors de l’énumération, une seconde interface réseau interne est découverte, révélant un réseau non accessible directement depuis la machine attaquante.

Une seconde machine, nommée MACHINE_2, est identifiée sur ce réseau et héberge un serveur web.

L’analyse de l’environnement Active Directory met également en évidence plusieurs relations de délégation et permissions intéressantes entre différents comptes utilisateurs.


## 🔎 Découverte menant à la chaîne d’attaque

Les éléments suivants sont identifiés :
- Présence d’un réseau interne accessible uniquement depuis TARGET_IP
- SMB Signing désactivé sur MACHINE_2
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


