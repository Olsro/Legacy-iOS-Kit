# A5Mate Wii — 0.1.2, correctif de topologie EHCI

Ce dossier est autonome pour la carte SD de la Homebrew Channel : copier son
contenu à la racine de la SD. L'application apparaîtra sous le nom
**A5Mate Wii**.

```text
SD:/apps/a5mate-wii-8940/boot.dol
SD:/apps/a5mate-wii-8940/meta.xml
```

Trois builds explicitement séparés sont inclus. Tous démarrent avec
`--pwndfu` et vérifient le CPID choisi avant d'envoyer la séquence.

| Dossier HBC | Profil compilé | État matériel |
| --- | --- | --- |
| `a5mate-wii-8940` | `A5_8940` | PWNDFU observé sur le 4S de test |
| `a5mate-wii-8942` | `A5_8942` | PWNDFU observé sur le iPod Touch 5G de test ; fonctionnement confirmé par un utilisateur sur Wii U/vWii avec un iPad CPID 8942 le 25 octobre 2026 |
| `a5mate-wii-8945` | `A5_8945` | PWNDFU et boot ramdisk confirmés sur l’iPad 3 de test |

## Préconditions et comportement

- Connecter un seul appareil A5 en DFU correspondant au profil choisi à un
  port USB externe de la console, sans hub. Pour un essai, débrancher les
  autres périphériques USB externes.
- Le programme refuse les appareils ne correspondant pas à l'identité DFU
  attendue.
- Les profils 8940 et 8945 vérifient `PWND:[checkm8]` dans le descripteur
  série, puis gardent l'EHCI afin qu'IOS58 n'envoie pas de requête supplémentaire.
- Le profil 8942 termine la séquence et revient automatiquement à la
  Homebrew Channel. La confirmation du pwnDFU se fait ensuite sur le Mac :
  le retour au menu ou `result=0` ne suffit pas à la prouver.

Les DOL distribués n'initialisent pas le réseau : ni DHCP, ni télémétrie, ni
port TCP ne sont ouverts. Pour les profils 8940 et 8945, après le marqueur,
appuyer sur **A** (Wiimote ou
manette GameCube) pour éjecter proprement, débrancher le câble, puis appuyer
sur **B** pour rendre l'EHCI à IOS58.

Après `DONE returning to Homebrew Channel`, l'écran affiche :
`Visit https://olsro.fr for cool stuff and to support Olsro with a donation.`
Ce message est du texte uniquement ; il n'ouvre aucune connexion réseau.

Le mode de développement peut être construit séparément avec
`A5WII_ENABLE_NETWORK=1`; il réactive la télémétrie vers le Mac et les consoles
TCP. Les détails et la preuve matérielle sont dans
[JALON-PWNDFU.md](JALON-PWNDFU.md).

Le profil 8942 utilise la révision `8d22193` de `synackuk/checkm8-a5`, qui
retire la démotion. Cette variante est nécessaire pour conserver les clés de
production et permettre au Mac de lancer un iBSS Apple signé après le pwnDFU.

## Validation Wii U / vWii

Le correctif 0.1.2 est intégré aux trois profils. La validation utilisateur
sur Wii U/vWii concerne le profil **8942** ; les profils 8940 et 8945 restent
à valider sur cette console.

La vidéo du test 8942 montre `params=00002406 ports=6 connected=1 ehci=1` :
le contrôleur expose six ports racine, ce qui déclenchait le refus `-20` du
code exigeant exactement quatre ports. Le correctif utilise le nombre de
ports annoncé et écarte les connexions appartenant au contrôleur compagnon.
Il exige toujours une seule connexion EHCI et un port prêt avant le reset.

Le test atteint `result=0 phase=4 packet_step=1298`, `global_out=28/28` et
`reset code=0 stage=7`. Le 25 octobre 2026, l'utilisateur a ensuite confirmé
que l'ensemble fonctionnait. Ce retour valide le correctif pour cette
configuration ; il ne constitue pas une validation de tous les profils
sur toutes les Wii U.

## Reconstruire le DOL avec Docker

Le paquet contient les sources sous `sources/` et épingle l'image devkitPPC
utilisée pour ce jalon. Depuis `a5mate-wii/` :

```sh
./build-distribution.sh
shasum -a 256 -c SHA256SUMS
```

Le script compile successivement avec `A5WII_A5_PROFILE=8940`, `8942` et
`8945`, remplace leurs `boot.dol` respectifs, puis régénère `SHA256SUMS`. Il
construit hors réseau par défaut ; pour un artefact de développement, lancer
`A5WII_ENABLE_NETWORK=1 ./build-distribution.sh`. Il ne contacte pas la Wii.
Après ce contrôle, recopier `apps/` dans `SD:/apps/`.
