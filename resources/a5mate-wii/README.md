# A5Mate Wii — jalon PWNDFU

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
| `a5mate-wii-8942` | `A5_8942` | Généré, à tester sur cible |
| `a5mate-wii-8945` | `A5_8945` | Généré, à tester sur cible |

## Préconditions et comportement

- Connecter un seul appareil A5 en DFU correspondant au profil choisi à un
  port USB externe de la Wii.
- Le programme refuse les appareils ne correspondant pas à l'identité DFU
  attendue.
- Il ne déclare pas la réussite à partir d'un simple transport USB : il exige
  `PWND:[checkm8]` dans le descripteur série.
- Après ce marqueur, il garde l'EHCI Wii afin qu'IOS58 n'envoie pas de requête
  supplémentaire au téléphone.

Les DOL distribués n'initialisent pas le réseau : ni DHCP, ni télémétrie, ni
port TCP ne sont ouverts. Après le marqueur, appuyer sur **A** (Wiimote ou
manette GameCube) pour éjecter proprement, débrancher le câble, puis appuyer
sur **B** pour rendre l'EHCI à IOS58.

Le mode de développement peut être construit séparément avec
`A5WII_ENABLE_NETWORK=1`; il réactive la télémétrie vers le Mac et les consoles
TCP. Les détails et la preuve matérielle sont dans
[JALON-PWNDFU.md](JALON-PWNDFU.md).

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
