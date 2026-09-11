# Sources incluses

`a5wii/` est le projet devkitPPC de l'application Wii. Il contient le
Makefile et l'intégralité des unités de compilation nécessaires au DOL.

`a5wii/source/a5mate_constants.h` contient les géométries et payloads
A5_8940, A5_8942 et A5_8945 importés par `packet_probe.c`. Il est local au
projet Wii : le paquet ne dépend donc pas du répertoire historique
`a5mac-dfu`.

La référence comportementale du protocole est l'esquisse a5mate. Le Makefile
exige un profil explicite : `A5WII_A5_PROFILE=8940`, `8942` ou `8945`. Il
définit simultanément la constante de payload et le CPID exigé par le DOL ; il
ne sélectionne jamais un payload au runtime.
