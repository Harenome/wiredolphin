Wiredolphin
===========

TP Analyseur réseau - M1 RISE 2014-2015, [UFR Mathématique-Informatique][], [Université de Strasbourg][].

Compiler `wiredolphin`
----------------------

```bash
$ make
$ [sudo] make install
```

Lancer `wiredolphin`
--------------------

Se renseigner sur `libpcap` (ou lancer le programme avec les droits root pour
les plus téméraires!) et regarder la manpage de `wiredolphin`.

### Exemples

```bash
$ [sudo] bin/wiredolphin -i <interface> -v 3
$ sudo wiredolphin -i <interface> -v 1
```

Le second exemple fonctionne si `wiredolphin` est dans `$PATH`.

Documentation
-------------

Voir la manpage.

```bash
$ man man/man1/wiredolphin.1
$ man wiredolphin
```

Le second exemple nécessite que la manpage se trouve au bon endroit
(voir `man man`), ce qui devrait être le cas si `wiredolphin` a été installé
via `make install`

License
-------
Copyright © 2014 RAZANAJATO RANAIVOARIVONY Harenome

Ce projet est libre. Vous pouvez le redistribuer ou le modifier selon les termes
de la license « Do What The Fuck You Want To Public License », Version 2, comme
publiée par Sam Hocevar. Pour de plus amples informations, veuillez vous référer
au fichier COPYING, ou bien http://www.wtfpl.net/.

[Université de Strasbourg]: https://www.unistra.fr
[UFR Mathématique-Informatique]: https://mathinfo.unistra.fr/
