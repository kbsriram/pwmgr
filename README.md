Pwmgr
=====

This is a command line java application that uses OpenPGP to manage an
secure password database.

The database is encrypted with a public/private key pair, and the
private key is encrypted with a passphrase. Reading the password
database needs something "you have" (the private key) and something
"you know" (the passphrase.)

You can place the keys on a separate device to reduce your exposure to
theft. For instance, you can place your private key on a flash drive
and the password database under a Dropbox folder. If you lose either
one of these things, you're still very safe. If you lose both at the
same time, your data is protected by your passphrase.

I have a [guide](http://kbsriram.github.com/pwmgr) that shows how to
use pwmgr, as well as a description of the database format.
