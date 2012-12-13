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

License
=======

The code and file specification are released under a Simplified BSD
License.

Copyright (c) 2012, KB Sriram

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
