# Sulphur
![sulphur logo](sulphur.png)

(My transliteration was bad in that image, but i can't recover the original project to fix it D:)

Remember to extract all .zips!

## Info

Sulphur botnet written in C++

Competitor of [Marlborge for C++](https://github.com/PR3C14D0/Marlborge)

(Made first as a joke with him and me, lol)

Fixes issues and add more functionality + best practices (char[1024] FORBIDDEN HERE!!)

Tested under Windows 8.1 x64

Client & Server require at least 1 Visual C++ Redistributable Package to Run
(vcruntime and msvcp), or compile with /MT (but precompiled libs won't work)

You can remove the administrator perms in Client manifest.

## Server UI
Initial UI

![SS of the UI](https://i.imgur.com/LoEwR5D.png)

Client Control Menu

![menu](https://i.imgur.com/MI839cR.png)

If you deactivate the notifications, doesn't show anything when a client connects to server

![notifications off](https://i.imgur.com/yn1QUGv.png)

You can set up that option if you have a large botnet or the notifications annoy you

### Requirements

Extract all .zip in their respective folder! (in the root folder, /include and /include/stealer)

libssl and libcrypto required by client (to enable HTTPS requests), or build/download OpenSSL for Windows (You can download precompiled binaries)

P.S. There's already static .libs in /lib compiled by me

## WARNING!

The libs included precompiled by me are with OpenSSL 1.1.1m MDx32, compile your own libs if you compile to/with;

  * x64 or ARM CPUs

  * MultiThread Compilations

  * Static Compilations

  * OpenSSL 3.0 Headers
