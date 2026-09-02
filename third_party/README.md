# Third-party FairPlay SAP

`fairplay-sap-core/` is a vendored copy of
[objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake](https://github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake)
(LGPL-3.0-or-later). It is **not** DoubleTake.

`fpsap-bridge/` is a tiny C ABI around that module's session-aware M1/M3.
omacast links it statically. The combined binary is a Combined Work under
LGPL-3.0: source for this directory ships with omacast so the library can be
relinked. License texts: `fairplay-sap-core/LICENSE`,
`fairplay-sap-core/COPYING.GPL-3.0`, `fairplay-sap-core/LICENSE.BlueOak-1.0.0`.
