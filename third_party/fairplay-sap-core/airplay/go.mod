module github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake/airplay

go 1.25.0

replace github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake => ../

require (
	github.com/objevovat/fairplay-sap-core-airplay2-sender-authentication-handshake v0.0.0
	golang.org/x/crypto v0.54.0
)

require golang.org/x/sys v0.47.0 // indirect
