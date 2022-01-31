# Dokumentation
### Hinweis
Der Inhalt dieses Repositories wurde von https://github.com/ConSol/ePa_av-gate (tag=v0.15) unverändert übernommen und hier als Version 0.0.1 (tag=0.0.1) veröffentlicht (ausgenommen: Inhalt des Verzeichnisses /samples).

Der Download einiger Beispiele (/samples) kann durch Antivirenscanner eventuell als Bedrohung eingestuft werden. 

---

# AV-Gate

Proxy für den Antivirus-Scan von Dokumenten zu der elektronischen Patientenakte (ePa). Dieser Proxy wird zwischen dem Konnektor der Gematik und den Primärsystemen geschaltet und überprüft sämtliche Dokumente der ePA vor der Übertragung an die Primärsysteme. 

Bei einem Fund von Malware wird das Dokument aus der Übertragung herausgenommen. Stattdessen wird eine Fehlermeldung für das entsprechende Dokument an das Primärsystem übergeben. Veränderungen an dem Repository der ePA selbst werden nicht vorgenommen.

Für den AV-Scan wird die open-source Lösung [ClamAV](https://www.clamav.net/) genutzt.

## Architektur und Funktionsweise

![architektur](docs/architektur.png)

Das AV-Gate fungiert als Man-in-the-middle zwischen Primärsystem und Konnektor. Die Verbindungen zwischen Primärsystem und NGINX sowie zwischen AV-Gate und Konnektor sind TLS gesichert. Die Requests an den Konnektor sind technisch komplett getrennt von den Requests an das AV-Gate (bzw. dem NGINX).

Die Autorisierung für den Konnektor wird bei Basic-Auth aus dem ursprünglichen Request übernommen. Client-Zertifikate müssen je Konnektor für das AV-Gate gesondert konfiguriert werden; eine Übername aus dem Request ist hier nicht möglich.

Die Verbindung zum ClamAV Dienst erfolgt über unix Socket. Daher muss der clamd auf der gleichen Maschine installiert sein.

![sequence](docs/sequence.png)

Die Trennung zwischen NGINX und AV-Gate wurde aus Gründen der Übersichtlichkeit weggelassen.

1: Request der connector.sds  
Die connector.sds ist ein Verzeichnis der Service-Adressen.

2: Request an den Konnektor  
Hier wird ein neuer Request erzeugt (kein Forward oder Proxy). Der Request aus 1 wird gehalten.

4: Die Adresse für PHRService, welche den Endpunkt RetrieveDocumentSet enthält wird durch die Adresse des AV-Gates ersetzt. Diese wird aus dem Request an das AV-Gate ermittelt.

7: Response vom Konnektor
Der Response beinhaltet neben SOAP-Response auch die Dokumente als [XOP](https://de.wikipedia.org/wiki/XML-binary_Optimized_Packaging).

Responses zu anderen Endpunkten als RetrieveDocumentSet werden direkt an das Primärsystem weitergegeben.

8: AV-Scan
Die aus dem Response extrahierten Dokumente werden via socket stream an den clamd übergeben. Die Dateien werden nicht im Filesystem gespeichert. Die Latenz durch den Scan ist sehr gering (<100ms).

9: Remove Document  
Der XOP Teil der Nachricht für die betroffenen Dokumente wird entfernt und eine Fehlermeldung wird in den SOAP-Response geschrieben.

## ClamAV

Der Virenscanner läuft als Daemon. Die Aktualisierung der Viren-Signaturen erfolgt über einen eigenen Dienst. 

- [Installation](https://docs.clamav.net/manual/Installing.html)
- [SignatureManagement](https://docs.clamav.net/manual/Usage/SignatureManagement.html)

## Installation

Es werden benötigt:
- Python 3.8 
- uWSGI 1.19 
- NGINX 1.18.0
- ClamAV 0.103.2

Bislang wurde als Host-System Ubuntu Server 20.04.3 LTS verwendet. Die oben genanten Versionen entsprechen dieser Konfiguration. 

1. ClamAV   
/etc/clamav/clamd.conf  
`LocalSocket /tmp/clamd.socket`

2. Signaturen laden  
/etc/clamav/freshclam.conf   
`sh> freshclam`

1. NGINX   
Eine vollständig Beispielkonfiguration `nginx.conf` liegt bei. Ports, SSL-Zertifikate und ggf. Socket müssen angepasst werden. Angaben der Ports als Range sind seit NGINX 1.15.10 möglich.

1. uWSGI   
Beispieldatei `uwsgi.ini` liegt bei. Socket und chdir müssen angepasst werden. Virtualenv kann weggelassen werden, wenn auf dem Server keine weiteren, anderen Python-Versionen benötigt werden.

5. AV-Gate  
Dateien av_gate.py, av_gate.ini, requirements.txt in ein Programmverzeichnis kopieren (z.B. /usr/local/av_gate/). 
`sh> pip3 install -r requirements.txt` - oder mit `pip`, wenn pip3 nicht verfügbar.  
Der Pfad für den Socket in `av_gate.ini` ist ggf anzupassen.
## Konfiguration

In der `av_gate.ini` ist für jeden Konnektor eine Gruppe anzulegen. Der Gruppenname beschreibt das Routing über IP-Adresse mit Port `[<ip-address>:<port]` - oder aber ausschließlich über den Port `[*:<port>]`. Gruppen mit IP-Adresse werden vor den Gruppen ohne IP-Adressen berücksichtigt.

> Auf die Verwendung von Namen statt IP-Adressen wurde verzichtet, weil ein Großteil der Primärsysteme keine Namen in der Konfiguration verwenden kann.

Für jede Konnektor (jede Gruppe) kann konfiguriert werden:
- konnektor = https://<host><port>
- ssl_verify = true  
Die Zertifikate des Konnektors werden auf Gültigkeit überprüft. Verbindungen mit ungültigen (auch selfsigned) Zertifikaten werden abgelehnt.
- ssl_cert = <pfad.crt>  
- ssl_key = <pfad.key>  
Client-Zertifikat für Autorisierung gegenüber Konnektor.  

Auf jeden Arbeitsplatzrechner muss in der Konfiguration der Primärsysteme die IP-Adresse des AV-Gates als Konnektor eingetragen werden.

> **Warnung:** Wird auf einem Arbeitsplatzrechner der Konnektor nicht angepasst, erfolgt kein AV-Scan der Dokumente! Das Primärsystem wird aber dennoch wie bisher auch funktionieren - dies lässt sich technisch auch nicht verhindern.

Das Logging des AV-Gates erfolgt über uWSGI.


## Primärsysteme
Das AV-Gate wurde für folgende Primärsysteme getestet:

| Primärsystem | Version | Status | Anmerkung |
|---|---|---|---|
| | | |

--

Consol GmbH  
Norbert Ferchen  
November 2021