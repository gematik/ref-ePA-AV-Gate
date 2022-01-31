#! /bin/bash
curl --location --request POST 'https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/1.3.0' \
--header 'Content-Type: application/xml' \
--insecure --cert-type P12 --cert ./cert/ps_epa_consol_01.p12:00 \
--data-raw '<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:m0="http://ws.gematik.de/conn/ConnectorContext/v2.0" xmlns:m1="http://ws.gematik.de/conn/ConnectorCommon/v5.0">
  <SOAP-ENV:Header>
    <Action xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="true">http://ws.gematik.de/conn/phrs/PHRManagementService/v1.3/GetAuthorizationList</Action>
    <To xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="true">http://10.11.218.161:80/fm/phrmanagementservice</To>
    <MessageID xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="1">721bcef8-9d42-4819-b2cf-13e3faf6f5a6</MessageID>
    <ReplyTo xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="1">
      <Address>http://www.w3.org/2005/08/addressing/anonymous</Address>
    </ReplyTo>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <m:GetAuthorizationList xmlns:m="http://ws.gematik.de/conn/phrs/PHRManagementService/v1.3">
      <m0:Context>
        <m1:MandantId>ps_epa_consol_01</m1:MandantId>
        <m1:ClientSystemId>ps_epa_consol_01</m1:ClientSystemId>
        <m1:WorkplaceId>CATS</m1:WorkplaceId>
      </m0:Context>
    </m:GetAuthorizationList>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>' \
| xmllint --format -