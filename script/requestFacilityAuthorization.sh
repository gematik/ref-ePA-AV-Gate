#! /bin/bash
curl --location --request POST 'https://kon-instanz1.titus.ti-dienste.de/soap-api/PHRManagementService/1.3.0' \
--header 'Content-Type: application/xml' \
--insecure --cert-type P12 --cert ./cert/ps_epa_consol_01.p12:00 \
--data-raw '<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:m0="http://ws.gematik.de/conn/ConnectorContext/v2.0" xmlns:m1="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:m2="http://ws.gematik.de/fa/phr/v1.1">
  <SOAP-ENV:Header>
    <Action xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="true">http://ws.gematik.de/conn/phrs/PHRManagementService/v1.3/RequestFacilityAuthorization</Action>
    <To xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="true">http://10.11.218.161:80/fm/phrmanagementservice</To>
    <MessageID xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="1">748fd66c-6733-4d0f-b8f9-fec3605f6f3f</MessageID>
    <ReplyTo xmlns="http://www.w3.org/2005/08/addressing" SOAP-ENV:mustunderstand="1">
      <Address>http://www.w3.org/2005/08/addressing/anonymous</Address>
    </ReplyTo>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <m:RequestFacilityAuthorization xmlns:m="http://ws.gematik.de/conn/phrs/PHRManagementService/v1.3">
      <m0:Context>
        <m1:MandantId>ps_epa_consol_01</m1:MandantId>
        <m1:ClientSystemId>ps_epa_consol_01</m1:ClientSystemId>
        <m1:WorkplaceId>CATS</m1:WorkplaceId>
      </m0:Context>
      <m1:EhcHandle>X110403007</m1:EhcHandle>
      <m:AuthorizationConfiguration>
        <m:Vers_Docs>true</m:Vers_Docs>
        <m:LE_Docs>true</m:LE_Docs>
        <m:KTR_Docs>true</m:KTR_Docs>
        <m:ExpirationDate>2021-12-31</m:ExpirationDate>
      </m:AuthorizationConfiguration>
      <m:RecordIdentifier>
        <m2:InsurantId root="1.2.276.0.76.4.8" extension="X110403007"/>
        <m2:HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</m2:HomeCommunityId>
      </m:RecordIdentifier>
      <m:OrganizationName>Arztpraxis Martha Oberhausen TEST-ONLY</m:OrganizationName>
      <m:InsurantName>
        <m:Vorname>Ullrich</m:Vorname>
        <m:Nachname>Freiherr Wendler-SchonhäuserTEST-ONLY</m:Nachname>
      </m:InsurantName>
    </m:RequestFacilityAuthorization>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>' \
| xmllint --format -
