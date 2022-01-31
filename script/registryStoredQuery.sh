#! /bin/bash
curl -v --location --request POST 'https://kon-instanz1.titus.ti-dienste.de/soap-api/PHRService/1.3.0' \
--header 'Content-Type: application/xml' \
--insecure --cert-type P12 --cert ./cert/ps_epa_consol_01.p12:00 \
--output retrieveDocumentSetResponse \
--data-raw '<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:m0="http://ws.gematik.de/conn/ConnectorContext/v2.0" xmlns:m1="http://ws.gematik.de/conn/ConnectorCommon/v5.0" xmlns:m2="http://ws.gematik.de/fa/phr/v1.1">
  <soap:Header>
    <m:ContextHeader xmlns:m="http://ws.gematik.de/conn/phrs/PHRService/v1.3">
      <m0:Context>
        <m1:MandantId>ps_epa_consol_01</m1:MandantId>
        <m1:ClientSystemId>ps_epa_consol_01</m1:ClientSystemId>
        <m1:WorkplaceId>CATS</m1:WorkplaceId>
      </m0:Context>
      <m:RecordIdentifier>
        <m2:InsurantId root="1.2.276.0.76.4.8" extension="X110404542"/>
        <m2:HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</m2:HomeCommunityId>
      </m:RecordIdentifier>
    </m:ContextHeader>
    <Action xmlns="http://www.w3.org/2005/08/addressing">urn:ihe:iti:2007:RegistryStoredQuery</Action>
    <To xmlns="http://www.w3.org/2005/08/addressing">http://10.11.218.161:80/fm/phrservice</To>
    <MessageID xmlns="http://www.w3.org/2005/08/addressing">60ec313a-e08a-457e-92ac-f1ff808d4045</MessageID>
    <ReplyTo xmlns="http://www.w3.org/2005/08/addressing">
      <Address>http://www.w3.org/2005/08/addressing/anonymous</Address>
    </ReplyTo>
  </soap:Header>
  <soap:Body>
    <query:AdhocQueryRequest xmlns="urn:ihe:iti:xds-b:2007" xmlns:rim="urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0" xmlns:query="urn:oasis:names:tc:ebxml-regrep:xsd:query:3.0">
      <query:ResponseOption returnType="LeafClass" returnComposedObjects="true"/>
      <rim:AdhocQuery id="urn:uuid:14d4debf-8f97-4251-9a74-a90016b0af0d" home="urn:oid:1.2.276.0.76.3.1.405">
        <rim:Slot name="$XDSDocumentEntryPatientId">
          <rim:ValueList>
            <rim:Value>'X110404542^^^&amp;1.2.276.0.76.4.8&amp;ISO'</rim:Value>
          </rim:ValueList>
        </rim:Slot>
        <rim:Slot name="$XDSDocumentEntryStatus">
          <rim:ValueList>
            <rim:Value>('urn:oasis:names:tc:ebxml-regrep:StatusType:Approved')</rim:Value>
          </rim:ValueList>
        </rim:Slot>
      </rim:AdhocQuery>
    </query:AdhocQueryRequest>
  </soap:Body>
</soap:Envelope>' \
| xmllint --format -

