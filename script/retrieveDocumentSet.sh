#! /bin/bash
curl -v --location --request POST 'https://kon-instanz1.titus.gematik.solutions/soap-api/PHRService/1.3.0' \
--header 'Content-Type: application/xml' \
--insecure --cert-type P12 --cert ./cert/ps_epa_consol_01.p12:00 \
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
        <m2:InsurantId root="1.2.276.0.76.4.8" extension="X110403007"/>
        <m2:HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</m2:HomeCommunityId>
      </m:RecordIdentifier>
    </m:ContextHeader>
    <Action xmlns="http://www.w3.org/2005/08/addressing">urn:ihe:iti:2007:RetrieveDocumentSet</Action>
    <To xmlns="http://www.w3.org/2005/08/addressing">http://10.11.218.161:80/fm/phrservice</To>
    <MessageID xmlns="http://www.w3.org/2005/08/addressing">ec50fa1f-ff62-49d3-a870-f5218afba633</MessageID>
    <ReplyTo xmlns="http://www.w3.org/2005/08/addressing">
      <Address>http://www.w3.org/2005/08/addressing/anonymous</Address>
    </ReplyTo>
  </soap:Header>
  <soap:Body>
    <RetrieveDocumentSetRequest xmlns="urn:ihe:iti:xds-b:2007">
      <DocumentRequest xmlns="urn:ihe:iti:xds-b:2007">
        <HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</HomeCommunityId>
        <RepositoryUniqueId>1.2.276.0.76.3.1.91.1</RepositoryUniqueId>
        <DocumentUniqueId>2.25.123657184201295845861</DocumentUniqueId>
      </DocumentRequest>
      <DocumentRequest xmlns="urn:ihe:iti:xds-b:2007">
        <HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</HomeCommunityId>
        <RepositoryUniqueId>1.2.276.0.76.3.1.91.1</RepositoryUniqueId>
        <DocumentUniqueId>2.25.271901047428199838029</DocumentUniqueId>
      </DocumentRequest>
      <DocumentRequest xmlns="urn:ihe:iti:xds-b:2007">
        <HomeCommunityId>urn:oid:1.2.276.0.76.3.1.91.1</HomeCommunityId>
        <RepositoryUniqueId>1.2.276.0.76.3.1.91.1</RepositoryUniqueId>
        <DocumentUniqueId>2.25.234677361812986750726</DocumentUniqueId>
      </DocumentRequest>
    </RetrieveDocumentSetRequest>
  </soap:Body>
</soap:Envelope>
' \
#--output - | less
