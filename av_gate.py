import configparser
import email.parser
import email.policy
import io
import re
from email.message import EmailMessage
from typing import List
from urllib.parse import unquote, urlparse
import logging

import clamd
import lxml.etree as ET
import requests
import urllib3
from flask import Flask, Response, abort, request

__version__ = "0.14"

ALL_METHODS = [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
]

reg_retrieve_document = re.compile(b":RetrieveDocumentSetRequest</Action>")

# to prevent flooding log
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
config = configparser.ConfigParser()

config.read("av_gate.ini")

loglevel = config["config"].get("log_level", "ERROR")
logging.basicConfig(
    level=loglevel, format="[%(asctime)s] %(levelname)-8s in %(module)s: %(message)s"
)
logging.info(f"av_gate {__version__}")
logging.info(f"set loglevel to {loglevel}")
logging.debug(list(config["config"].items()))

clamav = clamd.ClamdUnixSocket(path=config["config"]["clamd_socket"])

# temporary
VIRUS_FOUND_PDF = open("virus_found.pdf", mode="rb").read()

CONTENT_MAX = config["config"].getint("content_max", 800)


@app.route("/connector.sds", methods=["GET"])
def connector_sds():
    """replace the endpoint for PHRService with our address"""
    # <si:Service Name="PHRService">
    # <si:EndpointTLS Location="https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRService/1.3.0"/>

    upstream = request_upstream(warn=False)

    xml = ET.fromstring(upstream.content)
    e = xml.find("{*}ServiceInformation/{*}Service[@Name='PHRService']//{*}EndpointTLS")
    if e is None:
        KeyError("connector.sds does not contain PHRService location.")

    previous_url = urlparse(e.attrib["Location"])
    e.attrib["Location"] = f"{previous_url.scheme}://{request.host}{previous_url.path}"

    return create_response(ET.tostring(xml), upstream)


@app.route("/<path:path>", methods=ALL_METHODS)
def soap(path):
    """Scan AV on xop documents for retrieveDocumentSetRequest"""
    upstream = request_upstream()
    data = run_antivirus(upstream)
    if not data:
        logging.info("no new body, copying content from konnektor")
        data = upstream.content
    assert b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" not in data
    return create_response(data, upstream)


def request_upstream(warn=True) -> Response:
    """Request to real Konnektor"""
    request_ip = request.headers["X-real-ip"]
    port = request.host.split(":")[1] if ":" in request.host else "443"

    client = f"{request_ip}:{port}"
    logging.info(f"client {client}")

    if config.has_section(client):
        cfg = config[client]
    else:
        fallback = "*:" + port
        if not config.has_section(fallback):
            logging.error(f"Client {client} not found in av_gate.ini")
            abort(500)
        else:
            cfg = config[fallback]

    konn = cfg["Konnektor"]
    url = konn + request.path
    data = request.get_data()

    # client cert
    cert = None
    if cfg.get("ssl_cert"):
        cert = (cfg["ssl_cert"], cfg["ssl_key"])
    verify = cfg.getboolean("ssl_verify")

    headers = {
        key: value
        for key, value in request.headers.items()
        if key not in ("X-Real-Ip", "Host")
    }

    try:
        response = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=data,
            cert=cert,
            verify=verify,
        )

        if warn and bytes(konn, "ASCII") in response.content:
            logging.warning(
                f"Found Konnektor Address in response: {konn} - {request.path}"
            )

        return response

    except Exception as err:
        logging.error(err)
        abort(502)


def create_response(data, upstream: Response) -> Response:
    """Create new response with copying headers from origin response"""
    response = Response(data)

    # copy headers from upstream response
    for k, v in upstream.headers.items():
        if k not in ["Transfer-Encoding", "Content-Length"]:
            response.headers[k] = v

    # overwrite content-length with current length
    response.headers["Content-Length"] = str(response.content_length)

    return response


def run_antivirus(res: Response):
    """Remove document when virus was found"""

    # only interested in multipart
    if not res.headers["Content-Type"].lower().startswith("multipart"):
        return

    # add Header for content-type
    body = (
        bytes(f"Content-Type: {res.headers['Content-Type']}\r\n\r\n\r\n", "ascii")
        + res.content
    )
    msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(body)
    soap_part: EmailMessage = next(msg.iter_parts())
    xml = ET.fromstring(soap_part.get_content())
    response_xml = xml.find("{*}Body/{*}RetrieveDocumentSetResponse")

    # only interested in RetrieveDocumentSet
    if response_xml is None:
        logging.info(f"XML NOT FOUND RetrieveDocument {soap_part.get_content()[:200]}")
        return

    virus_atts = []
    REMOVE_MALICIOUS = config["config"].getboolean("remove_malicious", False)

    for att in msg.iter_attachments():
        scan_res = clamav.instream(io.BytesIO(att.get_content()))["stream"]
        content_id = extract_id(att["Content-ID"])
        logging.debug(f"attachment {att.get_content()[:CONTENT_MAX]}")
        if scan_res[0] != "OK":
            logging.info(f"virus found {content_id} : {scan_res}")
            virus_atts.append(content_id)
        else:
            logging.info(f"scanned document {content_id} : {scan_res}")
            if b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in att.get_content():
                logging.error(f"EICAR was not detected by clamav {content_id}")

    if virus_atts:
        xml_resp = response_xml.find("{*}RegistryResponse")
        xml_ns = re.search("{.*}", xml_resp.tag)[0]
        xml_errlist = ET.Element(f"{xml_ns}RegistryErrorList")
        if REMOVE_MALICIOUS:
            xml_resp.append(xml_errlist)

        xml_documents = {}

        for doc in response_xml.findall("{*}DocumentResponse"):
            logging.debug(f"DocumentResponse: {ET.tostring(response_xml)}")
            content_id = extract_id(doc.find("{*}Document/{*}Include").attrib["href"])
            xml_documents[content_id] = doc

        logging.debug(f"content_ids: {list(xml_documents.keys())}")

        attachments: List[EmailMessage] = list(msg.iter_attachments())
        msg.set_payload([soap_part])
        for att in attachments:
            content_id = extract_id(att["Content-ID"])
            document_xml = xml_documents[content_id]
            document_id = document_xml.find("{*}DocumentUniqueId").text

            if content_id in virus_atts:
                if REMOVE_MALICIOUS:
                    add_error_msg(document_xml, xml_errlist, xml_ns)
                    # remove document reference
                    response_xml.remove(document_xml)
                    logging.info(f"document removed {content_id} {document_id}")

                else:  # replace document
                    logging.info(f"document replaced {content_id} {document_id}")
                    att.set_payload(VIRUS_FOUND_PDF)
                    msg.attach(att)
            else:
                logging.debug(f"document untouched {content_id} {document_id}")
                msg.attach(att)

        if REMOVE_MALICIOUS:
            fix_status(xml_resp, xml_errlist, xml_ns, msg)

    REWRITE_SOAP = config["config"].getboolean("rewrite_soap", False)

    if virus_atts or REWRITE_SOAP:
        if REMOVE_MALICIOUS or REWRITE_SOAP:
            soap_part.set_payload(ET.tostring(xml), charset="utf-8")
            del soap_part["MIME-Version"]
        policy = msg.policy.clone(linesep="\r\n")
        payload = msg.as_bytes(policy=policy)
        # remove headers
        body = payload[re.search(b"(\r?\n){3}", payload).end() :]
        logging.info("creating new body")
        logging.debug(body[:CONTENT_MAX])

        return body


def extract_id(id: str) -> str:
    id = unquote(id)

    if id.startswith("cid:"):
        id = id[4:]
    if id.startswith("<"):
        id = id[1:-1]

    if "@" in id:
        id = id[: id.index("@")]

    return id


def add_error_msg(document_id, xml_errlist, xml_ns):
    err_text = f"Document was detected as malware for uniqueId '{document_id}'."
    xml_errlist.append(
        ET.Element(
            f"{xml_ns}RegistryError",
            attrib={
                "codeContext": err_text,
                "errorCode": "XDSDocumentUniqueIdError",  # from RetrieveDocumentSetResponse
                # "errorCode": "XDSMissingDocument", # from AdHocQueryResponse
                "severity": "urn:oasis:names:tc:ebxml-regrep:ErrorSeverityType:Error",
            },
            text=err_text,
        )
    )


def fix_status(xml_resp, xml_errlist, xml_ns, msg):
    if len(msg.get_payload()) > 1:
        xml_resp.attrib["status"] = "urn:ihe:iti:2007:ResponseStatusType:PartialSuccess"
    else:
        xml_resp.attrib[
            "status"
        ] = "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Failure"
        xml_errlist.append(
            ET.Element(
                f"{xml_ns}RegistryError",
                attrib={
                    "severity": "urn:oasis:names:tc:ebxml-regrep:ErrorSeverityType:Error",
                    "errorCode": "XDSRegistryMetadataError",
                    "codeContext": "No documents found for unique ids in request",
                },
                text="No documents found for unique ids in request",
            )
        )


if __name__ == "__main__":
    # only relevant, when started directly.
    # production runs uwsgi
    app.run(host="0.0.0.0", debug=True, port=5001)
