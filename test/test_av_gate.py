import io
import re
import xml.etree.ElementTree as ET
from unittest.mock import Mock

import av_gate
import pytest
import requests


av_gate.config.read_dict(
    {
        "config": {"remove_malicious": True},
        "*:400": {"konnektor": "some"},
        "8.8.8.8:401": {"konnektor": "some"},
    }
)


@pytest.fixture
def client(monkeypatch):
    av_gate.config.update({"*:400": {"Konnektor": "https://nowhere.com"}})
    with av_gate.app.test_client() as client:
        with av_gate.app.app_context():

            # Mock Requests
            class MockResponse:
                headers = {"Test-Header": "bla"}
                content = b"""bla bla"""

                def __init__(self, **kwargs):
                    self.__dict__.update(kwargs)

            def mock_request(url: str, data: str, *args, **kwargs):

                if url.endswith("connector.sds"):
                    return MockResponse(
                        content=open("samples/connector.sds", "rb").read()
                    )

                if b"GET_EICAR" in data:
                    return MockResponse(
                        headers={
                            "Content-Type": 'multipart/related; type="application/xop+xml"; '
                            'boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; '
                            'start="<root.message@cxf.apache.org>"; '
                            'start-info="application/soap+xml";charset=UTF-8'
                        },
                        content=open(
                            "samples/retrievedocument-resp_eicar", "rb"
                        ).read(),
                    )

                if b"ALL_EICAR" in data:
                    return MockResponse(
                        headers={
                            "Content-Type": 'multipart/related; type="application/xop+xml"; '
                            'boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; '
                            'start="<root.message@cxf.apache.org>"; '
                            'start-info="application/soap+xml";charset=UTF-8'
                        },
                        content=open(
                            "samples/retrievedocument-resp_all_eicar", "rb"
                        ).read(),
                    )

                if b"ZIP_EICAR" in data:
                    return MockResponse(
                        headers={
                            "Content-Type": 'multipart/related; type="application/xop+xml"; '
                            'boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; '
                            'start="<root.message@cxf.apache.org>"; '
                            'start-info="application/soap+xml";charset=UTF-8'
                        },
                        content=open(
                            "samples/retrievedocument-resp_eicar_zip", "rb"
                        ).read(),
                    )

                if b"RetrieveDocumentSet" in data:
                    return MockResponse(
                        headers={
                            "Content-Type": 'multipart/related; type="application/xop+xml"; '
                            'boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; '
                            'start="<root.message@cxf.apache.org>"; '
                            'start-info="application/soap+xml";charset=UTF-8'
                        },
                        content=open("samples/retrievedocument-resp", "rb").read(),
                    )

                return MockResponse()

            monkeypatch.setattr(requests, "request", mock_request)

            yield client


@pytest.fixture
def clamav(monkeypatch):
    with av_gate.app.app_context():
        # Mock clamd
        def mock_clamav(stream: io.BytesIO):
            if b"EICAR" in stream.read():
                return {"stream": ("FOUND", "Win.Test.EICAR_HDB-1")}
            else:
                return {"stream": ("OK", None)}

        monkeypatch.setattr(av_gate.clamav, "instream", Mock(side_effect=mock_clamav))

        yield av_gate.clamav.instream


@pytest.mark.parametrize(
    "real_ip,host,expected",
    [
        ("2.2.2.2", "7.7.7.7:400", 200),
        ("8.8.8.8", "7.7.7.7:400", 200),
        ("8.8.8.8", "7.7.7.7:401", 200),
        ("8.8.8.8", "7.7.7.7:402", 500),
    ],
)
def test_routing_ip(client, real_ip, host, expected):
    "check config pick by ip and port"

    res = client.get(
        "/connector.sds",
        headers={"X-real-ip": real_ip, "Host": host},
    )

    assert res.status_code == expected


def test_connector_sds(client):
    "check endpoint is replaced"

    res = client.get(
        "/connector.sds",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
    )
    xml = ET.fromstring(res.data)

    data = {
        e.attrib["Name"]: e.find("**/{*}EndpointTLS").attrib["Location"]
        for e in xml.findall("{*}ServiceInformation/{*}Service")
    }
    assert (
        data["PHRManagementService"]
        == "https://kon-instanz1.titus.ti-dienste.de:443/soap-api/PHRManagementService/1.3.0"
    )
    assert data["PHRService"] == "https://7.7.7.7:400/soap-api/PHRService/1.3.0"


def test_clam_av(client, clamav):
    "check clam_av is called"

    res = client.post(
        "https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=open("./test/retrieveDocumentSet_req.xml", "rb").read(),
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1][re.search(b"(\r?\n){2}", parts[1]).end() :])

    assert len(parts) == 6  # n+2
    assert clamav.has_been_called()


def test_virus_removed(client, clamav):
    "check virus is removed"

    data = (
        open("./test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>GET_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1][re.search(b"(\r?\n){2}?", parts[1]).end() :])

    assert len(parts) == 5  # n+2
    assert clamav.has_been_called()
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:ihe:iti:2007:ResponseStatusType:PartialSuccess"
    )
    assert (
        "detected as malware" in rres.find("*/{*}RegistryError").attrib["codeContext"]
    )


def test_virus_replaced(client, clamav):
    "check virus is removed"

    av_gate.config["config"]["remove_malicious"] = "false"
    data = (
        open("./test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>GET_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])

    # reset config
    av_gate.config["config"]["remove_malicious"] = "true"

    assert len(parts) == 6  # n+2
    assert clamav.has_been_called()
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success"
    )
    assert b"Das Dokument ist mit einem Virus" in parts[3]


def test_virus_replaced_zip(client):
    "check virus is replaced on real zip - needs clamav running"

    av_gate.config["config"]["remove_malicious"] = "false"
    data = (
        open("./test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>ZIP_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])

    # reset config
    av_gate.config["config"]["remove_malicious"] = "true"

    assert len(parts) == 6  # n+2
    # assert clamav.has_been_called()
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success"
    )
    assert b"Das Dokument ist mit einem Virus" in parts[3]


def test_all_is_virusd(client, clamav):
    "check different error message if all msg are malicious"

    data = (
        open("./test/retrieveDocumentSet_req.xml", "rb")
        .read()
        .replace(
            b"<DocumentUniqueId>2.25.140094387439901233557</DocumentUniqueId>",
            b"<DocumentUniqueId>ALL_EICAR</DocumentUniqueId>",
        )
    )

    res = client.post(
        "/https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    parts = res.data.split(b"--uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b")
    xml = ET.fromstring(parts[1].split(b"\r\n\r\n")[1])

    assert len(parts) == 3  # n+2
    rres = xml.find("*//{*}RetrieveDocumentSetResponse/{*}RegistryResponse")
    assert (
        rres is not None
        and rres.attrib["status"]
        == "urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Failure"
    )
    assert (
        rres is not None
        and rres.find("*/{*}RegistryError[@errorCode='XDSRegistryMetadataError']")
        is not None
    )


def test_handle_multipart_request(client, clamav):
    "check handling of requests with multipart"

    data = (
        b"""Content-Type: multipart/related; type="application/xop+xml"; boundary="uuid:999"; start="<root.message@cxf.apache.org>"; start-info="application/soap+xml";charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive


--uuid:999
Content-Type: application/xop+xml; charset=UTF-8; type="application/soap+xml"
Content-Transfer-Encoding: binary
Content-ID: <root.message@cxf.apache.org>

""".replace(
            b"\n", b"\r\n"
        )
        + open("./test/retrieveDocumentSet_req.xml", "rb").read()
    )

    res = client.post(
        "/https://7.7.7.7:400/soap-api/PHRService/1.3.0",
        headers={"X-real-ip": "9.9.9.9", "Host": "7.7.7.7:400"},
        data=data,
    )

    assert res.status_code == 200


@pytest.mark.parametrize(
    "in_id,out_id",
    [
        ("<345-345-345>", "345-345-345"),
        ("cid:345-345-345", "345-345-345"),
        ("<345-345-345@sdf>", "345-345-345"),
        ("cid:345-345-345", "345-345-345"),
        ("345-345-345%40sdf", "345-345-345"),
    ],
)
def test_extract_id(in_id, out_id):
    assert av_gate.extract_id(in_id) == out_id
