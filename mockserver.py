from flask import Flask, send_file
import io

app = Flask(__name__)


@app.route("/")
def root():
    return "up and running"


@app.route("/soap-api/PHRService/1.3.0", methods=["POST", "GET"])
def soap():
    fn = open("./samples/retrievedocument-resp_eicar", "br")
    b = io.BytesIO(fn.read())
    response = send_file(b, mimetype="application/xop+xml; type='application/soap+xml'", as_attachment=False)
    response.headers.set("Content-Transfer-Encoding", "binary")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("X-XSS-Protection", "1; mode=block")
    response.headers.set(
        "Cache-Control", "no-cache, no-store, max-age=0, must-revalidate"
    )
    response.headers.set("Pragma", "no-cache")
    response.headers.set("Expires", "0")
    response.headers.set(
        "Strict-Transport-Security", "max-age=31536000 ; includeSubDomains"
    )
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set(
        "Content-Type",
        'multipart/related; type="application/xop+xml"; boundary="uuid:6b62cda6-95c5-441d-9133-da3c5bfd7e6b"; start="<root.message@cxf.apache.org>"; start-info="application/soap+xml"',
    )
    return response


if __name__ == "__main__":
    app.run(host="::", port=5000, debug=True, ssl_context='adhoc')
