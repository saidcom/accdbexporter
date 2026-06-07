import base64, io, os, tempfile, json
from flask import Flask, request, jsonify, Response
from access_parser import AccessParser

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB

def sanitize(val):
    if isinstance(val, str):
        import re
        return re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', val)
    return val

@app.route('/parse', methods=['POST'])
def parse():
    if 'file' not in request.files:
        return jsonify({"error": "no file"}), 400
    f = request.files['file']
    with tempfile.NamedTemporaryFile(suffix='.accdb', delete=False) as tmp:
        f.save(tmp.name)
        path = tmp.name

    db = AccessParser(path)
    images = {}
    tables_out = []
    img_counter = 0

    for tname in db.catalog:
        if tname.startswith('MSys'): continue
        try:
            data = db.parse_table(tname)
        except Exception:
            continue
        if not data: continue
        cols = list(data.keys())
        nrows = max(len(v) for v in data.values()) if data else 0
        rows = []
        for i in range(nrows):
            row = []
            for c in cols:
                v = data[c][i] if i < len(data[c]) else None
                if isinstance(v, (bytes, bytearray)):
                    mime = sniff_image(v)
                    if mime:
                        img_id = f"img_{img_counter}"; img_counter += 1
                        raw = strip_ole(v, mime)
                        images[img_id] = {
                            "mime": mime,
                            "data_b64": base64.b64encode(raw).decode()
                        }
                        row.append({"image_ref": img_id})
                    else:
                        row.append(f"<binary {len(v)} bytes>")
                else:
                    row.append(sanitize(v))
            rows.append(row)
        tables_out.append({"name": tname, "columns": cols, "rows": rows})

    os.unlink(path)

    payload = {"tables": tables_out, "images": images}
    return Response(
        json.dumps(payload, ensure_ascii=False, default=str),
        content_type='application/json; charset=utf-8'
    )

def sniff_image(b: bytes):
    head = b[:2048]
    if b'\xff\xd8\xff' in head: return 'image/jpeg'
    if b'\x89PNG\r\n\x1a\n' in head: return 'image/png'
    if head.startswith(b'GIF8'): return 'image/gif'
    if b'BM' == head[:2] and len(b) > 14: return 'image/bmp'
    return None

def strip_ole(b: bytes, mime: str) -> bytes:
    sigs = {
        'image/jpeg': b'\xff\xd8\xff',
        'image/png': b'\x89PNG\r\n\x1a\n',
        'image/gif': b'GIF8',
        'image/bmp': b'BM',
    }
    sig = sigs[mime]
    idx = b.find(sig)
    return b[idx:] if idx >= 0 else b

@app.route('/', methods=['GET'])
def health(): return "ok"
