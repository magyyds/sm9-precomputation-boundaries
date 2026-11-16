from pathlib import Path
import hashlib,json
root=Path(__file__).resolve().parent
entries=json.loads((root/'publication_manifest.json').read_text(encoding='utf-8'))
for e in entries:
 p=root/e['path'];assert p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==e['sha256'],e['path']
print('Verified',len(entries),'publication files')
