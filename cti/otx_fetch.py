#!/usr/bin/env python3
import os, json, requests
from datetime import datetime

OTX_API_KEY = os.getenv('OTX_API_KEY')
if not OTX_API_KEY:
    raise SystemExit('ERROR: OTX_API_KEY not set')

headers = {'X-OTX-API-KEY': OTX_API_KEY, 'User-Agent': 'cti-pipeline/1.0'}
url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'

print('Fetching CTI data from AlienVault OTX...')
r = requests.get(url, headers=headers, timeout=30)
r.raise_for_status()
data = r.json()

os.makedirs('out', exist_ok=True)
fname = datetime.utcnow().strftime('out/otx_pulses_%Y%m%dT%H%M%SZ.json')
with open(fname, 'w') as f:
    json.dump(data, f, indent=2)
print(f'Saved {fname} with {len(data.get('results', []))} pulses')
