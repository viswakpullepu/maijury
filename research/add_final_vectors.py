import json

REASONS_FILE = 'research/fake_email_reasons/comprehensive_reasons_taxonomy.json'
with open(REASONS_FILE, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Add to MOTIVE-07
dim7 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-07-IDENTITY-THEFT')
dim7['sub_vectors'].append({
    'name': 'Healthcare PHI & Medical Insurance Identity Theft',
    'target': 'Hospital Patients, Health Plan Members, Clinic Admins',
    'mechanism': 'Spoofs medical insurers or hospital portals asking victim to verify health insurance coverage and Social Security numbers.',
    'psychological_trigger': 'Fear of Losing Medical Coverage + Administrative Compliance',
    'real_world_example': 'Email claiming: "Emergency: Your BlueCross policy is suspended pending coverage re-verification."'
})

# Add to MOTIVE-08
dim8 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-08-DISINFORMATION-DEFAMATION')
dim8['sub_vectors'].append({
    'name': 'Deepfake Executive Video Call Baiting & Pretexting',
    'target': 'Corporate Treasury, Regional Financial Directors',
    'mechanism': 'Email sets up a scheduled video conference with an AI-generated deepfake video/audio executive persona who authorizes wire transfers in real time.',
    'psychological_trigger': 'Authority + Multimodal Sensory Proof (Seeing is Believing)',
    'real_world_example': 'Email inviting CFO to emergency Zoom call where deepfake CEO directs $25M wire to foreign account.'
})

# Add to MOTIVE-09
dim9 = next(d for d in data['dimensions'] if d['category_id'] == 'MOTIVE-09-OT-SCADA-SABOTAGE')
dim9['sub_vectors'].append({
    'name': 'Power Grid & Water Treatment Telemetry Espionage (Modbus/DNP3)',
    'target': 'Substation Technicians, Municipal Water Operators',
    'mechanism': 'Emails with weaponized PDF schematics or Excel workbooks targeting ICS telemetry protocols to stage physical blackout attacks.',
    'psychological_trigger': 'Technical Routine + Emergency Equipment Audit',
    'real_world_example': 'Email delivering Substation_Modbus_Configuration_v4.xlsm containing a BlackEnergy-style payload.'
})

with open(REASONS_FILE, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

total = sum(len(d['sub_vectors']) for d in data['dimensions'])
print(f"Done! Total dimensions: {len(data['dimensions'])}, Total vectors: {total}")
