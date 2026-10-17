def test_health_is_public(client):
    assert client.get('/health').status_code==200

def test_private_endpoints_require_auth(client):
    assert client.get('/api/scans').status_code==401
    assert client.get('/api/analytics/overview').status_code==401
    assert client.get('/api/model/readiness').status_code==401

def test_upload_and_history_round_trip(client,auth_headers):
    response=client.post('/api/scans/upload',headers=auth_headers,files={'file':('sample.bin',b'harmless sample fixture for a round trip','application/octet-stream')})
    assert response.status_code==200,response.text
    payload=response.json(); assert len(payload['sha256'])==64; assert payload['filename']=='sample.bin'; assert 'yara_summary' in payload
    history=client.get('/api/scans',headers=auth_headers)
    assert history.status_code==200
    assert any(item['id']==payload['scan_id'] for item in history.json())

def test_scan_upload_creates_actor_attributed_audit_event(client, admin_headers):
    response = client.post('/api/scans/upload', headers=admin_headers, files={'file': ('audited.bin', b'harmless audit fixture', 'application/octet-stream')})
    assert response.status_code == 200, response.text
    events = client.get('/api/admin/audit', headers=admin_headers)
    assert events.status_code == 200
    assert any(e['action'] == 'scan.completed' and e['target'] == str(response.json()['scan_id']) for e in events.json())


def test_registration_role_requests_and_approval(client):
    researcher=client.post('/api/auth/register',json={'email':'researcher-new@example.com','password':'correct-horse-battery-42','full_name':'Research Tester','role':'researcher'})
    assert researcher.status_code==200,researcher.text
    assert researcher.json()['role']=='researcher' and researcher.json()['active'] is True
    for role in ('administrator','security_analyst','soc_member'):
        r=client.post('/api/auth/register',json={'email':f'{role}-new@example.com','password':'correct-horse-battery-42','full_name':'Role Tester','role':role})
        assert r.status_code==200,r.text
        assert r.json()['role']==role and r.json()['active'] is False
        login=client.post('/api/auth/login',json={'email':f'{role}-new@example.com','password':'correct-horse-battery-42','role':role})
        assert login.status_code==403

def test_login_role_must_match_saved_account_role(client):
    client.post('/api/auth/register',json={'email':'role-match@example.com','password':'correct-horse-battery-42','full_name':'Role Match','role':'researcher'})
    wrong=client.post('/api/auth/login',json={'email':'role-match@example.com','password':'correct-horse-battery-42','role':'soc_member'})
    assert wrong.status_code==403
    right=client.post('/api/auth/login',json={'email':'role-match@example.com','password':'correct-horse-battery-42','role':'researcher'})
    assert right.status_code==200,right.text

def test_admin_route_rejects_non_admin(client,auth_headers):
    assert client.get('/api/admin/users',headers=auth_headers).status_code==403

def test_bad_login_rejected(client,auth_headers):
    r=client.post('/api/auth/login',json={'email':'analyst@example.com','password':'wrong-password-xx'})
    assert r.status_code==401


def test_admin_can_manage_roles_and_audit(client,admin_headers):
    created=client.post('/api/admin/users',headers=admin_headers,json={'email':'soc@example.com','password':'soc-passphrase-very-long','full_name':'SOC Operator','role':'soc_member'})
    assert created.status_code==200,created.text
    user=created.json(); assert user['role']=='soc_member'
    changed=client.patch(f"/api/admin/users/{user['id']}/role",headers=admin_headers,json={'role':'security_analyst'})
    assert changed.status_code==200 and changed.json()['role']=='security_analyst'
    events=client.get('/api/admin/audit',headers=admin_headers)
    assert events.status_code==200 and any(e['action']=='admin.user_created' for e in events.json())

def test_tampered_token_rejected(client,auth_headers):
    token=auth_headers['Authorization'].split(' ',1)[1]
    assert client.get('/api/api-placeholder',headers={'Authorization':'Bearer '+token+'x'}).status_code==404
    assert client.get('/api/scans',headers={'Authorization':'Bearer '+token+'x'}).status_code==401


def test_authenticated_analytics_model_and_yara_routes(client,auth_headers):
    assert client.get('/api/analytics/overview',headers=auth_headers).status_code==200
    model=client.get('/api/model/readiness',headers=auth_headers)
    assert model.status_code==200 and 'available' in model.json()
    rules=client.get('/api/yara/rules',headers=auth_headers)
    assert rules.status_code==200 and 'rules' in rules.json()

def test_upload_rejects_unsupported_extension(client,auth_headers):
    response=client.post('/api/scans/upload',headers=auth_headers,files={'file':('sample.txt',b'harmless text','text/plain')})
    assert response.status_code==415
    no_extension=client.post('/api/scans/upload',headers=auth_headers,files={'file':('sample',b'harmless text','application/octet-stream')})
    assert no_extension.status_code==415


def test_yara_manager_rejects_wrong_file_type(client,admin_headers):
    single=client.post('/api/yara/rules',headers=admin_headers,files={'file':('not-a-rule.txt',b'plain text','text/plain')})
    assert single.status_code==415
    pack=client.post('/api/yara/ruleset',headers=admin_headers,data={'source':'test','version':'v1','license_name':'MIT'},files={'file':('not-a-pack.txt',b'not zip','text/plain')})
    assert pack.status_code==415

def test_ruleset_import_rejects_path_traversal_before_install(client,admin_headers):
    import io,zipfile
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:z.writestr('../escape.yar','rule x { condition: true }')
    response=client.post('/api/yara/ruleset',headers=admin_headers,data={'source':'test','version':'traversal-test','license_name':'MIT'},files={'file':('rules.zip',buf.getvalue(),'application/zip')})
    assert response.status_code==400


def test_ruleset_import_records_provenance_and_installs_atomically(client,admin_headers,tmp_path,monkeypatch):
    import io,zipfile,types
    from app.core.config import settings
    monkeypatch.setattr(settings,'yara_rules_dir',str(tmp_path/'rules'))
    fake=types.SimpleNamespace(compile=lambda source: types.SimpleNamespace(rules=[object()]))
    monkeypatch.setitem(__import__('sys').modules,'yara',fake)
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w') as z:z.writestr('upstream/test.yar','rule test { condition: true }')
    response=client.post('/api/yara/ruleset',headers=admin_headers,data={'source':'test-source','version':'v1.2','license_name':'MIT'},files={'file':('rules.zip',buf.getvalue(),'application/zip')})
    assert response.status_code==200,response.text
    payload=response.json();assert payload['file_count']==1 and payload['source']=='test-source'
    manifest=tmp_path/'rules'/'imports'/'test-source_v1.2'/'manifest.json'
    assert manifest.exists()
    assert __import__('json').loads(manifest.read_text())['license']=='MIT'


def test_incident_and_research_workflows_persist(client,admin_headers):
    scan=client.post('/api/scans/upload',headers=admin_headers,files={'file':('triage.bin',b'harmless incident fixture bytes','application/octet-stream')})
    assert scan.status_code==200,scan.text
    sid=scan.json()['scan_id']
    incident=client.post('/api/incidents',headers=admin_headers,json={'scan_id':sid,'title':'Review triage fixture','notes':'Initial analyst review'})
    assert incident.status_code==200,incident.text
    iid=incident.json()['id']
    updated=client.patch(f'/api/incidents/{iid}',headers=admin_headers,json={'status':'investigating','assigned_to':1,'notes':'Review in progress'})
    assert updated.status_code==200 and updated.json()['status']=='investigating'
    annotation=client.post('/api/research/annotations',headers=admin_headers,json={'scan_id':sid,'ground_truth':'unknown','dataset_source':'test fixture','notes':'Not a labeled ground-truth sample'})
    assert annotation.status_code==200,annotation.text
    note=client.post('/api/research/notes',headers=admin_headers,json={'title':'Test note','content':'Record test setup and file hash.','tags':'verification'})
    assert note.status_code==200,note.text
    assert client.get('/api/research/annotations',headers=admin_headers).json()[0]['scan_id']==sid
    assert client.get('/api/research/notes',headers=admin_headers).json()[0]['title']=='Test note'

def test_researcher_cannot_use_incident_workflows(client,auth_headers):
    assert client.get('/api/incidents',headers=auth_headers).status_code==403


def test_model_evaluation_endpoint_returns_saved_artifacts(client, auth_headers):
    response = client.get('/api/model/evaluation', headers=auth_headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload['source'] == 'saved training artifacts'
    assert payload['applies_to_live_scans'] is False
    assert payload['metrics']['selected_model'] == 'Random Forest'
    assert payload['model_comparison'] == []
    assert 'not live scan accuracy' in payload['artifact_consistency_note']


def test_supplied_model_artifacts_match_schema():
    import json
    from pathlib import Path
    from app.services import ml_service
    schema_path = ml_service.SCHEMA_PATH
    model_path = ml_service.MODEL_PATH
    assert schema_path.exists() and model_path.exists()
    schema = json.loads(schema_path.read_text(encoding='utf-8'))
    names = schema['feature_columns_in_input_order']
    assert len(names) == 72 and len(set(names)) == 72
    import joblib
    model = joblib.load(model_path)
    assert int(model.n_features_in_) == len(names)
    assert list(model.feature_names_in_) == names


def test_model_inference_uses_saved_imputers_for_missing_runtime_telemetry(monkeypatch):
    import json
    from pathlib import Path
    from app.services import ml_service
    schema=json.loads(Path('ml/artifacts/feature_schema.json').read_text(encoding='utf-8'))
    features={}
    runtime={'registry_read','registry_write','registry_delete','registry_total','network_threats','network_dns','network_http','network_connections','processes_malicious','processes_suspicious','processes_monitored','total_procsses','files_malicious','files_suspicious','files_text','files_unknown'}
    numeric=set(schema['numeric_features'])
    for name in schema['feature_columns_in_input_order']:
        if name in runtime:
            continue
        if name=='file_extension': features[name]='exe'
        elif name=='PEType': features[name]='PE32+'
        elif name in numeric: features[name]=0
        else: features[name]=0
    monkeypatch.setattr(ml_service,'_runtime_compatibility_error',lambda:None)
    ml_service.reset_model_cache()
    result=ml_service.predict(features)
    assert result['available'] is True, result
    assert result['feature_count']==72
    assert set(result['runtime_features_missing'])==runtime
    assert 'imputed' in result['detail']

def test_scan_result_contains_only_file_derived_indicators(client, auth_headers):
    response = client.post('/api/scans/upload', headers=auth_headers, files={'file': ('demo.bin', b'harmless synthetic test fixture', 'application/octet-stream')})
    assert response.status_code == 200, response.text
    result = response.json()
    assert 'demo_evidence' not in result
    assert 'harmless synthetic test fixture' in result['indicators']['strings']
    assert result['indicators']['urls'] == []
    assert result['indicators']['ips'] == []


def test_soc_member_cannot_upload_samples(client):
    reg = client.post('/api/auth/register', json={'email':'soc-upload@example.com','password':'correct-horse-battery-42','full_name':'SOC Test','role':'soc_member'})
    assert reg.status_code == 200
    from app.models import User
    db = client.test_session_factory()
    user = db.query(User).filter(User.email == 'soc-upload@example.com').first()
    user.active = True
    db.commit()
    db.close()
    login = client.post('/api/auth/login', json={'email':'soc-upload@example.com','password':'correct-horse-battery-42','role':'soc_member'})
    assert login.status_code == 200, login.text
    headers = {'Authorization': f"Bearer {login.json()['access_token']}"}
    response = client.post('/api/scans/upload', headers=headers, files={'file': ('demo.bin', b'harmless', 'application/octet-stream')})
    assert response.status_code == 403
