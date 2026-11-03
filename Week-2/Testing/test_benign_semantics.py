"""Synthetic regression checks for the narrowly scoped benign candidate guardrails."""
import json
import unittest
from Core import benign_semantics, validator


def ev(ref, eid, fields):
    d = {'event_id':eid, 'event_data':fields, 'provider': 'Microsoft-Windows-Sysmon'}
    return {'ref':ref,'event_id':str(eid),'source_kind':'windows','raw':json.dumps(d),
            'fields':{'event_data.'+k:v for k,v in fields.items()},'host':'TESTHOST','user':'SYSTEM'}


def bt01():
    return [ev(f'E{k:03}',1,{'Image':r'C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe',
                     'ParentImage':r'C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe'}) for k in range(1,7)]


def bt02():
    return [ev('E001',4624,{'LogonType':'5','TargetUserName':'SYSTEM','TargetLogonId':'0x3e7'}),
            ev('E002',4672,{'SubjectUserName':'SYSTEM','SubjectLogonId':'0x3e7','PrivilegeList':'SeDebugPrivilege'}),
            ev('E003',4624,{'LogonType':'5','TargetUserName':'SYSTEM','TargetLogonId':'0x3e7'}),
            ev('E004',4672,{'SubjectUserName':'SYSTEM','SubjectLogonId':'0x3e7','PrivilegeList':'SeDebugPrivilege'})]


def bt03():
    return [ev(f'E{i:03}',7036,{'param1': name, 'param2':state}) for i,(name,state) in enumerate([
        ('Windows Biometric Service','stopped'),('BITS','stopped'),('Microsoft Passport','stopped'),
        ('Software Protection','running'),('Software Protection','stopped'),('AppX','stopped')],1)]


def additional_flags(events, section, statement):
    f = validator._Flags({section:statement})
    benign_semantics.add_review_requests(f,{section:statement},events)
    return [x['check'] for x in f.items]


class BenignGuardrailTests(unittest.TestCase):
    def test_bt01_missing_termination(self):
        self.assertIn('process_termination_not_observed',additional_flags(bt01(),'SUSPICIOUS ACTIVITIES',
            '- Possible ngen worker processes starting and stopping multiple times [E001].'))

    def test_bt01_wrong_system32(self):
        self.assertIn('process_image_path_mismatch',additional_flags(bt01(),'CONFIDENCE AND UNCERTAINTY',
            'The processes run from expected directory C:\\Windows\\system32.'))

    def test_bt01_valid_path(self):
        self.assertEqual(additional_flags(bt01(),'SIGNIFICANT SECURITY EVENTS',
            '[E001] mscorsvw.exe started from the Microsoft.NET Framework folder.'), [])

    def test_bt01_only_process_creation(self):
        self.assertEqual(additional_flags(bt01(),'SIGNIFICANT SECURITY EVENTS',
            '[E001] Process start of mscorsvw.exe was observed.'), [])

    def test_bt02_interactive(self):
        self.assertIn('service_logon_type_mismatch',additional_flags(bt02(),'EVIDENCE REFERENCES',
            '[E001] Shows a successful interactive logon by the service account.'))

    def test_bt02_network(self):
        self.assertIn('service_logon_type_mismatch',additional_flags(bt02(),'EVIDENCE REFERENCES',
            '[E003] Indicates another successful network logon by the service account.'))

    def test_bt02_correct_service(self):
        self.assertEqual(additional_flags(bt02(),'SIGNIFICANT SECURITY EVENTS',
            '[E001] Successful service logon (Logon Type 5).'), [])

    def test_bt02_explicit_negation(self):
        self.assertEqual(additional_flags(bt02(),'EVIDENCE REFERENCES',
            '[E001] Not an interactive logon; Service Logon Type 5.'), [])

    def test_bt02_suppress_specific_signal(self):
        f=validator._Flags({'SUSPICIOUS ACTIVITIES':'None identified'})
        f.add('none_claim_vs_signals','high','SeDebugPrivilege assigned','Manually review')
        f.add('finding_without_evidence_ref','medium','A finding','Review')
        benign_semantics.add_review_requests(f,{'SUSPICIOUS ACTIVITIES':'None identified'},bt02())
        self.assertEqual([x['check'] for x in f.items],['finding_without_evidence_ref'])

    def test_bt02_other_signal_remains(self):
        f=validator._Flags({'SUSPICIOUS ACTIVITIES':'None identified'})
        f.add('none_claim_vs_signals','high','SeDebugPrivilege assigned; LSASS referenced','Review')
        benign_semantics.add_review_requests(f,{'SUSPICIOUS ACTIVITIES':'None identified'},bt02())
        self.assertEqual(len(f.items),1)

    def test_bt02_non_system_not_suppressed(self):
        e=bt02()
        e[0]['fields']['event_data.TargetUserName']='SomeAdmin'
        e[0]['raw']=json.dumps({'event_data':{'LogonType':'5','TargetUserName':'SomeAdmin','TargetLogonId':'0x3e7'}})
        f=validator._Flags({'SUSPICIOUS ACTIVITIES':'None identified'})
        f.add('none_claim_vs_signals','high','SeDebugPrivilege assigned','Review')
        benign_semantics.add_review_requests(f,{'SUSPICIOUS ACTIVITIES':'None identified'},e)
        self.assertEqual(len(f.items),1)

    def test_bt03_service_sequence(self):
        self.assertIn('service_start_stop_overgeneralization',additional_flags(bt03(),'POTENTIAL ATTACK INDICATORS',
            'Possible: repeated service stops and starts could be an attempt to hide malicious activity [E001, E004].'))

    def test_bt03_observed_states(self):
        self.assertEqual(additional_flags(bt03(),'SIGNIFICANT SECURITY EVENTS',
            '[E004] Software Protection running; [E005] Software Protection stopped.'), [])

    def test_bt03_not_definite_malware(self):
        self.assertEqual(additional_flags(bt03(),'CONFIDENCE AND UNCERTAINTY',
            'No evidence establishes malicious activity from these 7036 events.'), [])

    def test_nonbaseline_not_tagged(self):
        e=bt03();e[0]['source_kind']='generic'
        self.assertEqual(additional_flags(e,'SUSPICIOUS ACTIVITIES',
            'Repeated service stops and starts were observed.'), [])

    def test_validator_integration_generates_numbered_flag(self):
        statement = '[E001] The mscorsvw.exe processes were starting and stopping repeatedly.'
        flags = validator.validate_output(statement, {'SIGNIFICANT SECURITY EVENTS':statement}, bt01(), [], [])
        target = [f for f in flags if f['check'] == 'process_termination_not_observed']
        self.assertTrue(target)
        self.assertTrue(all(f.get('id','').startswith('F') for f in target))

    def test_validator_integration_reclassifies_system_privilege_signal(self):
        statement = 'None identified'
        flags = validator.validate_output(statement, {'SUSPICIOUS ACTIVITIES':statement}, bt02(), [], [])
        self.assertFalse(any(f['check'] == 'none_claim_vs_signals' for f in flags))

    def test_reference_notes(self):
        self.assertIn('LogonType 5', ' '.join(benign_semantics.extra_reference_notes(bt02())))
        self.assertIn('Event ID 1', ' '.join(benign_semantics.extra_reference_notes(bt01())))
        self.assertIn('7036', ' '.join(benign_semantics.extra_reference_notes(bt03())))


if __name__=='__main__':
    unittest.main()
