"""Evidence-gated rule applicability, graded DNS omissions and section boundaries.

Reuses production test fixtures without original datasets, Ollama or web calls.
"""
import unittest
from Core import analysis, dns_grounding as d, network_grounding as n
from Testing.test_network_grounding import fixture as port_scan
from Testing.test_dns_grounding import sample as dns_burst


def checks(section, events):
    return n.review_requests({'EXECUTIVE SUMMARY': section}, events)


def codes(section, events):
    return [f['check'] for f in checks(section, events)]


class NT02ValidatorFixTests(unittest.TestCase):
    # ---- Applicability and prompt notes ----
    def test_01_dns_alone_never_produces_tcp_scan_flag(self):
        self.assertNotIn('network_vertical_scan_not_identified', codes('DNS queries are frequent.', dns_burst()))

    def test_02_dns_only_notes_no_vertical_scan_instruction(self):
        notes = n.prompt_notes(dns_burst())
        self.assertTrue(any('DNS GROUNDING' in note for note in notes))
        self.assertFalse(any('vertical TCP port scan' in note for note in notes))
        self.assertFalse(any('Computed aggregate E001' in note for note in notes))

    def test_03_port_scan_retains_scan_mention_flag(self):
        self.assertIn('network_vertical_scan_not_identified', codes('Many connections occurred.', port_scan()))

    def test_04_port_scan_notes_retained(self):
        self.assertTrue(any('vertical TCP port scan' in x for x in n.prompt_notes(port_scan())))

    def test_05_mixed_evidence_reports_tcp_omission(self):
        mixed = port_scan() + [dict(e, ref='E' + str(int(e['ref'][1:])+40).zfill(3)) for e in dns_burst()]
        self.assertIn('network_vertical_scan_not_identified', codes('Sequential DNS query burst.', mixed))

    def test_06_mixed_evidence_reports_dns_omission(self):
        mixed = port_scan() + [dict(e, ref='E' + str(int(e['ref'][1:])+40).zfill(3)) for e in dns_burst()]
        self.assertIn('network_dns_chunk_burst_not_identified', codes('Vertical TCP port scan detected.', mixed))

    def test_07_mixed_prompt_mentions_both(self):
        mixed = port_scan() + [dict(e, ref='E' + str(int(e['ref'][1:])+40).zfill(3)) for e in dns_burst()]
        notes = n.prompt_notes(mixed)
        self.assertTrue(any('vertical TCP port scan' in x for x in notes))
        self.assertTrue(any('DNS GROUNDING' in x for x in notes))

    def test_08_dns_e001_is_not_conn_aggregate(self):
        ev = dns_burst()
        ev[0]['ref'] = 'E001'
        out = n.review_requests({'SIGNIFICANT SECURITY EVENTS': '[E001] connection attempt on port 80'}, ev)
        self.assertNotIn('network_aggregate_misread_as_raw_event', [x['check'] for x in out])

    def test_09_tcp_e001_misread_still_detected(self):
        out = n.review_requests({'SIGNIFICANT SECURITY EVENTS': '[E001] connection attempt on port 80'}, port_scan())
        self.assertIn('network_aggregate_misread_as_raw_event', [x['check'] for x in out])

    def test_10_empty_input_has_no_network_review(self):
        self.assertEqual(n.review_requests({'EXECUTIVE SUMMARY': 'Queries happened.'}, []), [])

    # ---- Pattern identification versus omitted grounded metrics ----
    def test_11_baseline_dns_omission_raises_high(self):
        out = d.review_requests({'EXECUTIVE SUMMARY': 'Queries seem to contain chunks of data.'}, dns_burst())
        self.assertIn('network_dns_chunk_burst_not_identified', [f['check'] for f in out])
        self.assertNotIn('network_dns_chunk_burst_missing_quantification', [f['check'] for f in out])

    def test_12_postgrounding_language_is_recognized(self):
        text = 'A concentrated, high-diversity sequential DNS query burst originating from a host was observed.'
        self.assertNotIn('network_dns_chunk_burst_not_identified', codes(text, dns_burst()))
        self.assertIn('network_dns_chunk_burst_missing_quantification', codes(text, dns_burst()))

    def test_13_missing_metrics_severity_medium(self):
        text = 'A concentrated sequential DNS query burst was observed.'
        f = [x for x in checks(text, dns_burst()) if x['check'] == 'network_dns_chunk_burst_missing_quantification']
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['severity'], 'medium')
        self.assertIn('query_count', f[0]['value'])

    def test_14_fully_quantified_with_evidence_ref(self):
        text = '[E002] Observed 250 distinct DNS queries in 3.552866 seconds, a sequential chunk-style DNS query burst.'
        self.assertNotIn('network_dns_chunk_burst_missing_quantification', codes(text, dns_burst()))
        self.assertNotIn('network_dns_chunk_burst_not_identified', codes(text, dns_burst()))

    def test_15_rounded_seconds_accepted(self):
        text = '[E002] 250 unique DNS queries in 3.55 seconds; sequential chunk-style DNS query burst.'
        self.assertNotIn('network_dns_chunk_burst_missing_quantification', codes(text, dns_burst()))

    def test_16_missing_duration_is_flagged(self):
        text = '[E002] 250 unique DNS queries; sequential chunk-style DNS query burst.'
        f = [x for x in checks(text, dns_burst()) if x['check'] == 'network_dns_chunk_burst_missing_quantification']
        self.assertIn('duration_seconds', f[0]['value'])
        self.assertNotIn('query_count', f[0]['value'])
        self.assertNotIn('distinct_query_count', f[0]['value'])

    def test_17_missing_distinct_is_flagged(self):
        text = '[E002] 250 DNS queries in 3.552866 seconds; sequential chunk-style DNS query burst.'
        f = [x for x in checks(text, dns_burst()) if x['check'] == 'network_dns_chunk_burst_missing_quantification']
        self.assertIn('distinct_query_count', f[0]['value'])

    def test_18_unrelated_number_not_quantification(self):
        text = '[E002] sequential chunk-style DNS query burst; host 250 reported in 3.55 seconds.'
        f = [x for x in checks(text, dns_burst()) if x['check'] == 'network_dns_chunk_burst_missing_quantification']
        self.assertIn('query_count', f[0]['value'])

    def test_19_generalizes_to_different_counts(self):
        ev = dns_burst(count=120, unique=120)
        text = '[E002] 120 unique DNS queries in 3.55 seconds; sequential chunk-style DNS query burst.'
        self.assertNotIn('network_dns_chunk_burst_missing_quantification', codes(text, ev))

    def test_20_old_nt02_count_does_not_generalize_incorrectly(self):
        ev = dns_burst(count=120, unique=120)
        text = '[E002] 250 unique DNS queries in 3.55 seconds; sequential chunk-style DNS query burst.'
        self.assertIn('network_dns_chunk_burst_missing_quantification', codes(text, ev))

    def test_21_no_negative_conclusion_as_positive(self):
        text = '[E002] No DNS query burst observed; sequential chunk-style names were considered.'
        self.assertIn('network_dns_chunk_burst_not_identified', codes(text, dns_burst()))

    def test_22_dns_tunnel_without_burst_not_sufficient(self):
        text = 'Potential DNS tunneling requires investigation.'
        self.assertIn('network_dns_chunk_burst_not_identified', codes(text, dns_burst()))

    # ---- Correct section boundaries and aliases ----
    def test_23_extract_iocs_long_heading_recognized(self):
        text = '## SIGNIFICANT SECURITY EVENTS\n- [E003] Query\n## EXTRACTED IOCs (Indicators of Compromise)\n- IP: 10.0.0.1'
        s = analysis.parse_sections(text, analysis.HEADINGS['log_analysis'])
        self.assertIn('EXTRACTED IOCS', s)
        self.assertNotIn('10.0.0.1', s['SIGNIFICANT SECURITY EVENTS'])

    def test_24_recommendations_alias_recognized(self):
        text = '## SIGNIFICANT SECURITY EVENTS\n- [E003] Query\n## RECOMMENDATIONS\n- Investigate activity.'
        s = analysis.parse_sections(text, analysis.HEADINGS['log_analysis'])
        self.assertIn('RECOMMENDED INVESTIGATION STEPS', s)
        self.assertNotIn('Investigate', s['SIGNIFICANT SECURITY EVENTS'])

    def test_25_unknown_heading_stops_previous_section(self):
        text = '## SIGNIFICANT SECURITY EVENTS\n- [E003] Query\n## CUSTOM SECTION\n- Unreferenced statement.'
        s = analysis.parse_sections(text, analysis.HEADINGS['log_analysis'])
        self.assertNotIn('Unreferenced', s['SIGNIFICANT SECURITY EVENTS'])

    def test_26_unknown_heading_allows_following_known_section(self):
        text = '## SIGNIFICANT SECURITY EVENTS\n- [E003] Query\n## CUSTOM SECTION\n- test\n## INCIDENT TIMELINE\n|Timestamp|Event|'
        s = analysis.parse_sections(text, analysis.HEADINGS['log_analysis'])
        self.assertIn('INCIDENT TIMELINE', s)

    def test_27_nt02_baseline_uncited_sections_not_attributed_to_security_events(self):
        text = ('## SIGNIFICANT SECURITY EVENTS\n- [E003] Query\n'
                '## EXTRACTED IOCs (Indicators of Compromise)\n- IP addresses: 192.168.16.131\n'
                '## RECOMMENDATIONS\n- Investigate the purpose and origin of DNS queries.')
        s = analysis.parse_sections(text, analysis.HEADINGS['log_analysis'])
        self.assertEqual(s['SIGNIFICANT SECURITY EVENTS'], '- [E003] Query')
        self.assertTrue(s['RECOMMENDED INVESTIGATION STEPS'].startswith('- Investigate'))

    def test_28_late_markdown_heading_not_swallowed_by_previous(self):
        s = analysis.parse_sections('## LOG SOURCE\nZeek dns.log\n## INCIDENTAL CONTEXT\nX\n## SIGNIFICANT SECURITY EVENTS\n- [E003] Query',
                                    analysis.HEADINGS['log_analysis'])
        self.assertEqual(s['LOG SOURCE'], 'Zeek dns.log')
        self.assertEqual(s['SIGNIFICANT SECURITY EVENTS'], '- [E003] Query')


if __name__ == '__main__':
    unittest.main()
