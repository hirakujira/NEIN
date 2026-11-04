import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_ad_domains  # noqa: E402


class ScanAdDomainsTests(unittest.TestCase):
    def test_recognizes_only_audited_ad_domains(self):
        domains = scan_ad_domains.domains_from_blobs([
            b'https://googleads.g.doubleclick.net/mads',
            b'https://atlas.taboolanews.com/feed',
            b'https://ad.line-scdn.net/config',
            b'https://profile.line-scdn.net/user',
            b'https://www.google.com/normal-feature',
        ])
        self.assertEqual(domains, (
            'ad.line-scdn.net',
            'doubleclick.net',
            'taboolanews.com',
        ))

    def test_renders_deterministic_text_and_header(self):
        domains = ('taboola.com', 'doubleclick.net')
        self.assertEqual(
            scan_ad_domains.render_domains(domains),
            scan_ad_domains.render_domains(domains),
        )
        header = scan_ad_domains.render_header(domains)
        self.assertIn('@"taboola.com"', header)
        self.assertIn('NEINAdBlockedDomainCount', header)
