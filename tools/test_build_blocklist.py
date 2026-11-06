import pathlib
import subprocess
import sys
import tempfile
import unittest

from build_blocklist import HASH_BYTES, fnv


class BuildBlocklistTests(unittest.TestCase):
    def test_cosmetic_rules_do_not_leak_domains(self):
        # 'domain##selector' cosmetic rules must be skipped entirely — the old
        # split('#') comment heuristic ate '##' and added the bare domain
        # (baidu.com, qq.com, github.com ...) to the blocklist.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'easylist.txt'
            output = root / 'blocklist.bin'
            source.write_text('||ads.example.com^\n'
                              'baidu.com##div.ad\n'
                              'example.org#@#.ad\n'
                              'tmall.com#?#.popup\n'
                              '# plain hosts comment\n', encoding='utf-8')

            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            str(output), str(source)], check=True, capture_output=True, text=True)

            data = output.read_bytes()
            hashes = {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)}
            self.assertEqual(hashes, {fnv(domain.encode()) for domain in ('ads.example.com',)})

    def test_hosts_line_includes_every_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'hosts'
            output = root / 'blocklist.bin'
            source.write_text('0.0.0.0 ads.example.com tracker.example.com # comment\n'
                              '127.0.0.1 metrics.example.com\n', encoding='utf-8')

            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('build_blocklist.py')),
                            str(output), str(source)], check=True, capture_output=True, text=True)

            data = output.read_bytes()
            hashes = {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)}
            expected = {fnv(domain.encode()) for domain in
                        ('ads.example.com', 'tracker.example.com', 'metrics.example.com')}
            self.assertEqual(hashes, expected)


if __name__ == '__main__':
    unittest.main()
