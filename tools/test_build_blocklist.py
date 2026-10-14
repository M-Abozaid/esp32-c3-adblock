import pathlib
import subprocess
import sys
import tempfile
import unittest

import build_blocklist
from build_blocklist import HASH_BYTES, fnv

SCRIPT = str(pathlib.Path(__file__).with_name('build_blocklist.py'))
REPO_PARTITIONS = pathlib.Path(__file__).resolve().parent.parent / 'partitions.csv'


def run(*args):
    return subprocess.run([sys.executable, SCRIPT, *map(str, args)], capture_output=True, text=True)


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

            subprocess.run([sys.executable, SCRIPT, str(output), str(source)],
                           check=True, capture_output=True, text=True)

            data = output.read_bytes()
            hashes = {int.from_bytes(data[i:i + HASH_BYTES], 'little')
                      for i in range(0, len(data), HASH_BYTES)}
            expected = {fnv(domain.encode()) for domain in
                        ('ads.example.com', 'tracker.example.com', 'metrics.example.com')}
            self.assertEqual(hashes, expected)


class SizeGuardTests(unittest.TestCase):
    def test_oversized_output_is_refused_and_not_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'list.txt'
            output = root / 'blocklist.bin'
            source.write_text('a.example.com\nb.example.com\nc.example.com\n', encoding='utf-8')

            result = run(output, source, '--max-bytes', 10)       # 3 entries = 15 bytes

            self.assertEqual(result.returncode, 3)
            self.assertIn('TOO BIG', result.stderr)
            self.assertFalse(output.exists())

    def test_oversized_output_leaves_previous_list_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'list.txt'
            output = root / 'blocklist.bin'
            source.write_text('a.example.com\nb.example.com\n', encoding='utf-8')
            output.write_bytes(b'previous')

            self.assertEqual(run(output, source, '--max-bytes', 5).returncode, 3)
            self.assertEqual(output.read_bytes(), b'previous')
            self.assertEqual([p.name for p in root.iterdir() if p.name.startswith('.blocklist-')], [])

    def test_output_within_budget_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'list.txt'
            output = root / 'blocklist.bin'
            source.write_text('a.example.com\nb.example.com\n', encoding='utf-8')

            result = run(output, source, '--max-bytes', 10)       # exactly at the limit

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.stat().st_size, 10)
            self.assertIn('device budget', result.stdout)

    def test_budget_comes_from_custom_partition_table(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            table = root / 'partitions.csv'
            table.write_text('# Name, Type, SubType, Offset, Size\n'
                             'nvs, data, nvs, 0x9000, 0x5000\n'
                             'app0, app, factory, 0x10000, 0x200000\n'
                             'littlefs, data, littlefs, 0x210000, 1M\n', encoding='utf-8')

            budget, _ = build_blocklist.size_budget(None, table)

            self.assertEqual(budget, 1024 * 1024 - build_blocklist.FS_HEADROOM)

    def test_stock_partition_budget(self):
        budget, why = build_blocklist.size_budget(None, None)
        self.assertEqual(budget, build_blocklist.fs_partition_size(REPO_PARTITIONS) - build_blocklist.FS_HEADROOM)
        self.assertIn('partitions.csv', why)

    def test_parse_size_formats(self):
        self.assertEqual(build_blocklist.parse_size('0x150000'), 1376256)
        self.assertEqual(build_blocklist.parse_size('1376256'), 1376256)
        self.assertEqual(build_blocklist.parse_size('1344K'), 1376256)
        self.assertEqual(build_blocklist.parse_size('2M'), 2 * 1024 * 1024)

    def test_explicit_partition_table_that_is_missing_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / 'list.txt'
            output = root / 'out.bin'
            source.write_text('a.example.com\n', encoding='utf-8')

            result = run(output, source, '--partitions', root / 'nope.csv')

            self.assertNotEqual(result.returncode, 0)
            self.assertIn('cannot size against', result.stderr)
            self.assertFalse(output.exists())

    def test_default_partition_table_missing_skips_check(self):
        original = build_blocklist.DEFAULT_PARTITIONS
        try:
            build_blocklist.DEFAULT_PARTITIONS = pathlib.Path('/nonexistent/partitions.csv')
            budget, why = build_blocklist.size_budget(None, None)
        finally:
            build_blocklist.DEFAULT_PARTITIONS = original
        self.assertIsNone(budget)
        self.assertIn('size check skipped', why)


class PresetTests(unittest.TestCase):
    def test_preset_sources_extended_by_positional_sources(self):
        args = build_blocklist.parse_args(['out.bin', '--preset', 'threats', 'extra.txt'])
        self.assertEqual(args.preset, 'threats')
        self.assertEqual(args.sources, ['extra.txt'])

    def test_positional_sources_without_preset_replace_defaults(self):
        args = build_blocklist.parse_args(['out.bin', 'a.txt', '--allow-missing', 'b.txt'])
        self.assertIsNone(args.preset)
        self.assertEqual(args.sources, ['a.txt', 'b.txt'])
        self.assertTrue(args.allow_missing)

    def test_presets(self):
        self.assertEqual(build_blocklist.PRESETS['default'], build_blocklist.DEFAULT_SOURCES)
        self.assertIn(build_blocklist.HAGEZI_TIF_MINI, build_blocklist.PRESETS['threats'])
        self.assertEqual(set(build_blocklist.PRESETS['security']),
                         {build_blocklist.HAGEZI_LIGHT, build_blocklist.HAGEZI_TIF_MINI})

    def test_unknown_preset_rejected(self):
        self.assertEqual(run('out.bin', '--preset', 'nope').returncode, 2)


if __name__ == '__main__':
    unittest.main()
