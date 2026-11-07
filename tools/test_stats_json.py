"""The dashboard parses /stats.json as JSON, so a stray quote in a field
separator breaks the whole page. This test rebuilds the response the way
handleStats() emits it (same statements, same order, sample values) and checks
that the result is valid JSON with the fields the dashboard reads."""
import json
import pathlib
import re
import unittest

SOURCE = pathlib.Path(__file__).resolve().parent.parent / 'src' / 'main.cpp'

# Values handed to the calls in handleStats(), in the order the code uses them.
STRING_VALUES = [
    '192.168.1.104',              # WiFi.localIP()
    '5d 14h 46m',                 # uptime
    '9.9.9.9',                    # upstreamDns (dns)
    'built-in',                   # upstreamSource (dnsSource)
    'http://example.com/list.bin',  # updateUrl
    'ok: 128452 domains',         # updateStatus
    'Software Watchdog',          # bootReset
    'Fatal exception:3',          # bootCrash
    'upload',                     # lastOp
    '192.168.1.50',               # a client's IP
    '84:f3:eb:97:86:9f',          # a client's MAC
    'ads.example.com',            # a custom domain
]
UNSIGNED = [18719, 193101, 128452, 30504, 24, 0, 2072576, 656640, 642260,
            642260, 42, 10, 20]
SIGNED = [-55]
DECIMAL = [0, 0]
BOOLEAN = ['false', 'true', 'true', 'false']

SPECIFIER = re.compile(r'%(lu|ld|d|s)')


def unescape(literal):
    return literal.replace('\\"', '"').replace('\\\\', '\\')


def build_stats_json(source):
    body = source[source.index('static void handleStats()'):]
    body = body[:body.index('// Upstream shipped every state-changing')]
    queues = {'lu': iter(UNSIGNED), 'ld': iter(SIGNED), 'd': iter(DECIMAL),
              's': iter(BOOLEAN)}
    strings = iter(STRING_VALUES)
    out = []
    for statement in body.split(';'):
        call = re.search(r'jsonPut(f|Esc|Ip)?\(\s*("(?:[^"\\]|\\.)*"|[^,)]*)',
                         statement)
        if not call:
            continue
        kind, argument = call.group(1) or '', call.group(2)
        if kind == '' and argument == '","' and re.search(r'if\s*\(\s*i\s*\)', statement):
            # The separator between array items is only emitted from the second
            # item on; the simulation renders one item, so it is skipped.
            continue
        if kind == 'f':
            out.append(SPECIFIER.sub(lambda m: str(next(queues[m.group(1)])),
                                     unescape(argument[1:-1])))
        elif argument.startswith('"'):
            # jsonPut("literal") emits the literal as it is.
            out.append(unescape(argument[1:-1]))
        else:
            # jsonPut(variable), jsonPutEsc(...) and jsonPutIp(...) emit a value.
            out.append(next(strings))
    return ''.join(out)


class StatsJsonTests(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding='utf-8')
        self.raw = build_stats_json(self.source)

    def test_response_is_valid_json(self):
        self.assertIsInstance(json.loads(self.raw), dict)

    def test_dashboard_fields_are_present(self):
        stats = json.loads(self.raw)
        for field in ('ip', 'blocked', 'allowed', 'domains', 'rssi', 'temp', 'heap',
                      'uptime', 'dns', 'dnsSource', 'upurl', 'upiv', 'upstat', 'blocking', 'resumeIn',
                      'defcreds', 'clients', 'custom'):
            self.assertIn(field, stats)

    def test_diagnostics_fields_are_present(self):
        stats = json.loads(self.raw)
        for field in ('reset', 'crash', 'fsTotal', 'fsUsed', 'listBytes', 'lastOp',
                      'lastOpOk', 'lastOpBytes', 'lastOpAge'):
            self.assertIn(field, stats)

    def test_values_land_in_the_right_fields(self):
        stats = json.loads(self.raw)
        self.assertEqual(stats['ip'], '192.168.1.104')
        self.assertEqual(stats['domains'], 128452)
        self.assertEqual(stats['upiv'], 24)
        self.assertEqual(stats['upstat'], 'ok: 128452 domains')
        self.assertEqual(stats['lastOp'], 'upload')
        self.assertEqual(stats['clients'][0]['mac'], '84:f3:eb:97:86:9f')
        self.assertEqual(stats['custom'], ['ads.example.com'])


if __name__ == '__main__':
    unittest.main()
