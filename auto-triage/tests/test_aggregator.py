from core import aggregator
def test_parse_nmap():
    data = aggregator.parse_nmap('examples/sample_nmap.xml')
    assert 'hosts' in data
