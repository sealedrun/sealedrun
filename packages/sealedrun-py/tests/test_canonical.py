from sealedrun import canonicalize


def test_sorted_keys_and_compact() -> None:
    assert canonicalize({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'


def test_unicode_and_numbers() -> None:
    assert canonicalize({"é": 1e21, "n": 10.0}) == b'{"n":10,"\xc3\xa9":1e+21}'
