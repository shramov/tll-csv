#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import csv
import pytest

from tll.chrono import TimePoint
from tll.error import TLLError

SCHEME = '''yamls://
- name: First
  id: 10
  fields:
    - { name: f0, type: int32 }
    - { name: f1, type: int64 }
    - { name: f2, type: double }
- name: Second
  id: 20
  fields:
    - { name: f0, type: string }
    - { name: f1, type: byte32, options.type: string}
'''

def test_many(context, tmp_path):
    c = context.Channel(f'csv://;basedir={tmp_path}', name='csv', scheme=SCHEME)
    c.open()

    fn0 = tmp_path / "First.csv"
    fn1 = tmp_path / "Second.csv"

    assert not fn0.exists()
    assert not fn1.exists()

    c.post({'f0': 10, 'f1': 20, 'f2': 10.456}, name='First', seq=0)

    assert fn0.exists()
    assert not fn1.exists()

    r = list(csv.reader(open(fn0)))
    assert r[0] == ["seq"] + [f.name for f in c.scheme.messages.First.fields]
    assert r[1:] == [['0', '10', '20', '10.456']]

    c.post({'f0': 'string0', 'f1': 'byte0'}, name='Second', seq=1)

    assert fn0.exists()
    assert fn1.exists()

    r = list(csv.reader(open(fn1)))
    assert r[0] == ["seq"] + [f.name for f in c.scheme.messages.Second.fields]
    assert r[1:] == [['1', 'string0', 'byte0']]

    c.post({'f0': 11, 'f1': 21, 'f2': 11.456}, name='First', seq=2)

    r = list(csv.reader(open(fn0)))
    assert r[0] == ["seq"] + [f.name for f in c.scheme.messages.First.fields]
    assert r[1:] == [['0', '10', '20', '10.456'], ['2', '11', '21', '11.456']]

    c.post({'f0': 'string1', 'f1': 'b1'}, name='Second', seq=3)

    r = list(csv.reader(open(fn1)))
    assert r[0] == ["seq"] + [f.name for f in c.scheme.messages.Second.fields]
    assert r[1:] == [['1', 'string0', 'byte0'], ['3', 'string1', 'b1']]

    c.close()

@pytest.mark.parametrize("t,v", [
    ("int8", 123),
    ("int16", 12345),
    ("int32", 123456789),
    ("int64", 1234567890123),
    ("uint8", 234),
    ("uint16", 56789),
    ("uint32", 0x8f000000),
    ("uint64", 0x8f00000000000000),
    ("double", 123.456),
    ("decimal128", '1234567890123.E-9',),
    ("uint32, options.type: fixed3", (123.456, '123456.E-3')),
    ("string", 'str\"ing'),
    ("string, list-options.offset-ptr-type: legacy-short", 'str\"ing'),
    ("string, list-options.offset-ptr-type: legacy-long", 'str\"ing'),
    ("byte32, options.type: string", "string"),
    ("uint32, options.type: duration, options.resolution: us", "123us"),
    ("double, options.type: duration, options.resolution: ms", "123.456ms"),
    ("uint32, options.type: time_point, options.resolution: s", TimePoint.from_str("2000-01-02T03:04:05")),
    ("int64, options.type: time_point, options.resolution: ms", TimePoint.from_str("2000-01-02T03:04:05.123")),
    ("double, options.type: time_point, options.resolution: us", TimePoint.from_str("2000-01-02T03:04:05.123456")),
    ("uint64, options.type: time_point, options.resolution: ns", TimePoint.from_str("2000-01-02T03:04:05.123456789")),
    ])
def test_type(context, tmp_path, t, v):
    if isinstance(v, tuple):
        v, vs = v
    else:
        vs = str(v)
    scheme = f'''yamls://
- name: Data
  id: 10
  fields:
    - {{ name: g0, type: uint32 }}
    - {{ name: f0, type: {t}}}
    - {{ name: g1, type: uint64 }}
'''

    c = context.Channel(f'csv://;basedir={tmp_path}', name='csv', scheme=scheme)
    c.open()

    guard = 0xffffffff
    c.post({'g0': guard, 'f0': v, 'g1': guard}, name='Data')
    c.close()

    assert (tmp_path / "Data.csv").exists()

    r = list(csv.reader(open(tmp_path / "Data.csv")))
    assert r[0] == ["seq", "g0", "f0", "g1"]
    assert r[1:] == [['0', f'{guard}', vs, f'{guard}']]

@pytest.mark.parametrize("t", ["int32", "byte32", "int32[4]", "*int32", "Sub"])
def test_invalid(context, tmp_path, t):
    scheme = f'''yamls://
- name: Sub
  fields:
    - {{ name: s0, type: int32 }}
- name: Data
  id: 10
  fields:
    - {{ name: f0, type: {t}}}
'''
    c = context.Channel(f'csv://;basedir={tmp_path}', name='csv', scheme=scheme)
    if t == "int32":
        c.open()
    else:
        with pytest.raises(TLLError): c.open()

def test_bound_check(context, tmp_path):
    scheme = '''yamls://
- name: Data
  id: 10
  fields:
    - { name: f0, type: byte8, options.type: string }
    - { name: f1, type: string }
'''
    c = context.Channel(f'csv://;basedir={tmp_path}', name='csv', scheme=scheme)
    c.open()

    with pytest.raises(TLLError): c.post(b'\0' * 4, name='Data')
    with pytest.raises(TLLError): c.post(b'a' * 16, name='Data')
