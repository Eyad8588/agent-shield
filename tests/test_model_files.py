import io
import pickle
import zipfile

import pytest

from agent_shield.checks.model_files import classify_global, scan_pickle_bytes
from agent_shield.scanner import scan
from conftest import rule_ids


@pytest.fixture(autouse=True)
def forbid_unpickling(monkeypatch):
    """The scanner must never deserialize model files."""
    def boom(*a, **k):
        raise AssertionError("scanner tried to unpickle")
    monkeypatch.setattr(pickle, "loads", boom)
    monkeypatch.setattr(pickle, "load", boom)
    monkeypatch.setattr(pickle, "Unpickler", boom)


def test_global_reference_detected(write, tmp_path):
    write("m/model.pkl", b"\x80\x02cos\nsystem\n.")
    res = scan(tmp_path / "m")
    assert "PKL001" in rule_ids(res)
    assert res.verdict == "block"


def test_reduce_marks_called():
    imports, err = scan_pickle_bytes(b"\x80\x02cos\ngetcwd\n)R.")
    assert err is None and imports == [("os", "getcwd", True)]


def test_stack_global_with_memo():
    data = b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00\x00\x8c\nsubprocess\x94\x8c\x05Popen\x94\x93\x94."
    imports, _ = scan_pickle_bytes(data)
    assert ("subprocess", "Popen", False) in imports


def test_zip_checkpoint_member_scanned(write, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", b"\x80\x02cbuiltins\nexec\n.")
    write("m/model.pt", buf.getvalue())
    assert "PKL001" in rule_ids(scan(tmp_path / "m"))


def test_clean_state_dict_passes(write, tmp_path):
    data = (b"\x80\x02ccollections\nOrderedDict\n)RX\x06\x00\x00\x00weight"
            b"ctorch._utils\n_rebuild_tensor_v2\n)Rs.")
    write("m/model.pt", data)
    res = scan(tmp_path / "m")
    assert not rule_ids(res) & {"PKL001", "PKL002", "PKL004"}
    assert res.verdict == "pass"


@pytest.mark.parametrize("mod,name,expected", [
    ("os", "system", "dangerous"), ("builtins", "eval", "dangerous"), ("operator", "attrgetter", "dangerous"),
    ("torch", "FloatStorage", "safe"), ("torch", "load", "dangerous"), ("collections", "OrderedDict", "safe"),
    ("mypkg.layers", "Custom", "unknown"),
])
def test_classify(mod, name, expected):
    assert classify_global(mod, name) == expected


def test_safetensors_header_and_hash(write, tmp_path):
    import hashlib
    import json
    import struct
    h = json.dumps({"w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}).encode()
    good = struct.pack("<Q", len(h)) + h + struct.pack("<f", 1.0)
    write("m/model.safetensors", good)
    write("m/SHA256SUMS", f"{hashlib.sha256(good).hexdigest()}  model.safetensors\n")
    assert scan(tmp_path / "m").findings == []
    write("m/model.safetensors", good[:-4] + struct.pack("<f", 2.0))
    assert "MDL002" in rule_ids(scan(tmp_path / "m"))
    write("n/model.safetensors", b"\x80\x02cos\nsystem\n." + b"\0" * 8)
    assert "MDL001" in rule_ids(scan(tmp_path / "n"))


def test_malformed_pickle(write, tmp_path):
    write("m/model.pkl", b"\x80\x02cos\nsys")
    assert "PKL004" in rule_ids(scan(tmp_path / "m"))
