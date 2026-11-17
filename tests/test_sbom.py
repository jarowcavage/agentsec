import json

import pytest

from agentsec.sbom import InvalidSBOM, parse_sbom

from .conftest import SAMPLE


def test_sample_and_dependency_depth():
    inventory = parse_sbom(SAMPLE.read_bytes())
    assert inventory.component_count == 2
    assert [package.relationships for package in inventory.packages] == [["direct"], ["transitive"]]
    assert not inventory.skipped


def test_nested_and_duplicate_packages_and_cycles():
    bom = json.loads(SAMPLE.read_bytes())
    one, two = bom["components"]
    one["components"] = [two, {**one, "bom-ref": "duplicate"}]
    bom["components"] = [one]
    bom["dependencies"][1]["dependsOn"].append("duplicate")
    bom["dependencies"][2]["dependsOn"] = ["log4j"]
    inventory = parse_sbom(json.dumps(bom).encode())
    assert inventory.component_count == 3
    assert len(inventory.packages) == 2
    assert inventory.packages[0].refs == ["log4j", "duplicate"]
    assert inventory.packages[0].relationships == ["direct", "transitive"]


@pytest.mark.parametrize(
    ("purl", "version", "reason"),
    [
        (None, "1", "Missing package URL"),
        ("garbage", "1", "Invalid package URL"),
        ("pkg:generic/example@1", "1", "Unsupported"),
        ("pkg:npm/example@1", "2", "conflicts"),
        ("pkg:npm/example", None, "Missing or invalid"),
    ],
)
def test_skip_unqueryable_packages(purl, version, reason):
    bom = json.loads(SAMPLE.read_bytes())
    bom["components"] = [{"name": "test", "purl": purl, "version": version}]
    inventory = parse_sbom(json.dumps(bom).encode())
    assert not inventory.packages
    assert reason in inventory.skipped[0].reason


def test_version_in_component_can_complete_purl():
    bom = json.loads(SAMPLE.read_bytes())
    bom["components"] = [{"name": "example", "purl": "pkg:pypi/My_Package", "version": "1.2.3"}]
    (package,) = parse_sbom(json.dumps(bom).encode()).packages
    assert package.purl == "pkg:pypi/my-package@1.2.3"
    assert package.relationships == ["unknown"]


@pytest.mark.parametrize("payload", [b"xxx", b"[]", b'{"bomFormat":"SPDX","specVersion":"1.6"}', b"\xff"])
def test_invalid_input(payload):
    with pytest.raises(InvalidSBOM):
        parse_sbom(payload)


def test_ambiguous_component_refs():
    bom = json.loads(SAMPLE.read_bytes())
    bom["components"].append(bom["components"][0])
    with pytest.raises(InvalidSBOM, match="Duplicate"):
        parse_sbom(json.dumps(bom).encode())
