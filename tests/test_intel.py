from app.intel.ioc import IOC, extract_iocs
from app.intel.mitre import map_techniques
from app.intel.risk import assess_risk


def _types(iocs):
    return {(i.type, i.value) for i in iocs}


def test_ioc_refang_and_classification():
    iocs = extract_iocs("beacon to hxxps://evil-c2[.]com/a from 10.0.0.5 to 8.8.8.8, mail bad[at]phish.ru")
    found = _types(iocs)
    assert ("url", "https://evil-c2.com/a") in found
    assert ("domain", "evil-c2.com") in found
    assert ("email", "bad@phish.ru") in found
    ctx = {i.value: i.context for i in iocs if i.type == "ipv4"}
    assert ctx["10.0.0.5"].startswith("internal")
    assert ctx["8.8.8.8"].startswith("external")


def test_hashes_are_not_double_counted():
    sha256 = "a" * 64
    iocs = extract_iocs(f"hash {sha256} and md5 {'b' * 32}")
    assert ("sha256", sha256) in _types(iocs)
    assert ("md5", "b" * 32) in _types(iocs)
    assert not any(i.type == "sha1" for i in iocs)


def test_filenames_are_not_domains():
    iocs = extract_iocs("lsass.exe dumped by procdump.exe into report.zip")
    assert not any(i.type == "domain" for i in iocs)


def test_cve_extraction():
    assert ("cve", "CVE-2021-44228") in _types(extract_iocs("exploitation of cve-2021-44228 observed"))


def test_mitre_mapping_ransomware_chain():
    ids = {t.id for t in map_techniques("vssadmin delete shadows /all /quiet; files renamed to .locked")}
    assert {"T1490", "T1486"} <= ids


def test_mitre_explicit_reference():
    techs = map_techniques("What is T1558.003?")
    assert techs[0].id == "T1558.003"
    assert techs[0].url.endswith("/T1558/003/")


def test_risk_ransomware_is_critical():
    text = "winword spawned powershell -enc AAA; vssadmin delete shadows; files encrypted .locked; 4 GB uploaded to mega.nz"
    risk = assess_risk(text, map_techniques(text), extract_iocs(text))
    assert risk.severity == "CRITICAL"
    assert risk.factors


def test_risk_successful_bruteforce_beats_attempts_only():
    attempts = "sshd: Failed password for root from 185.220.101.4 (x300)"
    success = attempts + " ... Accepted password for root from 185.220.101.4"
    r1 = assess_risk(attempts, map_techniques(attempts), extract_iocs(attempts))
    r2 = assess_risk(success, map_techniques(success), extract_iocs(success))
    assert r2.score > r1.score
    assert r2.severity in {"HIGH", "CRITICAL"}


def test_risk_benign_is_info():
    risk = assess_risk("weekly backup job completed successfully", [], [IOC("ipv4", "10.1.1.1", "internal (RFC1918)")])
    assert risk.severity == "INFO"
