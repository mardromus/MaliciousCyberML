"""Runs tests/test_pipeline.py without needing pytest installed.
Usage:  python demo/run_tests.py      (or: python -m pytest -v tests)"""
import importlib.util
import os
import traceback

path = os.path.join(os.path.dirname(__file__), "..", "tests", "test_pipeline.py")
spec = importlib.util.spec_from_file_location("test_pipeline", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
tests = [n for n in dir(mod) if n.startswith("test_")]
passed = 0
for name in sorted(tests, key=lambda n: getattr(mod, n).__code__.co_firstlineno):
    try:
        getattr(mod, name)()
        passed += 1
        print(f"tests/test_pipeline.py::{name:<45} PASSED")
    except Exception:
        print(f"tests/test_pipeline.py::{name:<45} FAILED")
        traceback.print_exc()
print(f"\n{passed} of {len(tests)} tests passed")
