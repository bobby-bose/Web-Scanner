import importlib
import sys


# Alias package name.
# The actual engine lives under `dirsearch/`, which imports itself as `dirsearch.*`.
# This module provides an importable `web_scanner.*` namespace that forwards to it.

_dirsearch = importlib.import_module("dirsearch")
_lib = importlib.import_module("dirsearch.lib")

# Expose common entry points if callers import `web_scanner` directly.
lib = _lib

# Make `import web_scanner.lib...` resolve to `dirsearch.lib...`
sys.modules[__name__ + ".lib"] = _lib
