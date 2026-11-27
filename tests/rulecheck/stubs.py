"""Stand-ins so app/access.py and app/rulecheck.py import on the PC (no fastapi, no router)."""
import sys
import types
from unittest.mock import MagicMock


class Stub(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        v = MagicMock(name=f"{self.__name__}.{name}")
        setattr(self, name, v)
        return v


def install(app_dir):
    for n in ("fastapi", "fastapi.responses", "core", "router", "flows", "listcheck"):
        sys.modules[n] = Stub(n)
    core = sys.modules["core"]
    core.state = {}
    core.msp = {"lists": {}}
    core.INTERFACE_METADATA = {}
    core.router_macs = lambda: set()
    sys.modules["router"].feature_settings = {}
    sys.path.insert(0, app_dir)
