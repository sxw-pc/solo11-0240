"""Offline service release decisions + cross-region write continuity."""

import os
import sys
import types

_HERE = os.path.dirname(__file__)
_REAL = {
    "artifact", "stage", "recovery", "store", "cli", "dispatch", "writes",
    "__main__", "__init__",
}


def _real_module_exists(short):
    if short in _REAL:
        return True
    head = short.split(".")[0]
    if head in _REAL:
        return True
    return (os.path.exists(os.path.join(_HERE, head + ".py")) or
            os.path.exists(os.path.join(_HERE, head, "__init__.py")))


class _ShimModule(types.ModuleType):
    def __getattr__(self, attr):
        if attr.startswith("__") and attr.endswith("__"):
            raise AttributeError(attr)
        from .dispatch import module_call
        short = self.__name__.split(".", 1)[1]
        return module_call(short, attr)


class _RegionFinder:
    def find_spec(self, fullname, path=None, target=None):
        if not fullname.startswith("cloudroll."):
            return None
        short = fullname.split(".", 1)[1]
        if _real_module_exists(short):
            return None
        import importlib.machinery
        loader = _ShimLoader(fullname)
        return importlib.machinery.ModuleSpec(fullname, loader)


class _ShimLoader:
    def __init__(self, fullname):
        self.fullname = fullname

    def create_module(self, spec):
        mod = _ShimModule(spec.name)
        mod.__loader__ = self
        mod.__package__ = "cloudroll"
        return mod

    def exec_module(self, module):
        return None


# Insert near the end so normal finders win for real modules.
if not any(isinstance(f, _RegionFinder) for f in sys.meta_path):
    sys.meta_path.append(_RegionFinder())


def __getattr__(name):
    if name.startswith("__"):
        raise AttributeError(name)
    if _real_module_exists(name):
        raise AttributeError(name)
    fullname = "cloudroll." + name
    mod = _ShimModule(fullname)
    mod.__package__ = "cloudroll"
    sys.modules[fullname] = mod
    return mod
