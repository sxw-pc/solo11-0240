"""命名兼容门面：完整 API 见 cloudroll.response_api。"""
from .response_api import *  # noqa: F401,F403
from . import response_api as _api

for _name in getattr(_api, "__all__", []):
    globals()[_name] = getattr(_api, _name)


def __getattr__(name):
    return getattr(_api, name)
