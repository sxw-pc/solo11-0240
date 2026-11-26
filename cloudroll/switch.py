"""命名兼容门面：交换机/容器/NAT 相关能力统一见 cloudroll.response_api 与 cloudroll.fabric。"""
from .response_api import *  # noqa: F401,F403
from .fabric import ExternalFabric, SwitchFabric, Fabric  # noqa: F401
from . import response_api as _api

for _name in getattr(_api, "__all__", []):
    globals()[_name] = getattr(_api, _name)


def __getattr__(name):
    return getattr(_api, name)
