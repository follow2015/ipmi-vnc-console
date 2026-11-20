"""Vendor adapters. Importing this package registers the discovery-only ones."""
from .idrac8 import Idrac8Adapter
from .passthrough import PassthroughAdapter
from .supermicro_x10 import SupermicroX10IKVMAdapter

__all__ = ["Idrac8Adapter", "PassthroughAdapter", "SupermicroX10IKVMAdapter"]
