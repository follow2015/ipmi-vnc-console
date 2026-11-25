"""Vendor adapters. Importing this package registers the discovery-only ones."""
from .passthrough import PassthroughAdapter
from .supermicro_x10 import SupermicroX10IKVMAdapter

__all__ = ["PassthroughAdapter", "SupermicroX10IKVMAdapter"]
