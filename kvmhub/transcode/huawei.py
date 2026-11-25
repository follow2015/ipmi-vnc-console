"""Huawei protocol family plugin: wraps the already validated decoder."""
from ..video.framebuffer import geometry
from ..video.huawei import HuaweiDecoder
from .contract import Decoded, FamilyDecoder


class HuaweiFamily(FamilyDecoder):
    def __init__(self):
        self.decoder = None
        self.width = self.height = 0
        self.header = b''

    def init(self, width, height, header=b''):
        geometry(width, height)
        self.decoder = HuaweiDecoder()
        self.width, self.height, self.header = width, height, header
        return 1

    def feed(self, stream):
        if self.decoder is None:
            raise ValueError('transcode_family_not_initialized')
        return self.decoder.feed(stream, self.width, self.height, self.header)
