"""AST2100 family: detectable but not transcodable yet.

The source bitstream's self-containment has never been proven, and no decoder
exists in the platform. `detect` may identify the family from an observation;
`build` always refuses so no session can pretend the plugin is usable.
"""
from ..common import Problem
from .contract import FamilyDecoder


class Ast2100Family(FamilyDecoder):
    available = False

    @staticmethod
    def detect(observation) -> bool:
        if not isinstance(observation, dict):
            return False
        return str(observation.get('encoding', '')) in ('87', 'ast2100')

    def init(self, width, height, header=b''):
        raise Problem('transcode_family_unsupported', 503)

    def feed(self, stream):
        raise Problem('transcode_family_unsupported', 503)
