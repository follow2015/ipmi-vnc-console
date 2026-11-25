"""Deterministic synthetic JPEG block fixtures; contains no hardware evidence."""
from io import BytesIO


def jpeg_block(color=(220, 30, 10)):
    from PIL import Image
    out = BytesIO()
    Image.new('RGB', (64, 64), color).save(out, format='JPEG', quality=75,
                                        optimize=False, progressive=False, subsampling=0)
    jpeg = out.getvalue()
    sos = jpeg.index(b'\xff\xda')
    end = sos + 2 + int.from_bytes(jpeg[sos + 2:sos + 4], 'big')
    entropy = jpeg[end:-2]
    return jpeg[:end], b'\x40' + len(entropy).to_bytes(2, 'big') + entropy
