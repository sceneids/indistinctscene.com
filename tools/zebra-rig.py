"""Cut zebra.jpg into a static body and hinged leg pieces for the home page walk.

Run: python tools/zebra-rig.py  (needs pillow, numpy, scipy). Prints piece boxes in image pixels.
"""
import json
from pathlib import Path
import numpy as np
from PIL import Image, ImageDraw
from scipy import ndimage

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'zebra.jpg'
OUT = str(ROOT / 'zebra')
im = Image.open(SRC).convert('RGB')
W, H = im.size
a = np.asarray(im).astype(int)
mx, mn = a.max(-1), a.min(-1)
sat = mx - mn

# zebra mask: anything tinted or darker than paper, minus neutral hexagon lines
M = ((sat > 12) | (mn < 225)) & ~((sat < 10) & (mn > 150))
M = ndimage.binary_closing(M, iterations=2)
lab, n = ndimage.label(~M)
sizes = ndimage.sum(np.ones_like(lab), lab, range(1, n + 1))
for i, s in enumerate(sizes, 1):
    if s < 150:
        M[lab == i] = True
M = ndimage.binary_opening(M, iterations=1)


def poly_mask(pts):
    m = Image.new('L', (W, H), 0)
    ImageDraw.Draw(m).polygon(pts, fill=255)
    return np.asarray(m) > 0


def side(p, q):
    yy, xx = np.mgrid[0:H, 0:W]
    return (q[0] - p[0]) * (yy - p[1]) - (q[1] - p[1]) * (xx - p[0])


def ramp(d, width):
    return np.clip(d / width, 0, 1)


def signed_dist(p, q):
    s = side(p, q)
    L = np.hypot(q[0] - p[0], q[1] - p[1])
    return s / L


LEGS = {
    'hind-far': dict(
        poly=[(192, 503), (243, 512), (243, 536), (226, 560), (214, 674), (148, 674), (150, 560), (182, 528)],
        under=[(243, 512), (252, 512), (252, 540), (246, 560), (243, 536)],
        cut=((180, 520), (245, 526)), hip=(214, 522), knee=(194, 558),
        knee_line=((170, 548), (222, 566))),
    'hind-near': dict(
        poly=[(243, 512), (298, 518), (300, 540), (291, 588), (330, 636), (356, 674), (288, 674), (262, 602), (243, 560), (243, 536)],
        cut=((240, 532), (300, 532)), hip=(268, 532), knee=(272, 588),
        knee_line=((248, 582), (296, 594))),
    'fore-far': dict(
        poly=[(428, 534), (462, 534), (462, 560), (458, 600), (455, 626), (454, 641), (466, 641), (482, 644), (484, 666), (436, 666), (431, 630), (432, 560)],
        under=[(462, 534), (471, 534), (471, 560), (467, 600), (465, 624), (472, 626), (472, 641), (454, 641), (455, 626), (458, 600), (462, 560)],
        cut=((425, 544), (465, 544)), hip=(446, 544), knee=(447, 590),
        knee_line=((430, 590), (462, 590))),
    'fore-near': dict(
        poly=[(462, 520), (502, 514), (502, 600), (489, 630), (484, 643), (466, 641), (454, 641), (455, 626), (461, 600), (462, 560)],
        cut=((455, 544), (505, 540)), hip=(474, 542), knee=(484, 580),
        knee_line=((462, 572), (502, 586))),
}

NOT_PAPER = np.clip((250 - mn) / 10 + (sat - 4) / 8, 0, 1)

BAND = 8          # body keeps pixels this far below the cut, legs fade in across it
KNEE_OVERLAP = 14 # lower segment extends this far above the knee line, under the upper

body = a.copy().astype(float)
erase = np.zeros((H, W), bool)
meta = {}

for name, leg in LEGS.items():
    region = poly_mask(leg['poly']) & M
    rl, rn = ndimage.label(region)
    region = rl == (np.argmax(ndimage.sum(region, rl, range(1, rn + 1))) + 1)
    if 'under' in leg:
        region |= poly_mask(leg['under']) & M
    below_cut = signed_dist(*leg['cut'])     # positive below the cut line
    below_knee = signed_dist(*leg['knee_line'])
    if below_cut[H - 1, W // 2] < 0:
        below_cut = -below_cut
    if below_knee[H - 1, W // 2] < 0:
        below_knee = -below_knee

    leg_region = region & (below_cut > 0)
    erase |= ndimage.binary_dilation(region & (below_cut > BAND), iterations=5) & (below_cut > BAND)

    top_fade = ramp(below_cut, BAND) * NOT_PAPER
    upper_a = leg_region * top_fade * (1 - ramp(below_knee - 2, 3))
    lower_a = leg_region * (below_knee > -KNEE_OVERLAP) * NOT_PAPER

    meta[name] = {'hip': leg['hip'], 'knee': leg['knee']}
    for part, alpha in (('upper', upper_a), ('lower', lower_a)):
        alpha = ndimage.gaussian_filter(alpha.astype(float), 0.6) * (alpha > 0) if part == 'lower' else alpha
        ys, xs = np.nonzero(alpha > 0.01)
        x0, x1, y0, y1 = xs.min(), xs.max() + 1, ys.min(), ys.max() + 1
        rgba = np.dstack([a[y0:y1, x0:x1], (alpha[y0:y1, x0:x1] * 255).round()]).astype('uint8')
        Image.fromarray(rgba, 'RGBA').save(f'{OUT}-{name}-{part}.png', optimize=True)
        meta[name][part] = [int(x0), int(y0), int(x1 - x0), int(y1 - y0)]

paper = np.median(a[(~ndimage.binary_dilation(M, iterations=8)) & (mn > 240)], axis=0)
soft = np.clip(ndimage.gaussian_filter(erase.astype(float), 1.5) * 1.6, 0, 1)[..., None]
body = body * (1 - soft) + paper * soft
Image.fromarray(body.astype('uint8')).save(f'{OUT}-body.jpg', quality=90, optimize=True)
print(json.dumps(meta))
