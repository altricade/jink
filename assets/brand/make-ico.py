"""Packs PNGs of one image at several sizes into a Windows .ico, each size
as rendered (not rescaled): make-ico.py out.ico in-16.png in-32.png ..."""
import sys

from PIL import Image

out, *pngs = sys.argv[1:]
images = [Image.open(p).convert("RGBA") for p in pngs]
images.sort(key=lambda i: i.width)
largest = images[-1]
largest.save(out, format="ICO", sizes=[(i.width, i.height) for i in images], append_images=images[:-1])
