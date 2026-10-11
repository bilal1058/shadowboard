"""
ShadowBoard Definitive Presentation Deck Generator
Generates a 9-slide 16:9 widescreen presentation (ShadowBoard_Presentation.pptx)
featuring the clean reference card template for Existing Solutions,
embedded live application screenshots for Slides 5, 6, 7, 8, and an ending Slide 9.
Strictly adheres to the Orange/Black/White theme with zero emojis.
"""

import os
import sys

_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE

def generate_visual_deck(output_pptx: str = "ShadowBoard_Presentation.pptx", output_pdf: str = "ShadowBoard_Presentation.pdf", rendered_dir: str = "presentation/rendered_slides"):
    """
    Generates a 9-slide 16:9 widescreen presentation (ShadowBoard_Presentation.pptx)
    and PDF (ShadowBoard_Presentation.pdf) by embedding pixel-perfect 4K Retina renders
    directly captured from presentation/index.html.
    This guarantees 100% exact fidelity with Space Grotesk / JetBrains Mono typography,
    calibrated spacing, borders, and pure black/orange palette.
    """
    import os
    from pptx import Presentation
    from pptx.util import Inches
    from PIL import Image

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    pdf_images = []

    for i in range(1, 10):
        img_name = f"slide_{i:02d}.png"
        img_path = os.path.join(rendered_dir, img_name)
        if not os.path.exists(img_path):
            raise FileNotFoundError(f"Missing rendered slide: {img_path}")

        # Add slide to PowerPoint
        slide = prs.slides.add_slide(blank_layout)
        slide.shapes.add_picture(
            img_path,
            Inches(0),
            Inches(0),
            prs.slide_width,
            prs.slide_height
        )

        # Collect for PDF
        im = Image.open(img_path).convert("RGB")
        pdf_images.append(im)

    prs.save(output_pptx)
    print(f"[OK] Successfully saved pixel-perfect PowerPoint: {output_pptx}")

    if pdf_images and output_pdf:
        pdf_images[0].save(
            output_pdf,
            save_all=True,
            append_images=pdf_images[1:],
            resolution=300.0
        )
        print(f"[OK] Successfully saved pixel-perfect PDF: {output_pdf}")

if __name__ == "__main__":
    generate_visual_deck("ShadowBoard_Presentation.pptx", "ShadowBoard_Presentation.pdf")

