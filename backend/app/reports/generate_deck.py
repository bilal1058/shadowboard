import os
import sys

_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from app.reports.generate_visual_deck import generate_visual_deck

def create_deck(output_path: str):
    """Generates the unified 8-slide PowerPoint presentation matching reference template."""
    generate_visual_deck(output_path)

if __name__ == "__main__":
    create_deck("ShadowBoard_Presentation.pptx")
