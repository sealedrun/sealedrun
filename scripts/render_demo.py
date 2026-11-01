"""Record the "change one field, verify fails" demo as a GIF and an MP4, reproducibly.

    uv run --with pillow python scripts/render_demo.py docs/demo-tamper

Runs the real commands against `spec/examples/bundle.zip`, captures their output, and renders a
terminal-looking animation with Pillow, then encodes it with ffmpeg. No screen recorder and no
installed terminal tooling is needed, so the clip can be re-made at every release.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
WIDTH, HEIGHT, FPS = 960, 420, 12
BG, FG, DIM, PROMPT, OK, FAIL, EDIT = (
    "#0b1017",
    "#e6edf3",
    "#7d8a99",
    "#7cc4ff",
    "#3fd68a",
    "#ff5c6c",
    "#ffc857",
)


@dataclass
class Line:
    """One terminal line of the clip: typed like a command or printed like output."""

    text: str
    colour: str = FG
    typed: bool = False
    pause: float = 0.0


def run(*args: str) -> str:
    """Run a fixed command in the repository and return its stdout."""
    done = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)
    return done.stdout.rstrip()


def wrap(text: str, width: int = 86) -> list[str]:
    """Break a long output line at spaces, indenting the continuation like a terminal would."""
    out: list[str] = []
    while len(text) > width:
        cut = text.rfind(" ", 0, width)
        cut = width if cut < width // 2 else cut
        out.append(text[:cut])
        text = "      " + text[cut:].lstrip()
    out.append(text)
    return out


def principal_of(bundle: Path) -> str:
    """Read the Principal id from the bundle manifest."""
    with zipfile.ZipFile(bundle) as z:
        return json.loads(z.read("manifest.json"))["principal_id"]


def script(work: Path) -> list[Line]:
    """Run the three demo commands for real and return the lines to animate."""
    bundle = ROOT / "spec" / "examples" / "bundle.zip"
    edited = work / "edited.zip"
    principal = principal_of(bundle)
    short = principal[:12] + "…"
    out: list[Line] = []
    out.append(Line("$ python -m sealedrun bundle.zip " + short, PROMPT, typed=True))
    for text in run("uv", "run", "python", "-m", "sealedrun", str(bundle), principal).splitlines():
        for piece in wrap(text):
            out.append(Line(piece, OK if piece.startswith("OK") else DIM))
    out.append(Line("", pause=0.8))
    out.append(
        Line(
            "$ python scripts/demo_tamper.py bundle.zip edited.zip --seq 2 \\",
            PROMPT,
            typed=True,
        )
    )
    out.append(Line("    --field target.name --value filesystem/write_file", PROMPT, typed=True))
    tamper = run(
        "uv",
        "run",
        "python",
        "scripts/demo_tamper.py",
        str(bundle),
        str(edited),
        "--seq",
        "2",
        "--field",
        "target.name",
        "--value",
        "filesystem/write_file",
    )
    out.append(Line(tamper, EDIT, pause=0.8))
    out.append(Line("", pause=0.4))
    out.append(Line("$ python -m sealedrun edited.zip " + short, PROMPT, typed=True))
    for text in run("uv", "run", "python", "-m", "sealedrun", str(edited), principal).splitlines():
        out.append(Line(text, FAIL if text.startswith("FAIL") else DIM, pause=2.5))
    return out


def frames(lines: list[Line], font: ImageFont.FreeTypeFont) -> list[Image.Image]:
    """Render the lines into frames: commands typed four characters a frame, output at once."""
    shown: list[tuple[str, str]] = []
    images: list[Image.Image] = []

    def snapshot(count: int = 1, cursor: str | None = None) -> None:
        image = Image.new("RGB", (WIDTH, HEIGHT), BG)
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((12, 12, WIDTH - 12, HEIGHT - 12), radius=14, fill="#0f1620")
        for i, colour in enumerate(("#ff5f57", "#febc2e", "#28c840")):
            draw.ellipse((30 + i * 22, 26, 42 + i * 22, 38), fill=colour)
        draw.text((WIDTH // 2 - 60, 24), "sealedrun verify", font=font, fill=DIM)
        y = 60
        for text, colour in shown:
            draw.text((30, y), text, font=font, fill=colour)
            y += 26
        if cursor is not None:
            draw.text((30, y), cursor, font=font, fill=PROMPT)
        images.extend([image] * count)

    for line in lines:
        if line.typed:
            for n in range(4, len(line.text) + 4, 4):
                snapshot(1, line.text[:n] + "▌")
            shown.append((line.text, line.colour))
            snapshot(int(FPS * 0.3))
        else:
            shown.append((line.text, line.colour))
            snapshot(int(FPS * 0.15))
        if line.pause:
            snapshot(int(FPS * line.pause))
    return images


def main(argv: list[str]) -> int:
    """Render the clip to `<target>.gif`, `.mp4` and a `.png` poster of the last frame."""
    target = Path(argv[0]) if argv else ROOT / "docs" / "demo-tamper"
    target.parent.mkdir(parents=True, exist_ok=True)
    font = ImageFont.truetype(FONT, 17)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        images = frames(script(work), font)
        for index, image in enumerate(images):
            image.save(work / f"f{index:05d}.png")
        pattern = str(work / "f%05d.png")
        palette = str(work / "palette.png")
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-framerate",
                str(FPS),
                "-i",
                pattern,
                "-vf",
                "palettegen=max_colors=64:stats_mode=diff",
                palette,
            ],
            check=True,
        )
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-framerate",
                str(FPS),
                "-i",
                pattern,
                "-i",
                palette,
                "-lavfi",
                "paletteuse=dither=none",
                "-loop",
                "0",
                f"{target}.gif",
            ],
            check=True,
        )
        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-loglevel",
                "error",
                "-framerate",
                str(FPS),
                "-i",
                pattern,
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                "-crf",
                "24",
                "-movflags",
                "+faststart",
                f"{target}.mp4",
            ],
            check=True,
        )
        images[-1].save(f"{target}.png")
    for suffix in (".gif", ".mp4", ".png"):
        path = Path(f"{target}{suffix}")
        print(f"{path} {path.stat().st_size / 1024:.0f} KiB, {len(images) / FPS:.1f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
