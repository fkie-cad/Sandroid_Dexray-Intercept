#!/usr/bin/env python3
from pathlib import Path
import importlib.util
from setuptools import setup, find_packages

# ---- Paths -----------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
ABOUT = SRC / "dexray_intercept" / "about.py"
README = ROOT / "README.md"
REQS = ROOT / "requirements.txt"

# ---- Load metadata from about.py (no exec string) --------------------------
spec = importlib.util.spec_from_file_location("dexray_intercept.about", ABOUT)
about = importlib.util.module_from_spec(spec)
spec.loader.exec_module(about)  # type: ignore[attr-defined]

# ---- Long description (README) ---------------------------------------------
long_description = README.read_text(encoding="utf-8") if README.exists() else ""

# ---- Requirements parsing ---------------------------------------------------
def parse_requirements(path: Path):
    if not path.exists():
        return []
    reqs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        reqs.append(line)
    return reqs

install_requires = parse_requirements(REQS)


setup(
    name="dexray-intercept",
    version=about.__version__,
    description=(
        "Part of the Sandroid dynamic sandbox: creates runtime profiles to "
        "track Android app behavior using Frida."
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fkie-cad/Sandroid_Dexray-Intercept",

    author=about.__author__,
    author_email="daniel.baier@fkie.fraunhofer.de",
    license="GPL-3.0-only",

    # Source layout
    packages=find_packages(where="src"),
    package_dir={"": "src"},

    # Include non-Python assets shipped with the package
    # (adjust this list to actual non-Python files you want to ship)
    package_data={
        "dexray_intercept": [
            "profiling.js",
            # Example: "data/*.json",
        ]
    },
    include_package_data=True,

    # Runtime requirements
    install_requires=install_requires,
    python_requires=">=3.8",

    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: JavaScript",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
    ],
    keywords=["mobile", "instrumentation", "frida", "hook", "android"],

    project_urls={
        "Source": "https://github.com/fkie-cad/Sandroid_Dexray-Intercept",
        "Issues": "https://github.com/fkie-cad/Sandroid_Dexray-Intercept/issues",
        "Documentation": "https://fkie-cad.github.io/Sandroid_Dexray-Intercept/",
    },

    entry_points={
        "console_scripts": [
            "ammm=dexray_intercept.ammm:main",
            "dexray-intercept=dexray_intercept.ammm:main",
        ],
    },
)