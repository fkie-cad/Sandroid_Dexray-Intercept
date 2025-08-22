# Configuration file for the Sphinx documentation builder.
from pathlib import Path
import os
import sys
from datetime import datetime
import importlib.util

# Add the src directory to Python path for autodoc
src_path = os.path.abspath('../src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# ---- Paths -----------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


# Mock imports for modules that might not be available during docs build
autodoc_mock_imports = [
    'frida',
    'frida_tools',
    'AndroidFridaManager'
]

# -- Project information -----------------------------------------------------


current_year = datetime.now().year
start_year = 2024
if current_year == start_year:
    copyright = f"{start_year}, Daniel Baier, Jan-Niclas Hilgert"
else:
    copyright = f"{start_year} - {current_year}, Daniel Baier, Jan-Niclas Hilgert"

project = 'SanDroid - Dexray Intercept'
author = 'Daniel Baier, Jan-Niclas Hilgert'

# The full version, including alpha/beta/rc tags
about_path = SRC / "dexray_intercept" / "about.py"
spec = importlib.util.spec_from_file_location("dexray_intercept.about", about_path)
about = importlib.util.module_from_spec(spec)
spec.loader.exec_module(about)

release = about.__version__
version = about.__version__

# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.githubpages',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
]


if importlib.util.find_spec("sphinx_rtd_theme") is not None:
    extensions.append("sphinx_rtd_theme")

if importlib.util.find_spec("sphinx_copybutton") is not None:
    extensions.append("sphinx_copybutton")


# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The suffix(es) of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.
html_theme = 'sphinx_rtd_theme'

# Theme options are theme-specific and customize the look and feel of a theme
# further.
html_theme_options = {
    'logo_only': False,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': False,
    'vcs_pageview_mode': '',
    'style_nav_header_background': '#2980B9',
    # Toc options
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# -- Extension configuration -------------------------------------------------

# -- Options for intersphinx extension ---------------------------------------

intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
}

# -- Options for todo extension ----------------------------------------------

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True

# -- Options for autodoc extension -------------------------------------------

# This value selects if automatically documented members are sorted alphabetically
autodoc_member_order = 'bysource'

# This value is a list of autodoc directive flags that should be automatically applied
autodoc_default_flags = ['members', 'undoc-members', 'show-inheritance']

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True

# -- Options for copybutton extension ----------------------------------------

# Configure copy button for code blocks (only if extension loaded)
if 'sphinx_copybutton' in extensions:
    copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
    copybutton_prompt_is_regexp = True
    copybutton_only_copy_prompt_lines = True
    copybutton_remove_prompts = True

# -- Options for linkcheck builder --------------------------------------------

# Configure link checking (linkcheck is a builder, not an extension)
linkcheck_ignore = [
    r'http://localhost:\d+/',
    r'https://127\.0\.0\.1:\d+/',
    r'.*example\.com.*',
    r'.*test\.app.*',
    r'.*\.apk$',
]

linkcheck_timeout = 30
linkcheck_retries = 2

# -- GitHub Pages configuration ---------------------------------------------

# Configure GitHub Pages deployment
html_baseurl = 'https://your-username.github.io/Sandroid_Dexray-Intercept/'

# -- Additional HTML options ------------------------------------------------

# Add custom CSS if file exists
if os.path.exists(os.path.join('.', '_static', 'custom.css')):
    html_css_files = ['custom.css']

# Add favicon if file exists
if os.path.exists(os.path.join('.', '_static', 'favicon.ico')):
    html_favicon = '_static/favicon.ico'

# Custom sidebar
html_sidebars = {
    '**': [
        'relations.html',  # needs 'show_related': True theme option to display
        'searchbox.html',
    ]
}