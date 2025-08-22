# Configuration file for the Sphinx documentation builder.

import os
import sys

# Add the src directory to Python path for autodoc
sys.path.insert(0, os.path.abspath('../src'))

# -- Project information -----------------------------------------------------

project = 'SanDroid - Dexray Intercept'
copyright = '2024, Daniel Baier, Jan-Niclas Hilgert'
author = 'Daniel Baier, Jan-Niclas Hilgert'

# The full version, including alpha/beta/rc tags
release = '0.3.0.1'
version = '0.3.0.1'

# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.viewcode',
    'sphinx.ext.napoleon',
    'sphinx.ext.githubpages',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx.ext.linkcheck',
    'sphinx_rtd_theme',
    'sphinx_copybutton',
]

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
    'display_version': True,
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
    'frida': ('https://frida.re/docs/', None),
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

# Configure copy button for code blocks
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True
copybutton_only_copy_prompt_lines = True
copybutton_remove_prompts = True

# -- Options for linkcheck extension -----------------------------------------

# Configure link checking
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

# Add custom CSS
html_css_files = [
    'custom.css',
]

# Add favicon
html_favicon = '_static/favicon.ico'

# Custom sidebar
html_sidebars = {
    '**': [
        'relations.html',  # needs 'show_related': True theme option to display
        'searchbox.html',
    ]
}