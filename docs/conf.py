import sphinx_rtd_theme

project = 'pytest-eosiocdt'
copyright = '2021, Guillermo Rodriguez'
author = 'Guillermo Rodriguez'


extensions = [
    'sphinx.ext.autodoc',
    'sphinx_rtd_theme'
]

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'

html_theme_options = {
    'display_version': True,
    'collapse_navigation': True,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'titles_only': False
}
