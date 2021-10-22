import sphinx_rtd_theme

project = 'pytest-eosio'
copyright = '2021, Guillermo Rodriguez'
author = 'Guillermo Rodriguez'


extensions = [
    'sphinx.ext.autodoc',
    'sphinx_rtd_theme',
    'sphinx_rtd_dark_mode'
]

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'

default_dark_mode = False

html_static_path = ['_static']
html_js_files = [
    'js/expandMenu.js'
]

html_theme_options = {
    'display_version': True,
    'collapse_navigation': False,
    'titles_only': False
}

autodoc_member_order = 'bysource'

aliases = [
    'ExecutionResult', 'ExecutionStream',
    'TransactionResult',
    'ActionResult'
]
autodoc_type_aliases = {}
for type_alias in aliases:
    autodoc_type_aliases.update(
        {type_alias: f'pytest_eosio.typing.{type_alias}'})
