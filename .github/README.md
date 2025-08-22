# GitHub Actions for Dexray Intercept

This directory contains GitHub Actions workflows for automated documentation building and deployment.

## Workflows

### 📚 Documentation Build and Deploy (`docs.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Changes to documentation (`docs/`), source code (`src/`, `agent/`), or markdown files

**Actions:**
1. **Build Environment Setup**
   - Python 3.9 with Sphinx and extensions
   - Node.js 18 with TypeScript and frida-compile
   - System dependencies for compilation

2. **TypeScript Compilation**
   - Compiles all TypeScript hooks to JavaScript
   - Ensures documentation reflects current code state

3. **Documentation Build**
   - Generates HTML documentation using Sphinx
   - Uses Read the Docs theme with custom styling

4. **GitHub Pages Deployment** (main branch only)
   - Automatically deploys to GitHub Pages
   - Makes documentation available at project URL

### 🔍 Documentation Check (`docs-check.yml`)

**Triggers:**
- Pull requests to `main` or `develop`
- Changes to documentation or source files

**Validation Steps:**
1. **Syntax Checking**
   - reStructuredText syntax validation
   - Documentation style compliance (doc8)

2. **Build Testing**
   - Sphinx build with error checking
   - Internal link validation
   - TypeScript compilation verification

3. **PR Integration**
   - Uploads documentation preview as artifact
   - Comments on PR with build status and download link

## Setup Requirements

### Repository Configuration

1. **Enable GitHub Pages**
   ```
   Settings → Pages → Source: GitHub Actions
   ```

2. **Configure Branch Protection** (optional)
   ```
   Settings → Branches → Add rule for main:
   - Require status checks: "Documentation Check"
   ```

### Local Development

Build documentation locally:
```bash
# Install dependencies
pip install -r docs/requirements.txt
npm install

# Compile TypeScript
npm run build

# Build documentation
cd docs
make html
open _build/html/index.html
```

### Environment Variables

The workflows support these optional environment variables:

- `SPHINX_OPTS`: Additional Sphinx build options
- `NODE_OPTIONS`: Node.js runtime options
- `DOCS_BASE_URL`: Custom base URL for documentation

## File Structure

```
.github/
├── workflows/
│   ├── docs.yml           # Main documentation workflow
│   └── docs-check.yml     # PR documentation validation
└── README.md              # This file

docs/
├── requirements.txt       # Python documentation dependencies
├── conf.py               # Sphinx configuration
├── _static/              # Custom CSS and assets
└── ...                   # Documentation source files
```

## Troubleshooting

### Common Issues

**Build Fails on TypeScript Compilation:**
- Ensure `package.json` and `tsconfig.json` are properly configured
- Check that all TypeScript files have valid syntax

**Sphinx Build Errors:**
- Verify all `.rst` files have correct syntax
- Check that Python imports in autodoc work correctly
- Ensure intersphinx references are accessible

**GitHub Pages Deployment Issues:**
- Verify Pages is enabled in repository settings
- Check that workflow has `pages: write` permission
- Ensure `main` branch protection doesn't block Actions

**Link Check Failures:**
- Update `linkcheck_ignore` in `docs/conf.py` for problematic URLs
- Increase `linkcheck_timeout` for slow external sites

### Manual Deployment

If automatic deployment fails, manually trigger:
```bash
# From repository root
cd docs
make github
```

## Security Considerations

- Documentation is built in isolated GitHub Actions environment
- No secrets or credentials required for public documentation
- TypeScript compilation happens in controlled environment
- Only `main` branch deploys to public GitHub Pages

## Customization

### Adding Extensions

1. Update `docs/requirements.txt` with new Sphinx extensions
2. Add extension to `docs/conf.py` extensions list
3. Configure extension options in `docs/conf.py`

### Custom Styling

- Edit `docs/_static/custom.css` for visual customizations
- Add assets to `docs/_static/` directory
- Reference in `docs/conf.py` using `html_css_files` or `html_js_files`

### Workflow Modifications

- Edit trigger conditions in workflow `on:` sections
- Add additional validation steps in `docs-check.yml`
- Customize deployment targets in `docs.yml`