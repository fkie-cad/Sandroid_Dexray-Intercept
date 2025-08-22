# Documentation Setup Guide

This guide explains how to set up automated documentation building and deployment for Dexray Intercept using GitHub Actions.

## 🚀 Quick Setup

1. **Run the setup script:**
   ```bash
   ./scripts/setup-docs.sh
   ```

2. **Enable GitHub Pages:**
   - Go to repository Settings → Pages
   - Set Source to "GitHub Actions"
   - Save settings

3. **Push changes:**
   ```bash
   git add .
   git commit -m "Add automated documentation workflow"
   git push origin main
   ```

## 📋 What Gets Created

### GitHub Actions Workflows

- **`.github/workflows/docs.yml`** - Main documentation build and deployment
- **`.github/workflows/docs-check.yml`** - PR documentation validation

### Documentation Infrastructure

- **`docs/requirements.txt`** - Python dependencies for Sphinx
- **`docs/_static/custom.css`** - Custom styling for documentation
- **`.github/README.md`** - GitHub Actions documentation

### Configuration Updates

- **`docs/conf.py`** - Enhanced Sphinx configuration with extensions
- **`README.md`** - Added documentation badges and links

## 🔧 How It Works

### On Main Branch Push

1. **Trigger**: Push to `main` with changes to `docs/`, `src/`, `agent/`, or markdown files
2. **Build Process**:
   - Install Python and Node.js dependencies
   - Compile TypeScript hooks with `frida-compile`
   - Build Sphinx documentation
   - Deploy to GitHub Pages

### On Pull Requests

1. **Trigger**: PR to `main` with documentation changes
2. **Validation Process**:
   - Check reStructuredText syntax
   - Validate documentation style
   - Build documentation (error checking)
   - Check internal links
   - Upload preview as artifact
   - Comment on PR with status

## 📖 Documentation Structure

```
docs/
├── index.rst                 # Main documentation entry
├── installation.rst         # Installation guide
├── quickstart.rst           # Quick start guide
├── user-guide/             # User documentation
│   ├── index.rst
│   ├── cli-usage.rst
│   ├── hook-configuration.rst
│   └── output-formats.rst
├── api/                    # API reference
│   ├── index.rst
│   ├── python-api.rst
│   └── typescript-api.rst
├── development/            # Development guides
│   ├── index.rst
│   ├── creating-hooks.rst
│   ├── building.rst
│   └── contributing.rst
├── troubleshooting.rst     # Troubleshooting guide
├── conf.py                # Sphinx configuration
├── requirements.txt       # Documentation dependencies
└── _static/               # Custom assets
    └── custom.css         # Custom styling
```

## 🌐 Accessing Documentation

Once deployed, documentation will be available at:
- **Production**: `https://[username].github.io/Sandroid_Dexray-Intercept/`
- **PR Previews**: Download from GitHub Actions artifacts

## 🔍 Troubleshooting

### Common Issues

**Deprecated GitHub Actions:**
- All action versions have been updated to latest stable versions
- See `.github/WORKFLOW_FIXES.md` for version update details

**Build Fails on TypeScript Compilation:**
```bash
# Check locally
npm run build
# Fix any TypeScript errors
```

**Sphinx Build Errors:**
```bash
# Check locally
cd docs
pip install -r requirements.txt
make html
# Fix any reStructuredText syntax errors
```

**Missing Makefile Errors:**
- `docs/Makefile` and `docs/make.bat` are now included
- Workflows have fallback to direct sphinx-build commands

**GitHub Pages Not Deploying:**
1. Check repository Settings → Pages is set to "GitHub Actions"
2. Verify workflow has `pages: write` permission
3. Check GitHub Actions tab for error details

**Link Check Failures:**
- Update `linkcheck_ignore` in `docs/conf.py` for problematic URLs
- Increase `linkcheck_timeout` for slow sites

### Manual Build

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

### Manual Deployment

Force rebuild and deploy:
```bash
# Delete and recreate gh-pages branch
git branch -D gh-pages
git push origin --delete gh-pages

# Trigger fresh deployment
git commit --allow-empty -m "Trigger docs rebuild"
git push origin main
```

## 🔧 Customization

### Adding Sphinx Extensions

1. Add to `docs/requirements.txt`:
   ```
   sphinx-new-extension>=1.0.0
   ```

2. Add to `docs/conf.py`:
   ```python
   extensions = [
       # ... existing extensions ...
       'sphinx_new_extension',
   ]
   ```

### Custom Styling

Edit `docs/_static/custom.css` to modify appearance:
```css
/* Custom styles for your documentation */
.my-custom-class {
    color: #2980b9;
}
```

### Workflow Customization

Modify `.github/workflows/docs.yml`:
- Change trigger conditions
- Add custom build steps
- Modify deployment targets
- Add notification integrations

## 📊 Monitoring

### GitHub Actions

Monitor builds at: `https://github.com/[username]/[repo]/actions`

### Status Badges

Documentation status badge in README:
```markdown
[![Documentation](https://github.com/[username]/[repo]/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/[username]/[repo]/actions/workflows/docs.yml)
```

## 🛡️ Security

- Documentation builds in isolated GitHub Actions environment
- No secrets or credentials required
- TypeScript compilation in controlled environment
- Only `main` branch deploys to public documentation

## 📞 Support

For issues with documentation setup:

1. Check GitHub Actions logs for detailed error information
2. Review this troubleshooting guide
3. Check Sphinx and GitHub Actions documentation
4. Open an issue in the repository with workflow logs

## 🎯 Best Practices

1. **Keep Documentation Updated**: Documentation automatically rebuilds when code changes
2. **Test Locally**: Always build documentation locally before pushing
3. **Use PR Previews**: Review documentation changes in PRs using artifact previews
4. **Monitor Build Status**: Watch for broken builds and fix promptly
5. **Link Validation**: Regularly check that external links remain valid