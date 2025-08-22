#!/bin/bash

# Setup script for GitHub Pages documentation deployment

set -e

echo "🔧 Setting up Dexray Intercept Documentation"
echo "=============================================="

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "❌ Error: Not in a git repository"
    exit 1
fi

# Get repository information
REPO_URL=$(git config --get remote.origin.url)
if [[ $REPO_URL == *"github.com"* ]]; then
    # Extract username and repo name from GitHub URL
    if [[ $REPO_URL == *".git" ]]; then
        REPO_URL=${REPO_URL%.git}
    fi
    
    if [[ $REPO_URL == "https://github.com/"* ]]; then
        REPO_PATH=${REPO_URL#https://github.com/}
    elif [[ $REPO_URL == "git@github.com:"* ]]; then
        REPO_PATH=${REPO_URL#git@github.com:}
    fi
    
    USERNAME=$(echo $REPO_PATH | cut -d'/' -f1)
    REPO_NAME=$(echo $REPO_PATH | cut -d'/' -f2)
    
    DOCS_URL="https://${USERNAME}.github.io/${REPO_NAME}/"
    
    echo "📍 Repository: $USERNAME/$REPO_NAME"
    echo "📖 Documentation URL: $DOCS_URL"
else
    echo "⚠️  Warning: Not a GitHub repository. GitHub Pages won't work."
    echo "   Repository URL: $REPO_URL"
    read -p "Enter your GitHub Pages URL manually: " DOCS_URL
fi

# Update documentation configuration
echo ""
echo "🔧 Updating documentation configuration..."

# Update Sphinx conf.py
if [ -f "docs/conf.py" ]; then
    sed -i.bak "s|html_baseurl = '.*'|html_baseurl = '${DOCS_URL}'|g" docs/conf.py
    echo "✅ Updated docs/conf.py"
else
    echo "❌ docs/conf.py not found"
fi

# Update README.md
if [ -f "README.md" ]; then
    sed -i.bak "s|https://your-username.github.io/Sandroid_Dexray-Intercept/|${DOCS_URL}|g" README.md
    echo "✅ Updated README.md"
else
    echo "❌ README.md not found"
fi

# Clean up backup files
rm -f docs/conf.py.bak README.md.bak

echo ""
echo "🚀 Setup complete! Next steps:"
echo ""
echo "1. Commit the configuration changes:"
echo "   git add docs/conf.py README.md"
echo "   git commit -m 'Configure GitHub Pages documentation'"
echo ""
echo "2. Push to main branch to trigger documentation build:"
echo "   git push origin main"
echo ""
echo "3. Enable GitHub Pages in repository settings:"
echo "   - Go to Settings → Pages"
echo "   - Set Source to 'GitHub Actions'"
echo ""
echo "4. Documentation will be available at:"
echo "   $DOCS_URL"
echo ""
echo "📖 Check the GitHub Actions tab for build status"