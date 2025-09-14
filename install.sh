#!/bin/bash

# ------------------------------
# WebSpecter Dependency Installer
# ------------------------------

echo "🔍 Checking Python 3 installation..."

if ! command -v python3 &> /dev/null
then
    echo "❌ Python3 is not installed. Please install Python 3.8+ and try again."
    exit 1
else
    echo "✅ Python3 is installed: $(python3 --version)"
fi

# Check if pip is installed
echo "🔍 Checking pip..."
if ! command -v pip &> /dev/null
then
    echo "📦 pip not found. Installing pip..."
    python3 -m ensurepip --upgrade
else
    echo "✅ pip is installed: $(pip --version)"
fi

# Create virtual environment
echo "🌐 Creating virtual environment 'venv'..."
python3 -m venv venv

# Activate virtual environment
echo "⚡ Activating virtual environment..."
source venv/bin/activate

# Create requirements.txt dynamically if not exists
REQ_FILE="requirements.txt"
if [ ! -f "$REQ_FILE" ]; then
    echo "📄 Creating requirements.txt..."
    cat <<EOL > requirements.txt
requests>=2.31.0
urllib3>=2.0.6
python-whois>=0.7.3
dnspython>=2.3.0
builtwith>=1.6.0
EOL
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Verify installations
echo "🔍 Verifying installations..."
for pkg in requests urllib3 python-whois dnspython builtwith
do
    python3 -c "import $pkg" &> /dev/null
    if [ $? -eq 0 ]; then
        echo "✅ $pkg installed successfully"
    else
        echo "❌ $pkg failed to install"
    fi
done

echo "🎉 All done! Virtual environment 'venv' activated."
echo "To activate later, use: source venv/bin/activate"
