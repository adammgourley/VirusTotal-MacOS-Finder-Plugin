#!/bin/zsh

# Installs VirusTotal Scan Extension to MacOS system.

# Create appropriate directories
echo "Creating required directories (if they don't already exist) ..."
mkdir -p $HOME/.virustotal_plugin/log
mkdir $HOME/.virustotal_plugin/reports

# Copy Python source files
echo "Copying src to $HOME/.virustotal_plugin/src ..."
cp -r ./src $HOME/.virustotal_plugin

# Copy config file
echo "Copying config.ini to $HOME/virustotal_plugin ..."
cp ./config.ini $HOME/.virustotal_plugin

# Install Python dependencies
echo "Installing required Python dependencies ..."
cp "./requirements.txt" $HOME/.virustotal_plugin/src
pip3 install -r $HOME/.virustotal_plugin/src/requirements.txt

# Set permissions on scripts
echo "Settings permissions for script files ..."
sudo chmod +x $HOME/.virustotal_plugin/src/main.py
sudo chmod +x $HOME/.virustotal_plugin/src/scan.py

# Install Quick Action button
echo "Unzipping workflow files ..."
unzip "./QuickActions_Workflow.zip"
echo "Copying workflow files to ~/Library/Services to enable Quick Action shortcut 'Scan with VirusTotal' ..."
cp -r "./Scan with VirusTotal.workflow" ~/Library/Services

# Complete
echo "Installation complete! Review output for any errors during installation ..."