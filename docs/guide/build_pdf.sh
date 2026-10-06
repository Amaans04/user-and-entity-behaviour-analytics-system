#!/bin/bash
# Rebuild UEBA_Project_Guide_Amaan_Saify.pdf from guide.html with headless Chrome (no dialogs).
cd "$(dirname "$0")/../.." || exit 1
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu --no-pdf-header-footer \
  --allow-file-access-from-files --print-to-pdf="UEBA_Project_Guide_Amaan_Saify.pdf" "file://$(pwd)/docs/guide/guide.html"
