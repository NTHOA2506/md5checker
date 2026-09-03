name: Build Windows EXE

on:
  push:
    branches: [ main ]
  workflow_dispatch:

jobs:
  build:
    runs-on: windows-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install PyInstaller
        run: pip install pyinstaller

      - name: Build EXE
        run: pyinstaller --onefile --windowed --name "ChecksumChecker" md5checker.py

      - name: Upload EXE artifact
        uses: actions/upload-artifact@v4
        with:
          name: ChecksumChecker-exe
          path: dist/ChecksumChecker.exe
