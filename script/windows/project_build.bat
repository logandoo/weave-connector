@echo off
cd /d "%~dp0..\.."
if "%PIP_INDEX_URL%"=="" set PIP_INDEX_URL=https://pypi.org/simple
if not exist .venv\Scripts\python.exe (py -3 -m venv .venv)
.venv\Scripts\pip install -q --upgrade pip
.venv\Scripts\pip install -q -e .
.venv\Scripts\pip install -q pytest
echo build ok
