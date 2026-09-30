@echo off
cd /d "%~dp0..\.."
.venv\Scripts\python tests\test_e2e.py
