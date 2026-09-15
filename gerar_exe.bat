@echo off
setlocal

cd /d "%~dp0"
if errorlevel 1 goto :erro

python -m pip install -r requirements.txt
if errorlevel 1 goto :erro

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name ListarGruposPermissao ^
  --hidden-import=win32security ^
  --hidden-import=win32net ^
  --hidden-import=pywintypes ^
  listar_grupos_permissao.py
if errorlevel 1 goto :erro

echo.
echo Executavel criado em dist\ListarGruposPermissao.exe
pause
exit /b 0

:erro
echo.
echo ERRO: a criacao do executavel foi interrompida.
pause
exit /b 1
