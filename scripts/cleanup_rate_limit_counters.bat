@echo off
setlocal
set "LOG=%TEMP%\IdentityBridge-rate-limit-cleanup.log"
echo ==== %DATE% %TIME% ==== >> "%LOG%"
docker inspect -f "{{.State.Running}}" identitybridge-postgres | findstr /i "true" >nul
if errorlevel 1 (
  echo ERROR: PostgreSQL container is not running. >> "%LOG%"
  exit /b 1
)
docker exec -i identitybridge-postgres psql -v ON_ERROR_STOP=1 -U identitybridge -d identitybridge_app < "D:\IdentityBridge\scripts\cleanup_rate_limit_counters.sql" >> "%LOG%" 2>&1
if errorlevel 1 (
  echo ERROR: Rate-limit cleanup failed. >> "%LOG%"
  exit /b 1
)
echo SUCCESS: Rate-limit cleanup completed. >> "%LOG%"
exit /b 0
