Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   AutoHoneyX Startup Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/6] Checking Docker..." -ForegroundColor Yellow
$dockerCheck = docker ps 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "Docker is running" -ForegroundColor Green
} else {
    Write-Host "Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

Write-Host "[2/6] Checking configuration..." -ForegroundColor Yellow
if (-Not (Test-Path .env)) {
    if (Test-Path .env.example) {
        Copy-Item .env.example .env
        Write-Host "Created .env from .env.example" -ForegroundColor Green
    } else {
        Write-Host ".env.example not found" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host ".env file exists" -ForegroundColor Green
}

Write-Host "[3/6] Stopping existing containers..." -ForegroundColor Yellow
docker-compose down 2>&1 | Out-Null
Write-Host "Cleaned up existing containers" -ForegroundColor Green

Write-Host "[4/6] Building and starting services..." -ForegroundColor Yellow
docker-compose up -d --build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Failed to start services" -ForegroundColor Red
    exit 1
}
Write-Host "Services started" -ForegroundColor Green

Write-Host "[5/6] Waiting for database..." -ForegroundColor Yellow
$maxRetries = 30
$retryCount = 0
$dbReady = $false

while ($retryCount -lt $maxRetries -and -not $dbReady) {
    Start-Sleep -Seconds 2
    $result = docker-compose exec -T postgres pg_isready -U autohoneyx 2>&1
    if ($result -match "accepting") {
        $dbReady = $true
        Write-Host "Database is ready" -ForegroundColor Green
    }
    $retryCount++
}

if (-not $dbReady) {
    Write-Host "Database did not become ready" -ForegroundColor Red
    exit 1
}

Write-Host "[6/6] Initializing database..." -ForegroundColor Yellow
Start-Sleep -Seconds 5
docker-compose exec -T app python scripts/init_db.py 2>&1 | Out-Null
Write-Host "Database initialized" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   AutoHoneyX is now running!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Dashboard:     http://localhost:8501" -ForegroundColor Cyan
Write-Host "SSH Honeypot:  localhost:2222" -ForegroundColor Cyan
Write-Host "Web Honeypot:  http://localhost:8080" -ForegroundColor Cyan
Write-Host "DB Honeypot:   localhost:3307" -ForegroundColor Cyan
Write-Host ""
Write-Host "View logs:     docker-compose logs -f" -ForegroundColor Yellow
Write-Host "Stop:          docker-compose down" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Seconds 3
Start-Process "http://localhost:8501"

