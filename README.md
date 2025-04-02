# WHOIS и SSL Микросервис

API для проверки информации о доменах и SSL-сертификатах.

## Endpoints

- `/whois/{domain}` - Получить WHOIS информацию
- `/ssl/{domain}` - Получить информацию о SSL-сертификате

## Локальный запуск

1. `pip install -r requirements.txt`
2. `uvicorn main:app --reload`

## Использование

- WHOIS: `https://your-app.vercel.app/whois/example.com`
- SSL: `https://your-app.vercel.app/ssl/example.com`
