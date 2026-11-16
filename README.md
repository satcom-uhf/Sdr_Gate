Прокси с функцией администрирования для OpenWebRx

Позволяет защитить ваш приемник от халявщиков извне.

- /proxy-login - вход на приемник
- /proxy-logout - выход из учетки
- /change-password - смена пароля для пользователей вашего приемника
- /admin - панель управления (управление учетными записями, просмотр активности).
- /proxy-api/online - возвращает список активных пользователей (можно использовать для виджетов в интерфейсе OpenWebRx)

Пример настройки службы на порт 8080
```
sudo chmod +x /opt/openwebrx-proxy/SdrGate
sudo nano /etc/systemd/system/openwebrx-proxy.service
```

```
[Unit]
Description=OpenWebRx+ Reverse Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/openwebrx-proxy
ExecStart=/opt/openwebrx-proxy/SdrGate --urls "http://0.0.0.0:8080"
Restart=always
RestartSec=5
User=root
Environment=ASPNETCORE_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
```
Если требуется, положение OpenWebRx можно изменить в appsettings.json
```
"Address": "http://127.0.0.1:8073"
```
При первом входе создается дефолтная учетка, не забудьте поменять пароль!
```
admin: admin123
```
