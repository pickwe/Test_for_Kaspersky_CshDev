# VulnerabilityTracker

REST API на C# для учёта уязвимостей и фонового сканирования C# кода в публичных GitLab репозиториях. Выполнила: Мельникова О.А.

github rep: [pickwe/Test_for_Kaspersky_CshDev](https://github.com/pickwe/Test_for_Kaspersky_CshDev)

## Запуск

Нужен .NET SDK 10. В PowerShell из корня проекта:

```powershell
dotnet run --launch-profile http
```

Сервис запустится на http://localhost:5095
Проверка: http://localhost:5095/health

Тесты запускаются командой **dotnet test**.

## Команды

пока сервис работает  откройте второй PowerShell в корне проекта:

```powershell
.\vuln add "SQL injection" High
.\vuln get <id-уязвимости>
.\vuln scan https://gitlab.com/group/project
.\vuln status <id-сканирования>
.\vuln cancel <id-сканирования>
```

Подставьте ID из ответа **add** или **scan**. Уровни критичности: Low, Medium, High, Critical. Для scan  нужен URL существующего публичного проекта на gitlab.com.

В PowerShell .\ перед vuln указывает на команду в текущей папке. Для вызова просто vuln папку проекта нужно добавить в PATH. Если сервис запущен на другом адресе, задайте его перед командами, например:

```powershell
$env:VULN_API_URL = 'http://localhost:6000'
```

## HTTP API

| Метод  | Адрес                     | Действие                               |
| ------ | ------------------------- | -------------------------------------- |
| POST   | /api/vulnerabilities      | Добавить уязвимость (name, severity)   |
| GET    | /api/vulnerabilities/{id} | Получить уязвимость                    |
| POST   | /api/scans                | Запустить сканирование (repositoryUrl) |
| GET    | /api/scans/{id}           | Получить статус и результат            |
| DELETE | /api/scans/{id}           | Отменить сканирование                  |

Сканирование проходит состояния Queued, Running, Completed, Failed или Canceled. При Completed ответ содержит result, при Failed содержит error. Сканер проверяет только .cs файлы по четырём правилам: TLS, ключ AES в коде, динамический SQL и BinaryFormatter.Deserialize. 

**Лимит: 30 файлов, 100 КБ на файл, 1 МБ всего.**

## Файлы и настройки

Program.cs: маршруты API, логирование запросов и обработка ошибок

Contracts/: модели запросов и ответов

Services/: хранение записей, очередь задач, загрузка и проверка кода

Tests/: unit тесты

vuln.cmd и vuln-client.ps1: короткие команды для API

appsettings.json: Scanning:MaxParallelScans задаёт число одновременных сканирований. По умолчанию 2

Properties/launchSettings.json: адреса локального запуска

Уязвимости и задачи хранятся только в памяти и пропадают после перезапуска. Логи запросов и ошибки выводятся в консоль сервиса.
