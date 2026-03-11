import pandas as pd
import matplotlib.pyplot as plt
import json
import datetime
import os
from pathlib import Path

# Создаем необходимые папки
os.makedirs("logs", exist_ok=True)
os.makedirs("reports", exist_ok=True)

# --- Конфигурация ---
LOG_FILE = "logs/dns_logs.txt"
CVE_FILE = "reports/vuln_data.json"
REPORT_FILE = "reports/final_report.json"
PLOT_FILE = "reports/threat_analysis.png"

print("=" * 60)
print("СИСТЕМА МОНИТОРИНГА УГРОЗ")
print("=" * 60)

# --- Этап 1: Сбор данных ---
print("\n[1] ЭТАП СБОРА ДАННЫХ")
print("-" * 40)

# 1.1 Создаем имитацию логов DNS
print("Генерация тестовых DNS-логов...")

logs_data = [
    "2026-03-11 08:15:23, 192.168.1.105, google.com",
    "2026-03-11 08:15:45, 192.168.1.110, yandex.ru",
    "2026-03-11 08:16:02, 192.168.1.105, vk.com",
    "2026-03-11 08:16:30, 192.168.1.120, 185.130.5.133",  # Подозрительный IP
    "2026-03-11 08:17:15, 192.168.1.105, 185.130.5.133",  # Повторный запрос
    "2026-03-11 08:17:45, 192.168.1.105, mail.ru",
    "2026-03-11 08:18:22, 192.168.1.110, github.com",
    "2026-03-11 08:19:05, 192.168.1.105, 185.130.5.133",  # Третий запрос - аномалия
    "2026-03-11 08:19:55, 192.168.1.130, 94.142.241.111",  # Подозрительный IP
    "2026-03-11 08:20:33, 192.168.1.105, habr.com",
    "2026-03-11 08:21:12, 192.168.1.130, 94.142.241.111",  # Повтор
    "2026-03-11 08:22:01, 192.168.1.105, 185.130.5.133",  # Четвертый запрос - КРИТИЧНО
    "2026-03-11 08:22:45, 192.168.1.140, microsoft.com",
    "2026-03-11 08:23:30, 192.168.1.105, 185.130.5.133",  # Пятый запрос - АТАКА
    "2026-03-11 08:24:15, 192.168.1.110, 8.8.8.8",  # Запрос к DNS Google
]

with open(LOG_FILE, "w", encoding="utf-8") as f:
    for line in logs_data:
        f.write(line + "\n")

print(f"✓ Создан файл логов: {LOG_FILE} ({len(logs_data)} записей)")

# 1.2 Создаем имитацию базы уязвимостей
print("Генерация тестовых данных уязвимостей...")

vuln_data = {
    "vulnerabilities": [
        {"id": "CVE-2024-6387", "description": "Критическая уязвимость в OpenSSH", "cvss": 9.8,
         "affected": "OpenSSH < 4.4p1"},
        {"id": "CVE-2025-1234", "description": "Уязвимость удаленного выполнения кода в Apache", "cvss": 9.1,
         "affected": "Apache 2.4.49"},
        {"id": "CVE-2025-5678", "description": "Отказ в обслуживании в DNS BIND", "cvss": 7.5,
         "affected": "BIND 9.16-9.18"},
        {"id": "CVE-2024-4321", "description": "Межсайтовый скриптинг в WordPress", "cvss": 6.1,
         "affected": "WP < 6.4"},
        {"id": "CVE-2024-1111", "description": "Уязвимость повышения привилегий в Linux", "cvss": 7.8,
         "affected": "Linux Kernel 5.x"},
        {"id": "CVE-2023-9876", "description": "Небезопасная десериализация в Java", "cvss": 8.5,
         "affected": "Java 11-17"},
        {"id": "CVE-2025-4321", "description": "SQL-инъекция в phpMyAdmin", "cvss": 8.0,
         "affected": "phpMyAdmin < 5.2"},
    ]
}

with open(CVE_FILE, "w", encoding="utf-8") as f:
    json.dump(vuln_data, f, indent=4, ensure_ascii=False)

print(f"✓ Создан файл уязвимостей: {CVE_FILE} ({len(vuln_data['vulnerabilities'])} записей)")
print("✓ Этап 1 завершен")

# --- Этап 2: Анализ данных ---
print("\n[2] ЭТАП АНАЛИЗА ДАННЫХ")
print("-" * 40)

# 2.1 Анализ DNS-логов
print("Анализ DNS-запросов...")

dns_logs = []
with open(LOG_FILE, "r", encoding="utf-8") as f:
    for line in f:
        parts = line.strip().split(', ')
        if len(parts) == 3:
            dns_logs.append({
                "timestamp": parts[0],
                "src_ip": parts[1],
                "domain": parts[2]
            })

df_dns = pd.DataFrame(dns_logs)
print(f"Всего DNS-запросов: {len(df_dns)}")


# Функция для проверки, является ли строка IP-адресом
def is_ip_address(domain):
    parts = domain.split('.')
    if len(parts) != 4:
        return False
    try:
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except ValueError:
        return False


# Находим подозрительные запросы (прямые обращения к IP)
df_dns['is_ip'] = df_dns['domain'].apply(is_ip_address)
suspicious_queries = df_dns[df_dns['is_ip'] == True]

print(f"Найдено подозрительных запросов (прямые IP): {len(suspicious_queries)}")

# Анализируем частоту запросов по IP-адресам
if len(suspicious_queries) > 0:
    ip_threats = suspicious_queries['src_ip'].value_counts().reset_index()
    ip_threats.columns = ['ip_address', 'suspicious_count']

    # Классифицируем угрозы
    ip_threats['threat_level'] = ip_threats['suspicious_count'].apply(
        lambda x: 'КРИТИЧЕСКИЙ' if x >= 4 else ('ВЫСОКИЙ' if x >= 2 else 'СРЕДНИЙ')
    )

    print("\nОбнаруженные подозрительные IP-адреса:")
    for _, row in ip_threats.iterrows():
        print(f"  • IP: {row['ip_address']} - {row['suspicious_count']} запросов (уровень: {row['threat_level']})")
else:
    ip_threats = pd.DataFrame(columns=['ip_address', 'suspicious_count', 'threat_level'])
    print("Подозрительных IP не обнаружено")

# 2.2 Анализ уязвимостей
print("\nАнализ уязвимостей...")

with open(CVE_FILE, "r", encoding="utf-8") as f:
    vuln_data = json.load(f)

df_cve = pd.DataFrame(vuln_data['vulnerabilities'])
print(f"Всего уязвимостей в базе: {len(df_cve)}")

# Находим критические уязвимости (CVSS >= 7.0)
critical_cve = df_cve[df_cve['cvss'] >= 7.0].copy()
medium_cve = df_cve[(df_cve['cvss'] >= 4.0) & (df_cve['cvss'] < 7.0)].copy()
low_cve = df_cve[df_cve['cvss'] < 4.0].copy()

print(f"Критических уязвимостей (CVSS >= 7.0): {len(critical_cve)}")
print(f"Средних уязвимостей (4.0 <= CVSS < 7.0): {len(medium_cve)}")
print(f"Низких уязвимостей (CVSS < 4.0): {len(low_cve)}")

if len(critical_cve) > 0:
    print("\nКритические уязвимости:")
    for _, row in critical_cve.iterrows():
        print(f"  • {row['id']} - CVSS: {row['cvss']} - {row['description']}")

print("✓ Этап 2 завершен")

# --- Этап 3: Реагирование ---
print("\n[3] ЭТАП РЕАГИРОВАНИЯ")
print("-" * 40)

# Реагирование на подозрительный трафик
if len(suspicious_queries) > 0:
    print("Реагирование на сетевые угрозы:")
    for _, row in ip_threats.iterrows():
        if row['threat_level'] == 'КРИТИЧЕСКИЙ':
            print(f"  ⚠ БЛОКИРОВКА IP: {row['ip_address']} - Обнаружена DDoS-атака!")
            print(f"     Добавлено правило в firewall: deny ip from {row['ip_address']} to any")
        elif row['threat_level'] == 'ВЫСОКИЙ':
            print(f"  ⚠ ОГРАНИЧЕНИЕ IP: {row['ip_address']} - Подозрительная активность")
            print(f"     Установлен лимит соединений для {row['ip_address']}")
        else:
            print(f"  ⚠ НАБЛЮДЕНИЕ: {row['ip_address']} - Требуется дополнительный анализ")
else:
    print("  ✓ Сетевых угроз не обнаружено")

# Реагирование на уязвимости
print("\nРеагирование на уязвимости:")
if len(critical_cve) > 0:
    print("  ⚠ СРОЧНОЕ УВЕДОМЛЕНИЕ: Обнаружены критические уязвимости!")
    print("  ⚠ Отправка уведомления в Telegram...")
    print("  ⚠ Создан тикет в системе отслеживания инцидентов")
    for _, row in critical_cve.iterrows():
        print(f"     - {row['id']}: Требуется немедленное обновление ПО")
else:
    print("  ✓ Критических уязвимостей не обнаружено")

print("✓ Этап 3 завершен")

# --- Этап 4: Отчет и визуализация ---
print("\n[4] ЭТАП ФОРМИРОВАНИЯ ОТЧЕТА")
print("-" * 40)

# Формируем структуру отчета
report = {
    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "statistics": {
        "total_dns_queries": len(df_dns),
        "suspicious_dns_queries": len(suspicious_queries),
        "total_vulnerabilities": len(df_cve),
        "critical_vulnerabilities": len(critical_cve)
    },
    "suspicious_ips": [] if ip_threats.empty else ip_threats.to_dict('records'),
    "critical_vulnerabilities": [] if critical_cve.empty else critical_cve[['id', 'cvss', 'description']].to_dict(
        'records'),
    "actions_taken": {
        "blocked_ips": ip_threats[ip_threats['threat_level'] == 'КРИТИЧЕСКИЙ'][
            'ip_address'].tolist() if not ip_threats.empty else [],
        "notifications_sent": len(critical_cve) > 0
    }
}

# Сохраняем отчет
with open(REPORT_FILE, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4, ensure_ascii=False)

print(f"✓ Отчет сохранен: {REPORT_FILE}")

# Создаем визуализацию
print("Создание графика...")

plt.figure(figsize=(12, 6))

# Создаем два подграфика
plt.subplot(1, 2, 1)

# График 1: Топ подозрительных IP
if not ip_threats.empty:
    top_ips = ip_threats.head(5)
    colors = {'КРИТИЧЕСКИЙ': 'red', 'ВЫСОКИЙ': 'orange', 'СРЕДНИЙ': 'yellow'}
    bar_colors = [colors.get(level, 'gray') for level in top_ips['threat_level']]

    plt.bar(range(len(top_ips)), top_ips['suspicious_count'], color=bar_colors)
    plt.xticks(range(len(top_ips)), top_ips['ip_address'], rotation=45, ha='right')
    plt.title('Топ-5 подозрительных IP-адресов')
    plt.xlabel('IP-адрес')
    plt.ylabel('Количество подозрительных запросов')

    # Добавляем легенду
    from matplotlib.patches import Patch

    legend_elements = [
        Patch(facecolor='red', label='Критический'),
        Patch(facecolor='orange', label='Высокий'),
        Patch(facecolor='yellow', label='Средний')
    ]
    plt.legend(handles=legend_elements, loc='upper right')
else:
    plt.text(0.5, 0.5, 'Подозрительных IP не обнаружено',
             ha='center', va='center', transform=plt.gca().transAxes)
    plt.title('Анализ IP-адресов')

# График 2: Распределение уязвимостей по CVSS
plt.subplot(1, 2, 2)
if not df_cve.empty:
    cvss_ranges = ['0-3.9', '4.0-6.9', '7.0-10.0']
    cvss_counts = [
        len(df_cve[df_cve['cvss'] < 4.0]),
        len(df_cve[(df_cve['cvss'] >= 4.0) & (df_cve['cvss'] < 7.0)]),
        len(df_cve[df_cve['cvss'] >= 7.0])
    ]

    plt.bar(cvss_ranges, cvss_counts, color=['green', 'orange', 'red'])
    plt.title('Распределение уязвимостей по CVSS')
    plt.xlabel('CVSS балл')
    plt.ylabel('Количество уязвимостей')

    # Добавляем подписи значений
    for i, v in enumerate(cvss_counts):
        plt.text(i, v + 0.1, str(v), ha='center', va='bottom')
else:
    plt.text(0.5, 0.5, 'Нет данных об уязвимостях',
             ha='center', va='center', transform=plt.gca().transAxes)
    plt.title('Анализ уязвимостей')

plt.tight_layout()
plt.savefig(PLOT_FILE, dpi=100, bbox_inches='tight')
plt.show()

print(f"✓ График сохранен: {PLOT_FILE}")

# --- Итоговый вывод ---
print("\n" + "=" * 60)
print("ИТОГОВЫЙ ОТЧЕТ")
print("=" * 60)

print(f"Время анализа: {report['timestamp']}")
print(f"Всего DNS-запросов: {report['statistics']['total_dns_queries']}")
print(f"Подозрительных запросов: {report['statistics']['suspicious_dns_queries']}")
print(f"Критических уязвимостей: {report['statistics']['critical_vulnerabilities']}")
print(f"Заблокировано IP-адресов: {len(report['actions_taken']['blocked_ips'])}")

if report['actions_taken']['notifications_sent']:
    print("✓ Уведомления отправлены администратору")

print("\nРезультаты сохранены в папке 'reports'")
print("=" * 60)