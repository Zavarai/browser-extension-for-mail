import requests
import json

# 1. Читаем сохранённый токен из файла
with open("access_token.txt", "r") as f:
    ACCESS_TOKEN = f.read().strip()

# 2. URL и заголовки для GigaChat API
API_URL = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"

headers = {
    "Authorization": f"Bearer {ACCESS_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json"
}

# 3. Тестовое фишинговое письмо
email_text = """
Тема: Срочное обновление пароля!
Уважаемый клиент, ваш аккаунт будет заблокирован через 2 часа. 
Перейдите по ссылке http://sber-verify.ru для подтверждения данных.
С уважением, служба безопасности Сбербанка.
"""

# 4. Промпт, который заставит ИИ ответить в формате JSON
prompt = f"""
Проанализируй текст электронного письма на признаки фишинга и социальной инженерии.

Ответь СТРОГО в формате JSON со следующими полями:
- "is_phishing": true или false
- "threat_level": "низкий", "средний", "высокий" или "критический"
- "reasons": список причин (например: "искусственная срочность", "подозрительный домен")
- "suspicious_elements": список подозрительных элементов (ссылки, домены, фразы)
- "recommendation": краткая рекомендация для пользователя

Текст письма:
{email_text}
"""

# 5. Данные запроса к модели
data = {
    "model": "GigaChat:latest",
    "messages": [
        {"role": "system",
         "content": "Ты эксперт по кибербезопасности. Анализируй письма на фишинг и отвечай ТОЛЬКО валидным JSON без лишнего текста."},
        {"role": "user", "content": prompt}
    ],
    "temperature": 0.1,
    "max_tokens": 1000
}

print("🔍 Отправляю письмо на анализ в GigaChat...\n")

# 6. Отправляем запрос
try:
    response = requests.post(API_URL, headers=headers, json=data, verify=False)

    if response.status_code == 200:
        result = response.json()
        ai_response = result['choices'][0]['message']['content']

        # Пытаемся распарсить ответ как JSON
        try:
            analysis = json.loads(ai_response)
            print("✅ Анализ завершён успешно!\n")
            print(json.dumps(analysis, indent=4, ensure_ascii=False))
        except json.JSONDecodeError:
            print("⚠️ ИИ ответил, но не в формате JSON. Вот сырой ответ:")
            print(ai_response)
    else:
        print(f"❌ Ошибка API: {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"❌ Исключение: {e}")