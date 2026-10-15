import requests
import uuid

# ВСТАВЬТЕ СЮДА ВАШ AUTHORIZATION KEY (тот, что на скриншоте)
AUTH_KEY = "MDFhMTNhYWUtN2IyYi03YzM5LThjZGItYTY4ODFhOWY2ZjAzOmI2MGZhMTcwLWE4ODYtNDA5YS04MzcyLTIwYTFiMzllMGFlNw=="  # <-- ЗАМЕНИТЕ НА СВОЙ!

# URL GigaChat OAuth
TOKEN_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"

# Уникальный ID запроса
RQ_UID = str(uuid.uuid4())

headers = {
    "Authorization": f"Basic {AUTH_KEY}",
    "RqUID": RQ_UID,
    "Content-Type": "application/x-www-form-urlencoded"
}

data = {
    "scope": "GIGACHAT_API_PERS"
}

print("🔑 Получаю Access Token...")

try:
    response = requests.post(TOKEN_URL, headers=headers, data=data, verify=False)

    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data["access_token"]

        print("✅ Access Token получен успешно!")

        # Сохраняем токен в файл
        with open("access_token.txt", "w") as f:
            f.write(access_token)
        print("💾 Токен сохранён в access_token.txt")
    else:
        print(f"❌ Ошибка {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"❌ Исключение: {e}")