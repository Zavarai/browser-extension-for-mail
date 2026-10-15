document.getElementById('checkBtn').addEventListener('click', async () => {
  const resultDiv = document.getElementById('result');
  resultDiv.innerHTML = "<span class='loading'>🔍 Анализирую текст страницы...</span>";

  // Получаем текст с текущей вкладки
  let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => document.body.innerText.substring(0, 1500)
  }, async (results) => {
    const text = results[0].result;

    if (!text || text.trim().length < 50) {
      resultDiv.innerText = "⚠️ На странице слишком мало текста для анализа.";
      return;
    }

    // Отправляем текст в background script для анализа
    chrome.runtime.sendMessage(
      { action: "analyzeText", text: text },
      (response) => {
        if (response.success) {
          const aiText = response.data.choices[0].message.content;
          try {
            const analysis = JSON.parse(aiText);

            let color = analysis.is_phishing ? "red" : "green";
            let icon = analysis.is_phishing ? "🚨" : "✅";

            resultDiv.innerHTML = `
              <strong style="color:${color}; font-size:16px;">${icon} Угроза: ${analysis.threat_level.toUpperCase()}</strong><br><br>
              <strong>Причины:</strong><br>• ${analysis.reasons.join('<br>• ')}<br><br>
              <strong>Рекомендация:</strong><br>${analysis.recommendation}
            `;
          } catch (e) {
            resultDiv.innerText = "️ ИИ вернул не JSON. Сырой ответ:\n" + aiText;
          }
        } else {
          resultDiv.innerText = "❌ Ошибка: " + response.error;
        }
      }
    );
  });
});