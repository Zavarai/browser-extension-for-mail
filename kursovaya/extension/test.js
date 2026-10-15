// ============ ТЕСТОВЫЙ ДАТАСЕТ (40 писем) ============
const DATASET = [
  // ---------- ФИШИНГ (20) ----------
  { id: 1,  label: 'phishing', text: 'Служба безопасности: ваш аккаунт будет заблокирован через 2 часа, срочно подтвердите пароль по ссылке http://sber-verify.ru' },
  { id: 2,  label: 'phishing', text: 'Госуслуги: за вами числится штраф, во избежание ареста счетов введите данные карты на http://gosuslugi-bonus.ru' },
  { id: 3,  label: 'phishing', text: 'Вы выиграли 1 000 000 рублей в лотерее от Яндекса! Заберите приз до полуночи на http://yandex-prize.ru' },
  { id: 4,  label: 'phishing', text: 'Сбербанк: карта заблокирована, для разблокировки введите CVV-код на http://sberbank-online-verify.xyz' },
  { id: 5,  label: 'phishing', text: 'Срочно! Ваш почтовый ящик будет удалён сегодня, подтвердите владение на http://yandex-verify.ru' },
  { id: 6,  label: 'phishing', text: 'Зарплатный проект: перевыпуск вашей карты, подтвердите данные на http://sberbankk.ru' },
  { id: 7,  label: 'phishing', text: 'Налоговая: вам положен возврат 15 000 руб, для получения введите номер карты на http://nalog-refund.info' },
  { id: 8,  label: 'phishing', text: 'Ozon: проблема с оплатой заказа, обновите данные карты по ссылке http://ozon-pay.online' },
  { id: 9,  label: 'phishing', text: 'Пароль истекает сегодня, установите новый на странице http://login-yandex.ru' },
  { id: 10, label: 'phishing', text: 'Коллега прислал вам документ, для открытия введите рабочий пароль на http://doc-scan.online' },
  { id: 11, label: 'phishing', text: 'Ваш аккаунт приостановлен. Для разблокировки отправьте код из СМС ответным письмом в течение часа' },
  { id: 12, label: 'phishing', text: 'Здравствуйте, это служба безопасности вашего банка. Продиктуйте номер карты и код с обратной стороны для проверки' },
  { id: 13, label: 'phishing', text: 'От руководства: срочно переведите деньги на резервный счёт, реквизиты в ответном письме, никому не сообщайте' },
  { id: 14, label: 'phishing', text: 'Техподдержка: на вашем компьютере обнаружен вирус, предоставьте удалённый доступ для срочного удаления' },
  { id: 15, label: 'phishing', text: 'Почта: посылка задержана, оплатите пошлину 300 руб по ссылке http://sber-verify.ru/pay' },
  { id: 16, label: 'phishing', text: 'Ваш пароль скомпрометирован в утечке, немедленно смените его по ссылке http://ya-security.ru' },
  { id: 17, label: 'phishing', text: 'Инстаграм: жалоба на ваш аккаунт, чтобы не потерять страницу войдите на http://instagrarn.com' },
  { id: 18, label: 'phishing', text: 'Судебное уведомление: неоплаченный счёт, оплатите в течение 24 часов на http://sber-verify.ru/court' },
  { id: 19, label: 'phishing', text: 'Подтвердите личность: пришлите фото паспорта и карты в ответном письме для восстановления доступа' },
  { id: 20, label: 'phishing', text: 'Казино Вулкан: ваш бонус 5000 рублей сгорает через час, активируйте на http://vulkan-win.top' },

  // ---------- ЛЕГИТИМНЫЕ (20) ----------
  { id: 21, label: 'legit', text: 'Яндекс Музыка — Новая Моя волна, Озвучит ваш момент, слушайте подборку недели' },
  { id: 22, label: 'legit', text: 'Свои Плюсы — Скидка 1200 ₽ на букет, Проверенный способ порадовать близких' },
  { id: 23, label: 'legit', text: 'Яндекс Пэй — Чек покупки, Спасибо за покупку в интернет-магазине' },
  { id: 24, label: 'legit', text: 'Кинопоиск — Хиты от Смотрим уже в вашей подписке, смотрите до конца месяца' },
  { id: 25, label: 'legit', text: 'Ozon: заказ доставлен, электронный чек доступен в личном кабинете https://ozon.ru/orders' },
  { id: 26, label: 'legit', text: 'Госуслуги: уведомление о готовности документа, войдите в личный кабинет https://gosuslugi.ru' },
  { id: 27, label: 'legit', text: 'Сбербанк: выписка по счёту за октябрь доступна в СберБанк Онлайн https://sberbank.ru' },
  { id: 28, label: 'legit', text: 'Wildberries: купон на 500 ₽ действует до воскресенья https://wildberries.ru' },
  { id: 29, label: 'legit', text: 'Команда Алисы и умных устройств — рассказываем о текущих обновлениях прошивки' },
  { id: 30, label: 'legit', text: 'Яндекс Плюс — Чек + (1) подарок, ссылка на ваш чек https://yandex.plus' },
  { id: 31, label: 'legit', text: 'Встреча перенесена на четверг, 15:00, повестка собрания во вложении' },
  { id: 32, label: 'legit', text: 'Рецензия научного руководителя на курсовую работу, замечания в приложенном файле' },
  { id: 33, label: 'legit', text: 'Квитанция на оплату электроэнергии за октябрь, просим оплатить до 10 числа' },
  { id: 34, label: 'legit', text: 'ВКонтакте: друг поделился с вами фотографией https://vk.com' },
  { id: 35, label: 'legit', text: 'М.Видео: гарантия 3 года на вашу покупку активирована автоматически' },
  { id: 36, label: 'legit', text: 'Аэрофлот: открыта онлайн-регистрация на рейс SU-1234 до Кировa' },
  { id: 37, label: 'legit', text: 'Яндекс Еда: заказ доставлен за 25 минут, спасибо, что выбрали нас' },
  { id: 38, label: 'legit', text: 'Библиотека: напоминаем, что срок сдачи книги истекает 30 ноября' },
  { id: 39, label: 'legit', text: 'GitHub: новый pull request в вашем репозитории курсового проекта https://github.com' },
  { id: 40, label: 'legit', text: 'Фитнес-клуб: ваша подписка активна до 31 декабря, приходите на тренировки' }
];

// Положительный класс = фишинг (уровни high/critical)
const POS_LEVELS = new Set(['high', 'critical']);
const sleep = ms => new Promise(r => setTimeout(r, ms));

function sendMessage(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, resolve);
  });
}

let lastResults = null;

document.getElementById('runBtn').addEventListener('click', runTests);
document.getElementById('copyBtn').addEventListener('click', () => {
  navigator.clipboard.writeText(JSON.stringify(lastResults, null, 2));
  alert('✅ Результаты скопированы в буфер обмена');
});

async function runTests() {
  const progress = document.getElementById('progress');
  const resultsDiv = document.getElementById('results');
  resultsDiv.innerHTML = '';
  document.getElementById('runBtn').disabled = true;

  let tp = 0, fp = 0, fn = 0, tn = 0;
  const rows = [];

  for (let i = 0; i < DATASET.length; i++) {
    const item = DATASET[i];
    progress.innerText = `⏳ Прогон: ${i + 1} / ${DATASET.length} — письмо №${item.id}`;

    const resp = await sendMessage({ action: 'analyzeEmail', subject: item.text, sender: '' });
    const level = resp && (resp.threatLevel || resp.threat_level) || 'low';
    const pred = POS_LEVELS.has(level) ? 'phishing' : 'legit';

    if (item.label === 'phishing' && pred === 'phishing') tp++;
    else if (item.label === 'legit'  && pred === 'phishing') fp++;
    else if (item.label === 'phishing' && pred === 'legit') fn++;
    else tn++;

    rows.push({
      id: item.id,
      text: item.text.substring(0, 70) + '…',
      label: item.label,
      pred: pred,
      level: level,
      reason: resp && resp.reason || '',
      correct: item.label === pred
    });

    await sleep(2000); // пауза между запросами к API
  }

  const accuracy  = (tp + tn) / rows.length;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1        = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;

  lastResults = { tp, fp, fn, tn, accuracy, precision, recall, f1, rows };

  const errors = rows.filter(r => !r.correct);
  resultsDiv.innerHTML = `
    <h2>📊 Метрики качества</h2>
    <div class="metrics">
      <div class="metric"><b>${(accuracy * 100).toFixed(1)}%</b>Accuracy<br>(общая точность)</div>
      <div class="metric"><b>${(precision * 100).toFixed(1)}%</b>Precision<br>(точность)</div>
      <div class="metric"><b>${(recall * 100).toFixed(1)}%</b>Recall<br>(полнота)</div>
      <div class="metric"><b>${(f1 * 100).toFixed(1)}%</b>F1-score</div>
    </div>
    <h2>Матрица ошибок (confusion matrix)</h2>
    <table class="cm" style="width:auto">
      <tr><th></th><th>Предсказано: фишинг</th><th>Предсказано: легитим</th></tr>
      <tr><th>Факт: фишинг</th><td class="ok">TP = ${tp}</td><td class="err">FN = ${fn}</td></tr>
      <tr><th>Факт: легитим</th><td class="err">FP = ${fp}</td><td class="ok">TN = ${tn}</td></tr>
    </table>
    <h2>❌ Ошибки классификации (${errors.length}) — материал для анализа</h2>
    ${errors.length ? `<table>
      <tr><th>№</th><th>Текст</th><th>Факт</th><th>Предсказание</th><th>Уровень</th><th>Причина</th></tr>
      ${errors.map(e => `<tr><td>${e.id}</td><td>${e.text}</td><td>${e.label}</td><td>${e.pred}</td><td>${e.level}</td><td>${e.reason}</td></tr>`).join('')}
    </table>` : '<p class="ok">Ошибок нет! 🎉</p>'}
    <h2>Полная таблица прогонов</h2>
    <table>
      <tr><th>№</th><th>Текст</th><th>Факт</th><th>Предсказание</th><th>Уровень</th><th>Верно?</th></tr>
      ${rows.map(r => `<tr><td>${r.id}</td><td>${r.text}</td><td>${r.label}</td><td>${r.pred}</td><td>${r.level}</td><td class="${r.correct ? 'ok' : 'err'}">${r.correct ? '✔' : '✘'}</td></tr>`).join('')}
    </table>
  `;

  progress.innerText = '✅ Тестирование завершено. Скопируйте результаты для пояснительной записки.';
  document.getElementById('copyBtn').disabled = false;
  document.getElementById('runBtn').disabled = false;
}