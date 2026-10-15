// content.js — v4: исправлены дубли индикаторов и ложные срабатывания
console.log("🛡️ Фишинг-детектор: content script загружен");

const MARK = 'data-phishing-checked';
let isAnalyzing = false;
let observerTimeout = null;

// ГИБРИДНЫЙ ПОДХОД: известные сервисы проверяем правилами, без ИИ
const KNOWN_BRANDS = [
  'яндекс музыка', 'кинопоиск', 'свои плюсы', 'яндекс пэй', 'яндекс плюс',
  'яндекс сплит', 'команда алисы', 'алиса про', 'ozon', 'wildberries', 'госуслуги'
];
const RECEIPT_WORDS = ['чек покупки', 'чек об оплате', 'подтверждение оплаты', 'заказ доставлен', 'заказ передан', 'спасибо за покупку'];

function localPreCheck(text) {
  const lower = text.toLowerCase();
  const hasUrl = /https?:\/\/|www\./.test(lower);
  if (hasUrl) return null; // есть ссылка — пусть решает ИИ
  if (RECEIPT_WORDS.some(w => lower.includes(w))) {
    return { threatLevel: 'low', reason: 'Чек/уведомление о покупке — не фишинг' };
  }
  if (KNOWN_BRANDS.some(b => lower.includes(b))) {
    return { threatLevel: 'low', reason: 'Известный сервис, маркетинговая рассылка' };
  }
  return null;
}

function findEmailListContainer() {
  const allDivs = document.querySelectorAll('div');
  for (const div of allDivs) {
    const rect = div.getBoundingClientRect();
    const className = div.className || '';
    const text = div.textContent || '';
    if (className.includes('Folder') || className.includes('Left') ||
        className.includes('Sidebar') || className.includes('Nav') ||
        className.includes('Menu')) continue;
    const hasDates = /\d{1,2}\s*(окт|сен|авг|июл|июн|мая|апр|мар|фев|янв|дек|ноя)|сегодня|вчера|\d{1,2}:\d{2}/.test(text);
    const childCount = div.children.length;
    if (rect.left > 250 && rect.width > 500 && rect.height > 300 &&
        hasDates && childCount > 5 && childCount < 100) {
      console.log(`📦 Найден контейнер: ширина=${rect.width}, писем=${childCount}`);
      return div;
    }
  }
  return null;
}

function findEmailRows(container) {
  const candidates = [];
  container.querySelectorAll('div').forEach(div => {
    // пропускаем уже проверенные и всё, что ВНУТРИ проверенных
    if (div.closest(`[${MARK}]`)) return;
    const text = div.textContent.trim();
    const rect = div.getBoundingClientRect();
    // ИСПРАВЛЕНО: убрана голая буква "ч" — теперь только реальные даты
    const hasDate = /\d{1,2}\s*(окт|сен|авг|июл|июн|мая|апр|мар|фев|янв|дек|ноя)|сегодня|вчера|\d{1,2}:\d{2}/.test(text);
    if (text.length > 50 && text.length < 400 && hasDate &&
        div.children.length >= 2 && div.children.length <= 8 && rect.width > 400) {
      candidates.push(div);
    }
  });
  // Убираем вложенные дубли: оставляем только ВНЕШНЮЮ строку письма
  const rows = candidates.filter(row => !candidates.some(o => o !== row && o.contains(row)));
  console.log(`🔍 Найдено строк с письмами: ${rows.length}`);
  return rows;
}

function addIndicator(row, threatLevel, reason) {
  if (row.querySelector('.phishing-indicator')) return; // защита от дубля
  const indicator = document.createElement('div');
  indicator.className = 'phishing-indicator';
  indicator.title = reason || '';
  let circleColor, emoji;
  if (threatLevel === 'critical')      { circleColor = '#ff0000'; emoji = '🚨'; }
  else if (threatLevel === 'high')     { circleColor = '#ff4444'; emoji = '⚠️'; }
  else if (threatLevel === 'medium')   { circleColor = '#ffaa00'; emoji = ''; }
  else                                 { circleColor = '#44cc44'; emoji = '✅'; }
  indicator.innerHTML = `<div style="width:20px;height:20px;border-radius:50%;background-color:${circleColor};border:2px solid white;box-shadow:0 2px 4px rgba(0,0,0,0.3);display:flex;align-items:center;justify-content:center;font-size:12px;">${emoji}</div>`;
  indicator.style.cssText = `position:absolute;right:8px;top:50%;transform:translateY(-50%);background:white;padding:4px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,0.2);z-index:99999;cursor:help;display:flex;align-items:center;justify-content:center;`;
  row.style.position = 'relative';
  row.appendChild(indicator);
  console.log(`✅ Индикатор: ${threatLevel} — ${reason}`);
}

async function analyzePage() {
  if (isAnalyzing) return;
  isAnalyzing = true;
  try {
    const container = findEmailListContainer();
    if (!container) { console.log("⚠️ Контейнер не найден"); return; }
    const rows = findEmailRows(container);
    if (rows.length === 0) { console.log("ℹ️ Новых писем нет"); return; }
    console.log(`▶️ Анализирую ${rows.length} писем...`);
    for (const row of rows) {
      row.setAttribute(MARK, 'pending'); // помечаем СРАЗУ, а не после ответа
      const text = row.textContent.trim();
      const local = localPreCheck(text);
      if (local) { addIndicator(row, local.threatLevel, local.reason); continue; }
      chrome.runtime.sendMessage({ action: "analyzeEmail", subject: text, sender: "" }, (response) => {
        const level = response && (response.threatLevel || response.threat_level);
        if (level) {
          addIndicator(row, level, response.reason || '');
          row.setAttribute(MARK, level);
        } else {
          row.setAttribute(MARK, 'error');
          console.warn("❌ Нет уровня угрозы в ответе:", response);
        }
      });
      await new Promise(r => setTimeout(r, 700));
    }
    console.log("✅ Анализ завершён!");
  } finally {
    isAnalyzing = false;
  }
}

setTimeout(() => { console.log("▶️ Первый анализ страницы..."); analyzePage(); }, 3000);

const observer = new MutationObserver(mutations => {
  let hasNew = false;
  outer: for (const m of mutations) {
    for (const node of m.addedNodes) {
      if (node.nodeType !== 1) continue;
      if (node.classList.contains('phishing-indicator')) continue; // наше же дополнение
      if (node.closest(`[${MARK}]`)) continue;
      const t = node.textContent || '';
      if (t.length > 50 && /\d{1,2}\s*(окт|сен|авг|июл|июн|мая|апр|мар|фев|янв)|сегодня|вчера|\d{1,2}:\d{2}/.test(t)) {
        hasNew = true; break outer;
      }
    }
  }
  if (hasNew && !isAnalyzing) {
    clearTimeout(observerTimeout);
    observerTimeout = setTimeout(analyzePage, 2000);
  }
});

setTimeout(() => {
  observer.observe(document.body, { childList: true, subtree: true });
  console.log("✅ Observer запущен");
}, 5000);