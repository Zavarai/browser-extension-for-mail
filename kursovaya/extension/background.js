chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeText") {
    analyzeWithGigaChat(request.text)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
  if (request.action === "analyzeEmail") {
    analyzeEmailSubject(request.subject, request.sender)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ threatLevel: 'low', threat_level: 'low', reason: 'Ошибка: ' + error.message }));
    return true;
  }
});

// ============ СЛОЙ 1: ЭВРИСТИЧЕСКИЙ АНАЛИЗАТОР ССЫЛОК ============

const WHITELIST_DOMAINS = [
  'yandex.ru', 'yandex.com', 'yandex.net', 'yandex.plus', 'ya.ru', 'yadi.sk',
  'kinopoisk.ru', 'sberbank.ru', 'sber.ru', 'sbermarket.ru', 'sbermegamarket.ru',
  'gosuslugi.ru', 'nalog.ru', 'ozon.ru', 'wildberries.ru',
  'aliexpress.com', 'aliexpress.ru', 'mail.ru', 'vk.com',
  'google.com', 'microsoft.com', 'apple.com'
];

const BLACKLIST_DOMAINS = [
  'sber-verify.ru', 'sberbank-security.ru', 'gosuslugi-bonus.ru',
  'yandex-prize.ru', 'sberbank-online-verify.xyz', 'mail-yandex-security.com'
];

function extractUrls(text) {
  const regex = /(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+|[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\.(?:ru|com|net|org|xyz|top|info|online|club)[^\s<>"']*)/gi;
  return text.match(regex) || [];
}

function getDomain(url) {
  try {
    let u = url;
    if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
    return new URL(u).hostname.toLowerCase().replace(/^www\./, '');
  } catch (e) {
    return '';
  }
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  return dp[m][n];
}

function isTrustedDomain(domain) {
  return WHITELIST_DOMAINS.some(w => domain === w || domain.endsWith('.' + w));
}

function checkBrandImpersonation(domain) {
  for (const brand of WHITELIST_DOMAINS) {
    if (domain === brand || domain.endsWith('.' + brand)) continue;
    const brandCore = brand.split('.')[0];
    if (domain.includes(brandCore)) {
      return { type: 'brand_impersonation', brand };
    }
    const d = levenshtein(domain, brand);
    if (d > 0 && d <= 3) {
      return { type: 'typosquatting', brand, distance: d };
    }
  }
  return null;
}

function analyzeLinks(text) {
  const urls = extractUrls(text);
  const findings = [];
  for (const url of urls) {
    const domain = getDomain(url);
    if (!domain) continue;
    if (BLACKLIST_DOMAINS.includes(domain)) {
      findings.push({ url, domain, verdict: 'blacklist', score: 1.0, comment: 'Домен в базе фишинговых сайтов' });
      continue;
    }
    if (isTrustedDomain(domain)) {
      findings.push({ url, domain, verdict: 'trusted', score: 0.0, comment: 'Домен из белого списка' });
      continue;
    }
    const impersonation = checkBrandImpersonation(domain);
    if (impersonation) {
      const dist = impersonation.distance ? ` (Левенштейн: ${impersonation.distance})` : '';
      findings.push({ url, domain, verdict: impersonation.type, score: 0.8, comment: `Имитирует бренд ${impersonation.brand}${dist}` });
      continue;
    }
    if (/\.(xyz|top|club|loan|work|online)$/i.test(domain)) {
      findings.push({ url, domain, verdict: 'suspicious_tld', score: 0.5, comment: 'Подозрительная доменная зона' });
    } else {
      findings.push({ url, domain, verdict: 'unknown', score: 0.2, comment: 'Неизвестный домен' });
    }
  }
  return findings;
}

function linkLevelFromFindings(findings) {
  if (findings.some(f => f.verdict === 'blacklist')) return 'critical';
  if (findings.some(f => f.verdict === 'brand_impersonation' || f.verdict === 'typosquatting')) return 'high';
  if (findings.some(f => f.verdict === 'suspicious_tld')) return 'medium';
  return 'low';
}

// ============ СЛОЙ 2: ДЕТЕКТОР СОЦИАЛЬНОЙ ИНЖЕНЕРИИ ============

const SE_RULES = [
  { re: /код из смс|смс-код|код из сообщения|пришли.*код|отправьте.*код/i, level: 'high', tag: 'запрос кода из СМС' },
  { re: /cvv|cvc|код с обратной стороны|три цифры на обратной/i, level: 'critical', tag: 'запрос CVV/CVC карты' },
  { re: /фото паспорта|скан паспорта|фотографию паспорта|селфи с картой/i, level: 'critical', tag: 'запрос фото документов' },
  { re: /удалённ(ый|ого|ому) доступ(а|у)|anydesk|teamviewer|rustdesk/i, level: 'high', tag: 'запрос удалённого доступа' },
  { re: /резервн(ый|ого|ому) счёт|безопасн(ый|ого|ому) счёт|защищённ(ый|ого|ому) счёт/i, level: 'critical', tag: 'перевод на «безопасный» счёт' },
  { re: /продиктуйте|сообщите.*(номер карты|пароль|код)|назовите.*код/i, level: 'critical', tag: 'запрос секретных данных' },
  { re: /введите.*(пароль|password)|пароль.*(введите|укажите)/i, level: 'high', tag: 'требование ввести пароль' },
  { re: /жалоба.*(аккаунт|страниц)|(аккаунт|страниц).*(удал|потеря).*войд/i, level: 'high', tag: 'угроза потери аккаунта' },
  { re: /вирус.*(обнаружен|найден).*(удал|предостав|позвон)/i, level: 'high', tag: 'запугивание вирусом' },
  { re: /срочно перевед|срочн(ый|о|ое) перевод|переведите деньги/i, level: 'high', tag: 'требование срочного перевода' },
  { re: /казино|бонус.*сгорает|выиграли.*активируйте/i, level: 'high', tag: 'казино / призовой обман' }
];

function detectSocialEngineering(text) {
  const order = ['low', 'medium', 'high', 'critical'];
  let level = 'low';
  const hits = [];
  for (const rule of SE_RULES) {
    if (rule.re.test(text)) {
      hits.push(rule.tag);
      if (order.indexOf(rule.level) > order.indexOf(level)) level = rule.level;
    }
  }
  return { level, hits };
}

// ============ ГЛАВНАЯ ФУНКЦИЯ АНАЛИЗА ПИСЬМА (3 СЛОЯ) ============

async function analyzeEmailSubject(subject, sender) {
  const ACCESS_TOKEN = "eyJjdHkiOiJqd3QiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.N24E5bSHWBFyANfGj3e6E8gMt0pJVhKdKSgweWvLaQvWnw6Rw60ft6YuKY7z_axnfHVTqWvCXQbF72ak7e_XPzj_pAFMhe1N1Uu2zz8mpdWiv4LrYf0vT6N8WC_wkVMdQ_zAK9ujbGsyexv07s4QcbQMjNAuqFy4dtHipHu6m_aRwKn96jEwE3oQUqeysg496jZgTqhiIDPNV_9-mAwfVoHGXh4QAO6l_6fMwUpaWEQRRZEDnpVt2oI1_8SLDLV2tSZ6tiaT97yYfeEYUfXkxMAU7kMkpTI1aHXSfhYX2KXIR0WC1uNju8XbtJGnEplJW4IuEe6og3Z14XTtI3uXnA.JKuj7wbCc56PtLZz78NzdA.4RjvHHPjmvd2xqbD7AHP6txasKBJyfhxtRYPAXAqVDYbnUUzyFfyX04koi0mG7dBHyfrvZazE2AdCbh747D7u_nJdE5jK713FQiJW3qIlrjmNMt36lG3jhOF3ziTmY3hL91iHvgftk2whZle9J2rKwrUc51Hyd_AgoPKwHWWbWGCBoQm2KlLZeWX9amZ4HvkeE72HEMTp2F7ekx9sOT1JTxjOtRYWo48v1SH7wsfzY36vdKgf2Ig_gBHhqZc9jGPMllJncckPVZpN2ToZ0TcaVpogPJvEJO7OJU1S8y5p2Bx0uBx21Nah5_DmJmqunmOYvM-jSRmu40Q0yWmqhDSvzhjKXz72nXBs8y8BuHk0kql1ygspP2GI_qEZwILQoQhDWBUrw9Fp_lEMYkPDOv7KkQCg7szPhSV-eXf2xmAdNwy2YpqpzbFIsq7GA7pIO9w7UkLn9N6XEUWdVIr_feXq2thicxJ3rZjwCzYqnb9Q-AeZhs8ZxVD-yRRjsc_HmOsLTzuPk3YlewGd4SCllDePyc1GiNttjRTCNZlGt_Jk-TXyBrl11QwN59Q2hr0ieVCy1WR7-oxdHzqfqF3im1b6qX7SEHmM1gneL3O2cWeAgvasJ0ktjVKN2hicz7JAma-kncG_ssW9koMaOAl6U6e95r4HOF_aQHazUkUZ0wHxf427VsMn7H5GOSPdx8C7tE_2zyKOlrl0H-2Ms61ju1F3aGPVJ344_ccDDWtEUb9C6g.b4IlpYDVWFksNNMu68AAQf9K2X70pJzJsPjCe4vBeH4";

  // СЛОЙ 1: эвристика ссылок (без ИИ)
  const linkFindings = analyzeLinks(subject);
  const linkLevel = linkLevelFromFindings(linkFindings);

  // СЛОЙ 2: детектор социальной инженерии (без ИИ)
  const se = detectSocialEngineering(subject);

  // СЛОЙ 3: ИИ-анализ текста (с fail-safe)
  let aiLevel = 'low';
  let aiReason = '';
  try {
    const prompt = `Ты эксперт по кибербезопасности. Отличай ФИШИНГ (мошенничество) от обычной рекламы и сервисных писем.

Строка письма: "${subject}"

Ответь СТРОГО JSON без лишнего текста:
{"threat_level": "low" | "medium" | "high" | "critical", "reason": "одно предложение"}

ОБЯЗАТЕЛЬНЫЕ ПРАВИЛА:
1. low — реклама, скидки, акции, кешбэк, баллы, подборки, новости сервисов (Яндекс, Кинопоиск, Сбер, Ozon); чеки и подтверждения покупок; уведомления о доставке. Слова "срочно", "успей", "скидка" — МАРКЕТИНГ, уровень всё равно low.
2. medium — отправитель НЕИЗВЕСТЕН, заманивает выгодой ("вы выиграли", "вам положена выплата"), но без угроз и запроса данных.
3. high — неизвестный отправитель требует СРОЧНО "подтвердить", "восстановить", "разблокировать" аккаунт по ссылке, угрожает блокировкой.
4. critical — запрос пароля, кодов СМС, CVV/данных карты, угрозы штрафами или судом от имени банка, полиции, госорганов.

Ответ:`;

    const response = await fetch("https://gigachat.devices.sberbank.ru/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${ACCESS_TOKEN}`,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        model: "GigaChat:latest",
        messages: [
          { role: "system", content: "Ты эксперт по кибербезопасности. Отвечай только валидным JSON." },
          { role: "user", content: prompt }
        ],
        temperature: 0.1,
        max_tokens: 200
      })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const aiText = data.choices[0].message.content;
    console.log("🤖 Сырой ответ ИИ:", aiText);

    const parsed = JSON.parse(aiText);
    const lvl = String(parsed.threat_level || parsed.threatLevel || 'low').toLowerCase();
    if (['low', 'medium', 'high', 'critical'].includes(lvl)) aiLevel = lvl;
    aiReason = parsed.reason || '';
  } catch (e) {
    // FAIL-SAFE: ИИ недоступен → НЕ говорим «безопасно»
    console.error("❌ Ошибка ИИ-анализа:", e);
    aiLevel = 'medium';
    aiReason = 'ИИ недоступен — проверьте письмо вручную';
  }

  // Страховка для чеков: только если ВСЕ слои спокойны
  const isReceipt = /чек|квитанц|подтверждени(е|я) (оплаты|покупки|заказа)|заказ (доставлен|передан|оформлен)|спасибо за покупку/i.test(subject);
  if (isReceipt && linkLevel === 'low' && se.level === 'low') {
    aiLevel = 'low';
    aiReason = 'Чек или служебное уведомление, ссылки ведут на известные домены';
  }

  // ГИБРИДНОЕ ОБЪЕДИНЕНИЕ ТРЁХ СЛОЁВ: берём максимум
  const order = ['low', 'medium', 'high', 'critical'];
  const finalLevel = order[Math.max(order.indexOf(aiLevel), order.indexOf(linkLevel), order.indexOf(se.level))];

  const reasons = [aiReason];
  linkFindings.filter(f => f.score >= 0.5).forEach(f => reasons.push(`${f.comment}: ${f.domain}`));
  se.hits.forEach(h => reasons.push(`Социальная инженерия: ${h}`));

  console.log(`🔗 Ссылки: ${linkFindings.length}, эвристика: ${linkLevel}, SE: ${se.level}, ИИ: ${aiLevel} → итог: ${finalLevel}`);

  return {
    threatLevel: finalLevel,
    threat_level: finalLevel,
    reason: reasons.filter(Boolean).join(' | '),
    linkFindings: linkFindings
  };
}

// ============ АНАЛИЗ ПРОИЗВОЛЬНОГО ТЕКСТА (для popup) ============

async function analyzeWithGigaChat(text) {
  const ACCESS_TOKEN = "eyJjdHkiOiJqd3QiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.OIfjSnSdStvsu_JrDJRXLruh5nnmCQMvkQWUyejzl97Qt1AnytB31FOdXGakLH2M28UcMUX_qn02rxe0qI8Txj6eHGnV26rafSJM8zWypsQ-SNJXfGwETD9d5Mz10oGErdUDD1y4BJLN-0xpgVwkrwlcu6LAAbfXWayCjoU_jMdwubnATDVU9sZs3oOmbTduelCQvOVaoocV8cTY-TyRfl-1o2vBCv4g64qZjydodG8RZ0cDzph1nBU1Hvg522Fh0JhjHKUvb3H368yOYUGOKAlJx3FMiJ8v398eNV6n6oCWsDhjl41Dg3sOdFO6FCL6KdPqU3r__H99U5EXXnOggQ.2OsQd6qNXD9dW1iixH7WOQ._Az8a_aMWbSgT7vmL2K_X7EdMqsJ9korCm0x2EMGcJYlazDqUzn-B3fSJ-S3jHislzBBCoARedvEYG3Lpunvd_ZOPCCxRhVt2UYCuMMfjGo18ycauDWFVahNh0RPL1DJ6Xmwp6Z0bwSEGZJRInAjWBZw_FDfoxZyJo-WPltmYAYu-lecpNdBrkGSZ50EB2xMAfxhA58ZfxWrJ5lpElLIl48UFc083ovBWWvWiXiUOm8BkP2mNpL4wjPXJZ2dXsJdDRUZ6d0EvmtfZZEgt__Tm5z_kyuMkPk2sGxrXJX3fbG8SIGLlRPG8N1QImFJ4FWRXJ5g1VTkN3hr-s5G6rSpviaRJfuRkmLr01gT2FmJ5JBGRWxIxfXFFmeO9jSFKHmwfYWG8yweerve1mjEcfiMAiw_lUX5QWG4fHGATB1P-Ea32X5dupMIB4sS8VjBw_-PS8He6Hv9I5vhnR86-ULWw7aM5emVI_rKsMmPqq7INFGHGJHOz7RRx0iLuigzVoPhMhMAm6HIc5V6Re8fxIL_PjTocH8-rbXmSzSpfHl6MJb-wxPcAVrzUjFywCEuWhZF3sx2gcNufO-yCAwJagVtdRW4N8J6qJQy3CFxypAyVLCBiWH4jWcLm6CYo09rT5IsoZ8HcXPpg96jZZPAfkpjT1DxNA-EU43gCcbSSCLbHrr1K6c7o0lBAFt7XlYz8z_MCQu0CfEUmpSp1P1wR-FkjoKe7xPr4RlwBYWxjGGM33s.pHY64NkLIImGg-JpEkVMZPmjLTX6nkjBeSHi6L8XlvM";

  const prompt = `Проанализируй текст на признаки фишинга.

Ответь СТРОГО в формате JSON:
{
  "is_phishing": true или false,
  "threat_level": "низкий" | "средний" | "высокий" | "критический",
  "reasons": ["причина 1", "причина 2"],
  "suspicious_elements": ["элемент 1"],
  "recommendation": "рекомендация"
}

Текст:
${text.substring(0, 1500)}`;

  const response = await fetch("https://gigachat.devices.sberbank.ru/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${ACCESS_TOKEN}`,
      "Content-Type": "application/json",
      "Accept": "application/json"
    },
    body: JSON.stringify({
      model: "GigaChat:latest",
      messages: [
        { role: "system", content: "Ты эксперт по кибербезопасности. Отвечай только валидным JSON." },
        { role: "user", content: prompt }
      ],
      temperature: 0.1,
      max_tokens: 1000
    })
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }

  return await response.json();
}