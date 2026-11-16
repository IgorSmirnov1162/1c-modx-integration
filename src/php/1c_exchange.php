<?php
// 1c_exchange.php — CommerceML type=sale: отдача заказов miniShop2 в 1С
// Отдаём: невыгруженные заказы (в любом статусе) + все заказы в статусе «отправлен».
// Повторная отдача «отправленных» безопасна: 1С не создаёт дубли —
// наличие реализации проверяется в регистре инт_СвязьЗаказов.

define('MODX_API_MODE', true);
require dirname(__FILE__) . '/index.php';
$modx->getService('error', 'error.modError');

$cfg = require MODX_CORE_PATH . 'components/onec/config.php';

/* ---------- Безопасность ---------- */

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
if (!$isHttps) {
    die('failure Обмен разрешён только по HTTPS');
}

// примитивный rate-limit по IP
$lockFile = MODX_CORE_PATH . 'components/onec/rl_' . md5($_SERVER['REMOTE_ADDR']) . '.txt';
$now = time();
$hits = [];
if (is_file($lockFile) && is_readable($lockFile)) {
    $hits = array_filter(array_map('intval', file($lockFile, FILE_IGNORE_NEW_LINES)),
        function ($t) use ($now) { return $t > $now - 60; });
}
$hits[] = $now;
if (count($hits) > $cfg['rate_limit']) {
    die('failure Слишком много запросов');
}
file_put_contents($lockFile, implode("\n", $hits));

// Basic Auth
$login = $_SERVER['PHP_AUTH_USER'] ?? '';
$pass  = $_SERVER['PHP_AUTH_PW']  ?? '';
if ($login !== $cfg['login'] || !password_verify($pass, $cfg['password_hash'])) {
    header('WWW-Authenticate: Basic realm="1C exchange"');
    header('HTTP/1.1 401 Unauthorized');
    exchangeLog($modx, 'AUTH_FAIL', 'ip=' . $_SERVER['REMOTE_ADDR']);
    die('failure Неверный логин или пароль');
}

/* ---------- Протокол ---------- */

$type = $_GET['type'] ?? '';
$mode = $_GET['mode'] ?? '';

if ($type !== 'sale') {
    die('failure Поддерживается только type=sale');
}

session_name($cfg['session_name']);
session_start();

switch ($mode) {
    case 'checkauth':
        // чистый сеанс обмена: сбрасываем предыдущий
        session_regenerate_id(true);
        $_SESSION['onec_auth'] = true;
        $_SESSION['onec_orders'] = [];
        echo "success\n" . session_name() . "\n" . session_id();
        break;

    case 'init':
        if (empty($_SESSION['onec_auth'])) { die('failure Нет активной сессии'); }
        echo "zip=no\nfile_limit=52428800";
        break;

    case 'query':
        if (empty($_SESSION['onec_auth'])) { die('failure Нет активной сессии'); }
        header('Content-Type: application/xml; charset=utf-8');
        echo buildOrdersXml($modx, $cfg);
        break;

    case 'success':
        if (empty($_SESSION['onec_auth'])) { die('failure Нет активной сессии'); }
        $done = markExported($modx);
        exchangeLog($modx, 'SUCCESS', 'помечено заказов: ' . $done);
        echo 'success';
        break;

    default:
        die('failure Неизвестный mode');
}

/* ---------- Функции ---------- */

function exchangeLog(modX $modx, $event, $detail = '') {
    // лог только в core/, без персональных данных
    $line = date('Y-m-d H:i:s') . "\t" . $event . "\t" . $detail . "\n";
    file_put_contents(MODX_CORE_PATH . 'components/onec/exchange.log', $line, FILE_APPEND | LOCK_EX);
}

function buildOrdersXml(modX $modx, array $cfg) {
    // Заказы без флага выгрузки ИЛИ все заказы в статусе «отправлен»
    $sentId = (int)($cfg['status_sent_id'] ?? 0);

    $q = $modx->newQuery('msOrder');
    if ($sentId > 0) {
        $q->where("(COALESCE(properties,'') NOT LIKE '%onec_exported%' OR status = {$sentId})");
    } else {
        // fallback: если ID не задан — отдаём только невыгруженные
        $q->where("COALESCE(properties,'') NOT LIKE '%onec_exported%'");
    }
    $q->sortby('id', 'DESC'); // свежие первыми, чтобы лимит не «съедал» новые заказы
    $q->limit(200);            // увеличенный лимит для покрытия обоих условий
    $orders = $modx->getIterator('msOrder', $q);

    $ids = [];
    foreach ($orders as $order) {
        $ids[] = (int)$order->get('id');
    }

    $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
    $xml .= '<КоммерческаяИнформация ВерсияСхемы="2.05"'
          . ' ДатаФормирования="' . date('Y-m-d') . 'T' . date('H:i:s') . '">' . "\n";

    foreach ($ids as $id) {
        /** @var msOrder $order */
        $order = $modx->getObject('msOrder', $id);
        if (!$order) continue;

        $address = $modx->getObject('msOrderAddress', ['order_id' => $order->get('id')]);
        $status = $modx->getObject('msOrderStatus', ['id' => $order->get('status')]);

        $receiver = $address ? $address->get('receiver') : 'Покупатель ' . $order->get('id');
        $email    = $address ? (string)$address->get('email') : '';
        $phone    = $address ? (string)$address->get('phone') : '';
        $created  = $order->get('createdon'); // 'Y-m-d H:i:s'
        $date     = substr($created, 0, 10);
        $time     = substr($created, 11, 8);

        $xml .= '<Документ>' . "\n";
        $xml .= tag('Ид', $order->get('id'));
        $xml .= tag('Номер', $order->get('num'));
        $xml .= tag('Дата', $date);
        $xml .= tag('Время', $time);
        $xml .= tag('Валюта', 'RUB');
        $xml .= tag('СтатусЗаказа', $status ? $status->get('name') : 'Новый');

        $xml .= '<Контрагенты>' . "\n";
        $xml .= '<Контрагент>' . "\n";
        $xml .= tag('Ид', 'user_' . $order->get('user_id'));
        $xml .= tag('Наименование', $receiver);
        if ($email !== '') { $xml .= tag('Email', $email); }
        if ($phone !== '') { $xml .= tag('Телефон', $phone); }
        $xml .= '</Контрагент>' . "\n";
        $xml .= '</Контрагенты>' . "\n";

        $xml .= '<Товары>' . "\n";
        // позиция заказа + артикул товара из msProductData
        $pq = $modx->newQuery('msOrderProduct');
        $pq->where(['order_id' => $order->get('id')]);
        $pq->leftJoin('msProductData', 'Data', 'Data.id = msOrderProduct.product_id');
        $pq->select('msOrderProduct.*, Data.article AS article');
        $pq->prepare();
        $pq->stmt->execute();
        $rows = $pq->stmt->fetchAll(PDO::FETCH_ASSOC);

        foreach ($rows as $row) {
            $xml .= '<Товар>' . "\n";
            $xml .= tag('Ид', 'prod_' . $row['product_id']);
            $xml .= tag('Артикул', $row['article']);
            $xml .= tag('Наименование', $row['name']);
            $xml .= tag('БазоваяЕдиница', 'шт');
            $xml .= tag('ЦенаЗаЕдиницу', number_format((float)$row['price'], 2, '.', ''));
            $xml .= tag('Количество', number_format((float)$row['count'], 2, '.', ''));
            $xml .= tag('Сумма', number_format((float)$row['cost'], 2, '.', ''));
            $xml .= '</Товар>' . "\n";
        }
        $xml .= '</Товары>' . "\n";
        $xml .= '</Документ>' . "\n";
    }

    $xml .= '</КоммерческаяИнформация>';

    $_SESSION['onec_orders'] = $ids; // запоминаем для mode=success
    exchangeLog($modx, 'QUERY', 'отдано заказов: ' . count($ids));

    return $xml;
}

function tag($name, $value) {
    return '<' . $name . '>' . htmlspecialchars((string)$value, ENT_XML1, 'UTF-8')
         . '</' . $name . '>' . "\n";
}

function markExported(modX $modx) {
    $done = 0;
    foreach ($_SESSION['onec_orders'] ?? [] as $id) {
        /** @var msOrder $order */
        $order = $modx->getObject('msOrder', (int)$id);
        if (!$order) { continue; }
        $props = json_decode($order->get('properties'), true) ?: [];
        $props['onec_exported'] = true;   // поле properties у msOrder хранит JSON
        $order->set('properties', json_encode($props, JSON_UNESCAPED_UNICODE));
        $order->save();
        $done++;
    }
    $_SESSION['onec_orders'] = [];
    return $done;
}
