<?php
/**
 * security_filter.php
 *
 * This file should be included at the beginning of your PHP scripts.
 * It collects incoming data (GET, POST, REQUEST, COOKIE, and php://input),
 * scans for potential attack patterns (XSS, SQL injection, file inclusion,
 * command injection, etc.), logs any suspicious attempt into a SQLite database,
 * and terminates execution by displaying a centered closed lock emoji.
 */

// Define the path to the SQLite database (shared with the security log).
$db_file = __DIR__ . '/attack_log.sqlite';

try {
    $pdo = new PDO('sqlite:' . $db_file);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Create the whitelist table if not exists.
$pdo->exec("CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE
)");

// Function to check if IP is in the whitelist.
function is_whitelisted($pdo, $ip) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM whitelist WHERE ip = :ip");
    $stmt->execute([':ip' => $ip]);
    return $stmt->fetchColumn() > 0;
}

// Function to check if IP is in the blacklist.
function is_blacklisted($pdo, $ip) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM attacks WHERE ip = :ip");
    $stmt->execute([':ip' => $ip]);
    return $stmt->fetchColumn() > 0;
}

// Get the current visitor's IP.
$current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Check if the IP is whitelisted.
if (!is_whitelisted($pdo, $current_ip)) {
    // Check if the IP is blacklisted.
    if (is_blacklisted($pdo, $current_ip)) {
        block_execution();
    }
}

// Expanded regex patterns to detect potential attack vectors.
$attack_patterns = [
    // XSS-related patterns:
    '/<\s*script/iu',                         // opening <script> tag
    '/<\s*\/\s*script\s*>/iu',                  // closing </script> tag
    '/on\w+\s*=\s*["\']/iu',                    // inline event handlers (e.g. onclick, onerror)
    '/javascript\s*:/iu',                       // javascript: protocol
    '/vbscript\s*:/iu',                         // vbscript: protocol
    '/data\s*:[^,]+,.*?/iu',                     // data URI schemes
    '/expression\s*\(/iu',                      // CSS expression() syntax
    '/<\s*iframe/iu',                           // iframe tag usage
    '/<\s*img\s+.*\bonerror\s*=/iu',             // img tags with onerror attribute
    '/<\s*object/iu',                           // object tag usage

    // SQL injection patterns:
    '/\b(select|union|insert|update|delete|drop|alter|create|truncate|grant|execute|declare)\b/i',
    '/(\b(and|or)\b\s+\d+\s*=\s*\d+)/i',         // numeric boolean injection
    '/(\'|%27)\s*or\s*(\'|%27)/i',               // OR conditions using quotes
    '/(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i',        // additional numeric injection
    '/(\-\-|\#|\/\*)/i',                         // SQL comment markers (e.g. --, #, /*)
    '/;/',                                      // semicolon to chain SQL queries
    '/\b(select|insert|update|delete)\b.*\b(from|into)\b/i', // SQL clause patterns
    '/(?:\bunion\b\s*\bselect\b)/i',             // UNION SELECT patterns

    // File inclusion and directory traversal:
    '/\.\.\/+/i',                               // directory traversal attempts
    '/(\/|\\\)(etc|proc|sys)/i',                 // suspicious access to system directories
    '/(file|php):\/\/\//i',                      // misuse of file or php protocols

    // Remote Code Execution / Command Injection:
    '/\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(/i',
    '/\beval\s*\(/iu',
    '/\bassert\s*\(/iu',
    '/\binclude(?:_once)?\s*\(/iu',
    '/\brequire(?:_once)?\s*\(/iu',
    '/base64_decode\s*\(/iu',

    // General HTML tag detection (may flag benign HTML; use with caution):
    '/<[^>]+>/i'
];

/**
 * Recursively scan data for malicious patterns.
 *
 * @param mixed $data The input data to scan.
 * @return bool Returns true if any pattern is matched.
 */
function scan_data($data) {
    global $attack_patterns;
    if (is_array($data)) {
        foreach ($data as $value) {
            if (scan_data($value)) {
                return true;
            }
        }
    } else {
        // Cast non-string data to string.
        $dataStr = (string)$data;
        foreach ($attack_patterns as $pattern) {
            if (preg_match($pattern, $dataStr)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Log the attack attempt into a SQLite database.
 *
 * @param string $source The source of the input (e.g., GET, POST, php://input).
 * @param string $value The suspicious value detected.
 */
function log_attack($source, $value) {
    global $pdo;
    // Define the path to the SQLite database (adjust as needed)
    $db_file = __DIR__ . '/attack_log.sqlite';

    try {
        $pdo = new PDO('sqlite:' . $db_file);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Create the "attacks" table if it doesn't already exist.
        $pdo->exec("CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            source TEXT,
            value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )");

        // Prepare and execute the insert statement.
        $stmt = $pdo->prepare("INSERT INTO attacks (ip, source, value) VALUES (:ip, :source, :value)");
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $stmt->execute([
            ':ip'     => $ip,
            ':source' => $source,
            ':value'  => $value
        ]);
    } catch (PDOException $e) {
        // Log the error server-side. In production, consider more robust error handling.
        error_log("SQLite error: " . $e->getMessage());
    }
}

/**
 * Block execution by outputting a centered closed lock emoji and a message.
 */
function block_execution() {
    // Obfuscate the email address to prevent scraping.
    $email_part1 = "info";
    $email_part2 = "jocarsa";
    $email_part3 = "com";

    $html = '<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Access Denied</title>
    <style>
        body {
            margin: 0;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            background: #f8f8f8;
            font-family: Arial, sans-serif;
        }
        .lock-container {
            text-align: center;
        }
        .lock {
            font-size: 10rem;
            margin-bottom: 20px;
        }
        .message {
            font-size: 1.5rem;
            margin-bottom: 20px;
        }
        .contact {
            font-size: 1rem;
            color: #555;
        }
        .contact a {
            color: #007BFF;
            text-decoration: none;
        }
        .contact a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="lock-container">
        <div class="lock">🔒</div>
        <div class="message">Access Denied</div>
        <div class="contact">
            If you believe this is a mistake, please contact the administrator at
            <a href="#" onclick="this.href=\'mailto:\'+atob(\'aW5mb0Bqb2NhcnNhLmNvbQ==\')">
                <span id="email"></span>
            </a>.
        </div>
    </div>
    <script>
        // Assemble the email address using JavaScript to prevent scraping.
        var part1 = "'.$email_part1.'";
        var part2 = "'.$email_part2.'";
        var part3 = "'.$email_part3.'";
        document.getElementById("email").innerText = part1 + "@" + part2 + "." + part3;
    </script>
</body>
</html>';
    echo $html;
    exit;
}

// List of input sources to check.
$input_sources = [
    'GET'     => $_GET,
    'POST'    => $_POST,
    'REQUEST' => $_REQUEST,
    'COOKIE'  => $_COOKIE
];

// Scan each input source.
foreach ($input_sources as $source_name => $data) {
    if (scan_data($data)) {
        log_attack($source_name, print_r($data, true));
        block_execution();
    }
}

// Additionally, scan raw input from php://input.
$rawInput = file_get_contents("php://input");
if (!empty($rawInput) && scan_data($rawInput)) {
    log_attack('php://input', $rawInput);
    block_execution();
}
?>

