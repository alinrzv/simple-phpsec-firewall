<?php
// Configuration
$log_file = '/www/sec_firewall/security_log.txt'; // Configure your log path
$enable_logging = true; // Set to false to disable logging
$is_wordpress = true;

if($is_wordpress){
if (!empty($_SERVER['SCRIPT_FILENAME']) && preg_match('#/wp-content/uploads/.+\.php$#i', $_SERVER['SCRIPT_FILENAME'])) {
    // Log the attempt (optional)
    if ($enable_logging) {
        $log_message = date('Y-m-d H:i:s') . " - BLOCKED PHP EXECUTION: " . $_SERVER['SCRIPT_FILENAME'] . " - IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
        @file_put_contents($log_file, $log_message, FILE_APPEND | LOCK_EX);
    }

    // Block execution
    header("HTTP/1.1 403 Forbidden");
    exit;
}
}

// Function to Detect Hidden PHP Files
function is_php_file($file_path) {
    if (!file_exists($file_path)) {
        return false;
    }

    // Read the first 8 bytes (UTF-8 BOM is 3 bytes + `<?php` is 5 bytes)
    $handle = fopen($file_path, 'rb');
    if ($handle === false) {
        return false;
    }

    $first_bytes = fread($handle, 8); // Read first 8 bytes
    fclose($handle);

    // UTF-8 BOM check (first 3 bytes: \xEF\xBB\xBF)
    if (substr($first_bytes, 0, 3) === "\xEF\xBB\xBF") {
        $first_bytes = substr($first_bytes, 3); // Remove BOM
    }

    // Detect `<?php`
    return strpos($first_bytes, '<?php') === 0;
}

// Intercept File Uploads (BEFORE other security checks)
if (!empty($_FILES)) {
    foreach ($_FILES as $file) {
        if ($file['error'] === UPLOAD_ERR_OK) {
            $filename = strtolower($file['name']);
            $temp_path = $file['tmp_name'];

            // Get file MIME type
            $mime_type = mime_content_type($temp_path);

            // Block PHP files (by content, not extension)
            if (is_php_file($temp_path) || preg_match('/(application\/x-httpd-php|text\/x-php|application\/octet-stream)/i', $mime_type) || preg_match('/(php|phtml|phar)/i', $filename)) {

                // Log the attempt
                if ($enable_logging) {
                    $log_message = date('Y-m-d H:i:s') . " - BLOCKED UPLOAD: $filename - MIME: $mime_type - IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
                    @file_put_contents($log_file, $log_message, FILE_APPEND | LOCK_EX);
                }

                // Block the upload
                header("HTTP/1.1 403 Forbidden");
                #echo "File type not allowed.";
                exit;
            }
        }
    }
}

// Detect PHP Code in Raw POST Data
function detect_php_in_raw_post() {
    $handle = fopen('php://input', 'rb');
    if ($handle === false) {
        return false;
    }

    $first_bytes = fread($handle, 8); // Read first 8 bytes
    fclose($handle);

    // UTF-8 BOM check
    if (substr($first_bytes, 0, 3) === "\xEF\xBB\xBF") {
        $first_bytes = substr($first_bytes, 3); // Remove BOM
    }

    // Detect `<?php`
    return strpos($first_bytes, '<?php') === 0;
}

// Intercept Raw POST Data Uploads
if ($_SERVER['REQUEST_METHOD'] === 'POST' && detect_php_in_raw_post()) {

    // Log the attack
    if ($enable_logging) {
        $log_message = date('Y-m-d H:i:s') . " - BLOCKED RAW PHP UPLOAD - IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
        @file_put_contents($log_file, $log_message, FILE_APPEND | LOCK_EX);
    }

    // Block the request
    header("HTTP/1.1 403 Forbidden");
    #echo "Raw PHP data upload blocked.";
    exit;
}

// Optimized Blocked Files (O(1) hash lookups)
$blocked_files = [
    // PHP Shells & Exploits
    'shell.php' => 1, 'shell20211028.php' => 1, 'webshell.php' => 1,
    'sh3ll.php' => 1, 'b374k.php' => 1, 'r57.php' => 1, 'c99.php' => 1,
    'gecko.php' => 1, 'alfa-rex.php' => 1, 'xl2023x.php' => 1, 'xmrlpc.php' => 1,
    'DaoZM.php' => 1, 'MyShell.php' => 1, 'aconfig.php' => 1, 'engine.php' => 1,
    'evil.php' => 1, 'onclickfuns.php' => 1, 'defense.php' => 1, 'sym.php' => 1,
    'fun.php' => 1, 'fofo.php' => 1, 'flower.php' => 1, 'goat1.php' => 1,
    'mari.php' => 1, 'lux.php' => 1, 'net.php' => 1, 'max.php' => 1, 'rk2.php' => 1,

    // WordPress Core & Plugins
    'wp-config.php' => 1, 'wp-conflg.php' => 1, 'wp-login.php' => 1,
    'wp-admin.php' => 1, 'wp-load.php' => 1, 'wp-admin/includes/wp-conflg.php' => 1,
    'wp-admin/js/wp-conflg.php' => 1, 'wp-admin/install.php' => 1,
    'wp-content/install.php' => 1, 'wp-content/plugins/install.php' => 1,
    'wp-content/themes/astra/inc/network.php' => 1,
    'wp-content/plugins/pwnd/gecko.php' => 1, 'wp-content/uploads/install.php' => 1,
    'wp-includes/install.php' => 1, 'wp-includes/fonts/install.php' => 1,
    'wp-includes/ID3/install.php' => 1, 'wp-includes/IXR/install.php' => 1,
    'wp-includes/Requests/library/byp.php' => 1,
    'wp-includes/SimplePie/Content/about.php' => 1,
    'wp-includes/rest-api/autoload_classmap.php' => 1,
    'wp-includes/css/wp-login.php' => 1, 'wp-includes/js/crop/shell.php' => 1,
    'wp-includes/js/jquery/jquery.php' => 1,
    'wp-includes/js/imgareaselect/wp-the1me.php' => 1,
    'wp-includes/shell1.php' => 1, 'wp-includes/sitemaps/alfa-rex.php' => 1,
    'wp-admin/css/colors/moon.php' => 1,
    'wp-admin/css/colors/ocean/lock0360.php' => 1,
    'wp-admin/images/wp-login.php' => 1, 'wp-admin/network/lock.php' => 1,
    'wp-admin/maint/install.php' => 1, 'wp-admin/autoload_classmap.php' => 1,
    'wp-index.php' => 1, 'wp-links.php' => 1, 'wp-scr1pts.php' => 1,
    'wp-settings.php' => 1, 'wp-signup.php' => 1, 'wp-site.php' => 1,
    'wp-the1me.php' => 1, 'wpm.php' => 1, 'xindex.php' => 1,

    // WordPress Plugin-Specific
    'wp-content/plugins/revslider/temp/update_extract/revslider.php' => 1,
    'wp-content/plugins/wp-file-manager/lib/files/' => 1,

    // Joomla
    'configuration.php' => 1, 'administrator/index.php' => 1,
    'libraries/joomla/session/session.php' => 1,
    'components/com_jce/jce.php' => 1,
    'modules/mod_simplefileupload/simplefileupload.php' => 1,

    // Upload Scripts
    'upload.php' => 1, 'upload/injector.php' => 1, 'cgi-bin/upfile.php' => 1,
    'test/upload.php' => 1, 'admin/uploads/media.php' => 1,

    // Reverse Proxy & Server
    'server-info.php' => 1, 'server-status' => 1, 'proxy' => 1,
    'actuator/env' => 1, 'v2/_catalog' => 1, 'debug/default/view' => 1,
    'exchange.php' => 1, 'ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application' => 1,

    // Let's Encrypt
    '.well-known/acme-challenge/wso112233.php' => 1,
    '.well-known/admin.php' => 1,
    '.well-known/pki-validation/muse.php' => 1,
    '.well-known/pki-validation/pwnd.php' => 1,
    'pki-validation.php' => 1,

    // File Managers
    'filemanager.php' => 1, 'fckeditor.php' => 1, 'muse.php' => 1,
    'adminer.php' => 1, 'phpmyadmin/index.php' => 1,
    'admin/fckeditor/editor/filemanager/owlmailer.php' => 1,
    'cgi-bin/filemanager.php' => 1, 'assets/shell.php' => 1,
    'autoloadclassmap.php' => 1, 'room.php' => 1,

    // Miscellaneous
    'api.php' => 1, 'cpanel.php' => 1, 'login.action' => 1,
    'makeasmtp.php' => 1, 'modules.php' => 1, 'payment.php' => 1,
    's/6373e2835313e26323e2339313/_/META-INF/maven/com.atlassian.jira/' => 1,
    'sidebarx.php' => 1, 'siteindex.php' => 1, 'update.php' => 1,
    'db.php' => 1, '1.php' => 1, '0x.php' => 1,
    'buy.php' => 1, 'config.php' => 1, 'footer.php' => 1, 'post.php' => 1,
    'fw.php' => 1, 'function.php' => 1, 'm.php' => 1, 'mysql.php' => 1,
    'phpinfo.php' => 1, 'info.php' => 1
];

if ($is_wordpress) {
    unset($blocked_files['wp-signup.php']);
    unset($blocked_files['wp-login.php']);
    unset($blocked_files['post.php']);
    unset($blocked_files['upload.php']);
}

// Compiled Malicious Patterns
$blocked_patterns = [
    '/(?:\.\.\/\.\.|phpinfo|eval\(|base64_decode|config|\.env|swagger|telescope|'.
    '_all_dbs|v2\/_catalog|debug\/default\/view|server\-status|login\.action|'.
    'shell|symlink|r57|c99|cpanel|b374k|deface|filemanager|pki\-validation|'.
    'wp\-conflg|actuator\/env|exchange\.php|ecp\/Current|microsoft\.exchange)/i'
];

// Combine all patterns into a single regex
$combined_pattern = implode('|', array_map(function($pattern) {
    return substr($pattern, 1, -2); // Remove the leading '/' and trailing '/i'
}, $blocked_patterns));

$combined_regex = '/(' . $combined_pattern . ')/i';

// Known Malicious MySQL Queries
$malicious_sql_patterns = [
    '/\b(?:UNION\s+ALL\s+SELECT|SELECT\s+\*\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|'.
    'DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|EXEC\s+\(\s*@|'.
    'WAITFOR\s+DELAY\s+\'|\bOR\s+\d+\s*=\s*\d+|--\s*$|\/\*.*?\*\/|'.
    'LOAD_FILE\s*\(|INTO\s+OUTFILE\s*\(|BENCHMARK\s*\(|SLEEP\s*\(|\bAND\s+\d+\s*=\s*\d+)/i'
];

// SQLMap Detection
$sqlmap_patterns = [
    '/\?[^=]+=[^&]*[\'"]\s*(?:--|#|\/\*)/', // Parameter tampering
    '/\b(?:AND|OR)\s+\d+\s*=\s*\d+/', // Common SQLMap payloads
    '/\b(?:UNION\s+ALL\s+SELECT|SELECT\s+\*\s+FROM)/i' // SQLMap UNION-based injection
];

// User Agent Check
$bad_user_agents = '/WPScan|sqlmap|sqlmapuseragent|nmap|nikto|dirb|fuzzer|libwww-perl|python-requests/i';

// Get request data
$request_uri = $_SERVER['REQUEST_URI'] ?? '';
$request_file = basename(parse_url($request_uri, PHP_URL_PATH)); // Extract the file name
$request_method = $_SERVER['REQUEST_METHOD'] ?? '';
$post_data = file_get_contents('php://input'); // Read raw POST data
$request_data = $request_uri . ' ' . $post_data;

// Blocking Checks
$block_reason = null;

// 1. Direct File Match
if (isset($blocked_files[$request_file])) {
    $block_reason = "Malicious file request";
}

// 2. Pattern Match (Combined Regex)
if (!$block_reason && preg_match($combined_regex, $request_uri)) {
    $block_reason = "Malicious pattern detected";
}

// 3. SQL Injection Detection
if (!$block_reason) {
    foreach ($malicious_sql_patterns as $pattern) {
        if (preg_match($pattern, $request_data)) {
            $block_reason = "Malicious SQL query detected";
            break;
        }
    }
}

// 4. SQLMap Detection
if (!$block_reason) {
    foreach ($sqlmap_patterns as $pattern) {
        if (preg_match($pattern, $request_data)) {
            $block_reason = "SQLMap-like behavior detected";
            break;
        }
    }
}

// 5. User Agent Match
if (!$block_reason && isset($_SERVER['HTTP_USER_AGENT']) && 
    preg_match($bad_user_agents, $_SERVER['HTTP_USER_AGENT'])) {
    $block_reason = "Bad User Agent: " . substr($_SERVER['HTTP_USER_AGENT'], 0, 120);
}

// Handle Blocking
if ($block_reason) {
    header("HTTP/1.1 403 Forbidden");
    if ($enable_logging) {
        $log_message = date('Y-m-d H:i:s') . " - BLOCKED: " . $request_uri . " - Reason: " . $block_reason . " - IP: " . $_SERVER['REMOTE_ADDR']." \n";
        @file_put_contents($log_file, $log_message, FILE_APPEND | LOCK_EX);
    }
    exit;
}

// Allow legitimate traffic
?>