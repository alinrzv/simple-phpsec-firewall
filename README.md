# PHP Security Firewall

A lightweight PHP security firewall to prevent malicious file uploads, SQL injection, and suspicious request patterns.

## Features
- Blocks PHP file uploads regardless of extension.
- Detects and blocks raw POST data containing PHP code.
- Prevents access to known malicious files.
- Identifies and blocks SQL injection attempts.
- Detects suspicious request patterns and bad user agents.
- Logs all blocked attempts for auditing.

## Configuration
Modify the following variables as needed:
- `$log_file` - Path to the security log.
- `$enable_logging` - Set to `true` to enable logging.
- `$is_wordpress` - Set to `true` for WordPress compatibility.

## Logging
Blocked requests are logged in the configured log file with details such as:
- Timestamp
- Block reason
- IP address

### Setting It Up: A Step-by-Step Guide

#### Step 1: Install the Script
Create a directory for the firewall:
```sh
mkdir -p /www/sec_firewall
```

Place the firewall PHP file in the folder:
```sh
mv security_firewall.php /www/sec_firewall/
```

Set permissions to ensure security and allow logging:
```sh
chmod 664 /www/sec_firewall/security_firewall.php
chmod 755 /www/sec_firewall/
```

#### Step 2: Configure PHP
Edit your `php.ini` file to prepend the firewall:
```ini
auto_prepend_file = /www/sec_firewall/security_firewall.php
```

For shared hosting, use `.htaccess`:
```apache
php_value auto_prepend_file "/www/sec_firewall/security_firewall.php"
```

#### Step 3: Test the Firewall
Simulate an attack to ensure it’s working by attempting to access a sensitive file:
```sh
http://yoursite.com/wp-config.php
```

#### Step 4: Special Instructions for aaPanel (Nginx Users)
If you're using **aaPanel** with **Nginx** and have **XSS security** enabled:
1. Open the **File Manager**.
2. Navigate to the domain's root path.
3. Edit the `.user.ini` file.
4. Add the following to the `open_basedir` rule:
   ```ini
   :/www/server/panel/tmp:/www/sec_firewall/
   ```

So you have by default this line , right ?
   ```
   open_basedir=/www/wwwroot/DOMAIN_NAME/:/tmp/
   ```

After you change it, you should have this:
   ```
   open_basedir=/www/wwwroot/DOMAIN_NAME/:/tmp/:/www/server/panel/tmp:/www/sec_firewall/
   ```

5. Save the file.

This ensures the firewall script is correctly loaded while website security.

### Nginx rewrite for wordpress using this prepend firewall 

```
# Serve static files directly without PHP processing
location ~* \.(?:ico|css|js|gif|jpe?g|png|txt|woff2?|eot|ttf|svg|pdf)$ {
    expires 6M;
    add_header Cache-Control "public, max-age=15552000";
    try_files $uri /index.php?$args;
}

location / {
    try_files $uri $uri/ /index.php?$args;

    include fastcgi_params;
    fastcgi_pass unix:/tmp/php-cgi-83.sock;  # Update based on your system
    fastcgi_index index.php;

    # Security headers
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param SCRIPT_NAME $fastcgi_script_name;
    fastcgi_param PATH_INFO $uri;
        
    # Prevent direct execution of certain PHP files (WordPress protection)
    location ~* /(xmlrpc\.php|wp-config\.php|\.htaccess) {
        deny all;
    }
    
}

# Ensure proper redirection for WordPress admin panel
rewrite /wp-admin$ $scheme://$host$uri/ permanent;
```

# Changelog

## [2025-06-21] - BugFix & optimisations
- Update security_firewall.php
- Fixed bug in URL rules/path matching.
- Various fixes related to possible articles blocking because of matching bad words.

## [2025-03-25] - Hardened PHP Firewall Script (Prepend-Optimized)

### Added
- `is_php_payload()` function for unified detection of PHP code in both files and raw binary streams.
- Fast upload inspection using `$_FILES` and MIME type filtering combined with PHP content detection.
- Early blocking of raw POST body containing PHP code (up to first 1024 bytes).

### Changed
- Replaced previous multi-function detection approach with a streamlined and centralized `is_php_payload()` call.
- Combined raw input and file content scans using the same lightweight buffer strategy.
- Simplified logic blocks for early exits and minimal overhead on valid traffic.

### Performance
- All reads limited to 1024 bytes for faster execution.
- No redundant file handles or full file reads.
- Optimized for use as `auto_prepend_file` in PHP for early execution.



## License
This project is licensed under the MIT License.

## Disclaimer
Use at your own risk. No warranty is provided for any damages that may occur.
