"""Small embedded wordlists for the pure-Python fallbacks.

These are intentionally compact so SmartHunt works with zero setup.  For
serious hunting, point the GUI at a full wordlist (SecLists, etc.) via the
"Wordlist" field — that overrides these defaults.
"""

from __future__ import annotations

# Common subdomain labels used when no external subdomain tool is installed
# and no custom wordlist is supplied.
SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "admin", "portal",
    "dev", "staging", "stage", "test", "testing", "qa", "uat", "sandbox",
    "api", "api-dev", "api-staging", "apis", "app", "apps", "mobile", "m",
    "dashboard", "panel", "cpanel", "whm", "console", "manage", "manager",
    "vpn", "remote", "ns1", "ns2", "ns3", "dns", "mx", "mx1", "mx2",
    "cdn", "static", "assets", "img", "images", "media", "files", "download",
    "downloads", "docs", "documentation", "wiki", "blog", "news", "shop",
    "store", "cart", "checkout", "pay", "payment", "payments", "billing",
    "secure", "login", "signin", "sso", "auth", "oauth", "account", "accounts",
    "my", "internal", "intranet", "corp", "git", "gitlab", "jenkins", "ci",
    "build", "grafana", "kibana", "prometheus", "monitor", "monitoring",
    "status", "health", "metrics", "logs", "log", "db", "database", "sql",
    "mysql", "postgres", "redis", "mongo", "elastic", "search", "solr",
    "cache", "proxy", "gateway", "gw", "lb", "edge", "origin", "backend",
    "back", "front", "frontend", "web", "web1", "web2", "server", "srv",
    "host", "cloud", "aws", "azure", "gcp", "s3", "storage", "backup",
    "old", "new", "beta", "alpha", "demo", "preview", "review", "temp",
    "support", "help", "helpdesk", "ticket", "tickets", "crm", "erp", "hr",
    "vpn2", "gate", "connect", "access", "id", "identity", "keycloak",
    "smtp2", "email", "newsletter", "campaign", "track", "tracking", "analytics",
    "stats", "report", "reports", "data", "api2", "v1", "v2", "v3", "graphql",
    "ws", "socket", "chat", "video", "conference", "meet", "calendar",
]

# Common paths / files used by the built-in content-discovery fallback.
CONTENT_PATHS: list[str] = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config", ".env",
    ".env.local", ".env.production", ".DS_Store", "config.php", "config.json",
    "wp-config.php", "wp-config.php.bak", "backup.zip", "backup.tar.gz",
    "backup.sql", "db.sql", "dump.sql", "database.sql", "admin", "administrator",
    "admin/login", "login", "signin", "user", "users", "account", "dashboard",
    "panel", "phpmyadmin", "pma", "adminer.php", "server-status", "server-info",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger.json",
    "openapi.json", "api-docs", "docs", "actuator", "actuator/health",
    "actuator/env", "metrics", "debug", "test", "status", "info", "health",
    "console", ".well-known/security.txt", "crossdomain.xml", "web.config",
    "phpinfo.php", "info.php", "readme.html", "README.md", "CHANGELOG.md",
    "LICENSE", "package.json", "composer.json", "yarn.lock", "Dockerfile",
    "docker-compose.yml", ".htaccess", ".htpasswd", "id_rsa", "config.yml",
    "config.yaml", "settings.py", "application.properties", "credentials",
]

# Ports probed by the built-in port scanner (name is for display only).
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3000: "node/grafana", 3306: "mysql", 3389: "rdp", 4444: "metasploit",
    5000: "flask/upnp", 5432: "postgres", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5985: "winrm", 6379: "redis", 6443: "kubernetes", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "php-fpm/sonar", 9200: "elasticsearch",
    9300: "elasticsearch", 9090: "prometheus", 10250: "kubelet", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb",
}
