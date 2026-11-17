// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 Clift Cloud LLC

package guestinspect

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/cliftcloud/certistack/pkg/initplan"
)

// testSet is a fileSet that has read files (their contents as cat returns
// them, links already followed) and listed the given trees, as Detect's
// passes leave it.
func testSet(files map[string]string, trees ...string) *fileSet {
	fs := newFileSet()
	for name, contents := range files {
		fs.content[name] = contents
	}
	for _, tree := range trees {
		seen := map[string]bool{}
		for name := range files {
			rest, ok := strings.CutPrefix(name, tree+"/")
			if !ok {
				continue
			}
			parts := strings.Split(rest, "/")
			for i := range parts {
				seen[strings.Join(parts[:i+1], "/")] = true
			}
		}
		var entries []string
		for entry := range seen {
			entries = append(entries, entry)
		}
		sort.Strings(entries)
		fs.trees[tree] = entries
	}
	return fs
}

// listeners is a service's listeners as "address:port[/tls][/http][=status]"
// (address "*" for every address), in order.
func listeners(service initplan.Service) string {
	var out []string
	for _, l := range service.Listeners {
		address := l.Address
		if address == "" {
			address = "*"
		}
		s := fmt.Sprintf("%s:%d", address, l.Port)
		if l.TLS {
			s += "/tls"
		}
		if l.HTTP {
			s += "/http"
		}
		if l.Status != 0 {
			s += fmt.Sprintf("=%d", l.Status)
		}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

// rockyNginx is Rocky Linux 9's packaged nginx.conf, cut to what matters.
const rockyNginx = `# For more information on configuration, see:
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       80;
        listen       [::]:80;
        server_name  _;
        root         /usr/share/nginx/html;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

        error_page 404 /404.html;
        location = /404.html {
        }
    }

# Settings for a TLS enabled server.
#
#    server {
#        listen       443 ssl http2;
#        listen       [::]:443 ssl http2;
#    }
}
`

// debianNginx is Debian 12's packaged nginx.conf, cut to what matters.
const debianNginx = `user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
	worker_connections 768;
}

http {
	sendfile on;
	include /etc/nginx/mime.types;
	default_type application/octet-stream;
	ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
	access_log /var/log/nginx/access.log;
	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
`

const debianNginxDefault = `# Default server configuration
#
server {
	listen 80 default_server;
	listen [::]:80 default_server;

	# SSL configuration
	#
	# listen 443 ssl default_server;
	# listen [::]:443 ssl default_server;

	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;
	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}
}
`

func TestNginxListeners(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
		notes string // a note that must be there
	}{
		{"Rocky 9 as packaged", map[string]string{"/etc/nginx/nginx.conf": rockyNginx, "/etc/nginx/mime.types": "types {\n    text/html html;\n}\n"},
			"*:80/http [::]:80/http", "/usr/share/nginx/modules/*.conf, outside the files inspected"},
		{"Debian 12 as packaged", map[string]string{"/etc/nginx/nginx.conf": debianNginx, "/etc/nginx/sites-enabled/default": debianNginxDefault},
			"*:80/http [::]:80/http", ""},
		{"loopback, specific address, TLS, a server without listen", map[string]string{"/etc/nginx/nginx.conf": `http {
  server { listen 127.0.0.1:8080; }
  server { listen 192.0.2.40:80; listen 443 ssl http2; listen [::]:443 ssl; }
  server { server_name old.example; }
}`}, "127.0.0.1:8080/http 192.0.2.40:80/http *:443/tls/http [::]:443/tls/http *:80/http", ""},
		{"unix sockets and QUIC are left out; ssl on makes a server's listens TLS", map[string]string{"/etc/nginx/nginx.conf": `http {
  server { listen unix:/run/app.sock; listen 8443 quic reuseport; listen 8443 ssl; }
  server { ssl on; listen 9443; }
}`}, "*:8443/tls/http *:9443/tls/http", ""},
		{"comments after a directive, quoted arguments, an address without a port", map[string]string{"/etc/nginx/nginx.conf": "http {\n  server { listen \"8080\";#comment\n listen 198.51.100.7; # its own\n }\n}\n"},
			"*:8080/http 198.51.100.7:80/http", ""},
		{"a redirect to HTTPS, and the default server of a port", map[string]string{"/etc/nginx/nginx.conf": `http {
  server { listen 80; server_name first.example; return 301 https://$host$request_uri; }
  server { listen 80 default_server; server_name catch.example; location / { return 302 https://login.example/; } }
  server { listen 8080; rewrite ^ https://$host$request_uri permanent; }
}`}, "*:80/http=302 *:80/http=302 *:8080/http=301", ""},
		{"stream servers are TCP, not HTTP", map[string]string{"/etc/nginx/nginx.conf": "stream {\n  server { listen 3306; proxy_pass db:3306; }\n}\n"},
			"*:3306", ""},
		{"includes are followed one level deep", map[string]string{
			"/etc/nginx/nginx.conf":         "http { include conf.d/*.conf; }",
			"/etc/nginx/conf.d/a.conf":      "server { listen 81; include /etc/nginx/snippets/more.conf; }",
			"/etc/nginx/conf.d/.hidden":     "server { listen 99; }",
			"/etc/nginx/snippets/more.conf": "listen 82;",
		}, "*:81/http", "includes /etc/nginx/snippets/more.conf, which was not followed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := testSet(tc.files, "/etc/nginx")
			service := parseNginx(fs, "nginx.service")
			if got := listeners(service); got != tc.want {
				t.Errorf("listeners %q, want %q", got, tc.want)
			}
			if tc.notes != "" && !strings.Contains(strings.Join(fs.notes, "\n"), tc.notes) {
				t.Errorf("notes %q lack %q", fs.notes, tc.notes)
			}
			if len(fs.wanted) != 0 {
				t.Errorf("wanted %v", fs.wanted)
			}
		})
	}
}

// The Listen scopes as the probe sees them.
func TestListenerScopes(t *testing.T) {
	for address, want := range map[string]string{
		"": initplan.ScopeAll, "*": initplan.ScopeAll, "0.0.0.0": initplan.ScopeAll, "[::]": initplan.ScopeAll, "::": initplan.ScopeAll, "_default_": initplan.ScopeAll,
		"127.0.0.1": initplan.ScopeLoopback, "127.0.1.1": initplan.ScopeLoopback, "[::1]": initplan.ScopeLoopback, "::1": initplan.ScopeLoopback, "localhost": initplan.ScopeLoopback,
		"10.0.0.5": initplan.ScopeAddress, "[2001:db8::5]": initplan.ScopeAddress, "db.example.com": initplan.ScopeAddress,
	} {
		if got := (initplan.Listener{Address: address}).Scope(); got != want {
			t.Errorf("scope of %q = %s, want %s", address, got, want)
		}
	}
}

const debianApache = `DefaultRuntimeDir ${APACHE_RUN_DIR}
PidFile ${APACHE_PID_FILE}
Timeout 300
# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf

<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>

LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
`

const debianPorts = `# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 80

<IfModule ssl_module>
	Listen 443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 443
</IfModule>
`

const rhelHttpd = `ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
IncludeOptional conf.d/*.conf
`

func TestApacheListeners(t *testing.T) {
	debian := func(extra map[string]string) map[string]string {
		files := map[string]string{
			"/etc/apache2/apache2.conf":                     debianApache,
			"/etc/apache2/ports.conf":                       debianPorts,
			"/etc/apache2/mods-enabled/mpm_event.load":      "LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so\n",
			"/etc/apache2/sites-enabled/000-default.conf":   "<VirtualHost *:80>\n\tServerAdmin webmaster@localhost\n\tDocumentRoot /var/www/html\n</VirtualHost>\n",
			"/etc/apache2/mods-available/ssl.load":          "LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so\n",
			"/etc/apache2/sites-available/default-ssl.conf": "<VirtualHost _default_:443>\nSSLEngine on\n</VirtualHost>\n",
		}
		for name, contents := range extra {
			files[name] = contents
		}
		return files
	}
	for _, tc := range []struct {
		name  string
		unit  string
		files map[string]string
		want  string
	}{
		{"Debian as packaged: no ssl module, so no 443", "apache2.service", debian(nil), "*:80/http"},
		{"Debian with ssl enabled", "apache2.service", debian(map[string]string{
			"/etc/apache2/mods-enabled/ssl.load":          "LoadModule ssl_module /usr/lib/apache2/modules/mod_ssl.so\n",
			"/etc/apache2/sites-enabled/default-ssl.conf": "<VirtualHost _default_:443>\n\tSSLEngine on\n</VirtualHost>\n",
		}), "*:80/http *:443/tls/http"},
		{"RHEL with mod_ssl", "httpd.service", map[string]string{
			"/etc/httpd/conf/httpd.conf":             rhelHttpd,
			"/etc/httpd/conf.modules.d/00-base.conf": "LoadModule mpm_event_module modules/mod_mpm_event.so\n",
			"/etc/httpd/conf.modules.d/00-ssl.conf":  "LoadModule ssl_module modules/mod_ssl.so\n",
			"/etc/httpd/conf.d/ssl.conf":             "Listen 443 https\n<VirtualHost _default_:443>\nSSLEngine on\n</VirtualHost>\n",
		}, "*:80/http *:443/tls/http"},
		{"a redirect of / to HTTPS", "apache2.service", debian(map[string]string{
			"/etc/apache2/sites-enabled/000-default.conf": "<VirtualHost *:80>\n  ServerName www.example\n  Redirect permanent / https://www.example/\n</VirtualHost>\n",
		}), "*:80/http=301"},
		{"certbot's rewrite has a condition on the host name, which a request to the address does not meet", "apache2.service", debian(map[string]string{
			"/etc/apache2/sites-enabled/000-default.conf": "<VirtualHost *:80>\nRewriteEngine on\nRewriteCond %{SERVER_NAME} =www.example\nRewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]\n</VirtualHost>\n",
		}), "*:80/http"},
		{"an unconditional rewrite redirects", "apache2.service", debian(map[string]string{
			"/etc/apache2/sites-enabled/000-default.conf": "<VirtualHost *:80>\nRewriteEngine on\nRewriteRule ^/?(.*) https://www.example/$1 [R=301,L]\n</VirtualHost>\n",
		}), "*:80/http=301"},
		{"a specific address, a continued line, an http protocol on 8443", "httpd.service", map[string]string{
			"/etc/httpd/conf/httpd.conf": "Listen 192.0.2.8:8080\nListen \\\n  8443 http\nListen [::1]:9000\n",
		}, "192.0.2.8:8080/http *:8443/http [::1]:9000/http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := testSet(tc.files, "/etc/apache2", "/etc/httpd")
			service := parseApache(fs, tc.unit)
			if got := listeners(service); got != tc.want {
				t.Errorf("listeners %q, want %q (notes %q)", got, tc.want, fs.notes)
			}
			for wanted := range fs.wanted {
				t.Errorf("wanted %s", wanted)
			}
		})
	}
}

func TestMySQLListeners(t *testing.T) {
	const debianMariaDB = "[client-server]\n# port = 3306\nsocket = /run/mysqld/mysqld.sock\n\n!includedir /etc/mysql/conf.d/\n!includedir /etc/mysql/mariadb.conf.d/\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
		noTCP bool
	}{
		{"Debian as packaged: localhost", map[string]string{
			"/etc/mysql/my.cnf":                       debianMariaDB,
			"/etc/mysql/mariadb.conf.d/50-server.cnf": "[server]\n\n[mysqld]\nuser                    = mysql\npid-file                = /run/mysqld/mysqld.pid\n#port                   = 3306\nbind-address            = 127.0.0.1\n",
			"/etc/mysql/mariadb.conf.d/50-client.cnf": "[client]\nport = 3399\n",
			"/etc/mysql/debian.cnf":                   "[client]\npassword = do-not-read\n",
		}, "127.0.0.1:3306", false},
		{"RHEL as packaged: every address", map[string]string{
			"/etc/my.cnf":                      "[client-server]\n!includedir /etc/my.cnf.d\n",
			"/etc/my.cnf.d/mariadb-server.cnf": "[server]\n[mysqld]\ndatadir=/var/lib/mysql\nsocket=/var/lib/mysql/mysql.sock\n",
		}, "*:3306", false},
		{"a port, an address list, an inline comment, loose- and underscores", map[string]string{
			"/etc/my.cnf": "[mysqld]\nport=3307\nloose_bind_address = 0.0.0.0,::1 # every IPv4 address and IPv6 loopback\n",
		}, "0.0.0.0:3307 ::1:3307", false},
		{"a later file wins", map[string]string{
			"/etc/my.cnf":       "[mysqld]\nbind-address=127.0.0.1\n",
			"/etc/mysql/my.cnf": "[mariadb-10.11]\nbind-address=\"0.0.0.0\"\n",
		}, "0.0.0.0:3306", false},
		{"skip-networking", map[string]string{"/etc/my.cnf": "[mysqld]\nskip-networking\n"}, "", true},
		{"skip-networking=0 keeps it", map[string]string{"/etc/my.cnf": "[mysqld]\nskip_networking=0\n"}, "*:3306", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := testSet(tc.files, "/etc/mysql", "/etc/my.cnf.d")
			for _, main := range mysqlMains {
				if _, ok := tc.files[main]; ok {
					fs.present[main] = true
				}
			}
			service := parseMySQL(fs, "mariadb.service")
			if got := listeners(service); got != tc.want || (service.NoTCP != "") != tc.noTCP {
				t.Errorf("listeners %q, no TCP %q; want %q, %v", got, service.NoTCP, tc.want, tc.noTCP)
			}
			for wanted := range fs.wanted {
				t.Errorf("wanted %s", wanted)
			}
		})
	}
}

func TestPostgreSQLListeners(t *testing.T) {
	debian := pgCluster{unit: "postgresql@15-main.service", conf: "/etc/postgresql/15/main/postgresql.conf", autoConf: "/var/lib/postgresql/15/main/postgresql.auto.conf", startConf: "/etc/postgresql/15/main/start.conf"}
	rhel := pgCluster{unit: "postgresql.service", conf: "/var/lib/pgsql/data/postgresql.conf", autoConf: "/var/lib/pgsql/data/postgresql.auto.conf"}
	for _, tc := range []struct {
		name    string
		cluster pgCluster
		files   map[string]string
		want    string
		noTCP   bool
	}{
		{"Debian as packaged: localhost", debian, map[string]string{
			"/etc/postgresql/15/main/postgresql.conf": "data_directory = '/var/lib/postgresql/15/main'\t\t# use data in another directory\n#listen_addresses = 'localhost'\t\t# what IP address(es) to listen on;\nport = 5432\t\t\t\t# (change requires restart)\ninclude_dir = 'conf.d'\n",
			"/etc/postgresql/15/main/start.conf":      "# Automatic startup configuration\nauto\n",
		}, "localhost:5432", false},
		{"Debian with conf.d and ALTER SYSTEM", debian, map[string]string{
			"/etc/postgresql/15/main/postgresql.conf":          "port = 5433\ninclude_dir = 'conf.d'\n",
			"/etc/postgresql/15/main/conf.d/listen.conf":       "listen_addresses = 'localhost'\n",
			"/var/lib/postgresql/15/main/postgresql.auto.conf": "# Do not edit this file manually!\nlisten_addresses = '*'\n",
		}, "*:5433", false},
		{"RHEL with a list and a quote in a comment", rhel, map[string]string{
			"/var/lib/pgsql/data/postgresql.conf": "listen_addresses = 'localhost, 192.0.2.20' # it's both\nport 5434\n",
		}, "localhost:5434 192.0.2.20:5434", false},
		{"no TCP at all", rhel, map[string]string{"/var/lib/pgsql/data/postgresql.conf": "listen_addresses = ''\n"}, "", true},
		{"a cluster that does not start with the guest", debian, map[string]string{
			"/etc/postgresql/15/main/postgresql.conf": "listen_addresses = '*'\n",
			"/etc/postgresql/15/main/start.conf":      "manual\n",
		}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := testSet(tc.files, "/etc/postgresql")
			service := parsePostgres(fs, tc.cluster)
			if got := listeners(service); got != tc.want || (service.NoTCP != "") != tc.noTCP {
				t.Errorf("listeners %q, no TCP %q; want %q, %v (notes %q)", got, service.NoTCP, tc.want, tc.noTCP, fs.notes)
			}
		})
	}
}

func TestRedisListeners(t *testing.T) {
	for _, tc := range []struct {
		name, conf, want string
		noTCP            bool
	}{
		{"as packaged", "bind 127.0.0.1 -::1\nprotected-mode yes\nport 6379\n", "127.0.0.1:6379 ::1:6379", false},
		{"every address with TLS", "bind 0.0.0.0\nport 6380\ntls-port 6381\n", "0.0.0.0:6380 0.0.0.0:6381/tls", false},
		{"no bind", "# bind 127.0.0.1\nport 6379\n", "*:6379", false},
		{"TLS only", "port 0\ntls-port 6390\n", "*:6390/tls", false},
		{"no TCP", "port 0\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := testSet(map[string]string{"/etc/redis/redis.conf": tc.conf}, "/etc/redis")
			service := parseRedis(fs, "redis-server.service", "/etc/redis/redis.conf")
			if got := listeners(service); got != tc.want || (service.NoTCP != "") != tc.noTCP {
				t.Errorf("listeners %q, no TCP %q; want %q, %v", got, service.NoTCP, tc.want, tc.noTCP)
			}
		})
	}
}

func TestSSHDListeners(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"Debian 12 as packaged", map[string]string{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n#Port 22\n#ListenAddress 0.0.0.0\nKbdInteractiveAuthentication no\n"}, "*:22"},
		{"a port from an included file", map[string]string{
			"/etc/ssh/sshd_config":                  "Include /etc/ssh/sshd_config.d/*.conf\n",
			"/etc/ssh/sshd_config.d/10-port.conf":   "Port 2222\n",
			"/etc/ssh/sshd_config.d/50-redhat.conf": "Include /etc/crypto-policies/back-ends/opensshserver.config\n",
		}, "*:2222"},
		{"ports and addresses", map[string]string{"/etc/ssh/sshd_config": "Port 22\nport=2222\nListenAddress 192.0.2.30\nListenAddress [::1]:2200\nListenAddress 127.0.0.1:22\n"},
			"192.0.2.30:22 192.0.2.30:2222 [::1]:2200 127.0.0.1:22"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := testSet(tc.files, "/etc/ssh")
			service := parseSSHD(fs, "ssh.service")
			if got := listeners(service); got != tc.want {
				t.Errorf("listeners %q, want %q (notes %q)", got, tc.want, fs.notes)
			}
		})
	}
}
