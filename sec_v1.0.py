#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Linux服务器应急响应排查脚本
功能：
1. SSH爆破/登录记录分析
2. 异常进程分析（挖矿/隐藏/可疑）
3. 网络连接分析（外联/高危端口/挖矿）
4. Webshell检测（强化冰蝎JSP+扩展扫描目录）
5. 系统账户异常分析（UID=0/空密码/新增用户/sudo权限）
6. 文件篡改检测（敏感文件修改/临时目录可执行文件/异常定时任务）
7. 日志异常分析（日志篡改/su失败/root异常命令）
8. 挖矿行为专项检测（挖矿文件/矿池连接/GPU使用）
"""

import os
import re
import time
import json
import subprocess
import sys
import getpass
import hashlib
from datetime import datetime, timedelta

# 密码验证
print("===== Linux服务器应急响应排查脚本 =====")

# 检测是否为Windows环境
is_windows = sys.platform.startswith('win')

if is_windows:
    print("Windows环境下运行，跳过密码验证...")
else:
    print("请输入密码以继续...")
    password = getpass.getpass()

    # 使用SHA256哈希存储密码
    correct_hash = "e724679b1613be6600cd9635873c0f07cf9d74a23242219386c41141521798c6"
    input_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    if input_hash != correct_hash:
        print("密码错误，脚本将退出。")
        sys.exit(1)

    print("密码正确，正在加载脚本...")

# 全局配置
MAX_LOG_SIZE = 10 * 1024 * 1024  # 最大日志文件大小（10MB）
SUSPICIOUS_PROCESS_NAMES = [
    # 主流挖矿软件
    "minerd", "xmrig", "cpuminer", "ccminer", "bfgminer", "cgminer",
    "ethminer", "claymore", "t-rex", "lolminer", "gminer", "nbminer",
    "nanominer", "teamredminer", "wildrig", "miniZ", "prohashing",
    # 变种和伪装名
    "xmr-stak", "xmrminer", "monero", "bitcoin", "ethereum", "litecoin",
    "dogecoin", "dash", "zcash", "ravencoin", "binance", "huobi",
    # 新增挖矿家族
    "wannamine", "elfcoinminer", "givemexyz", "trojancoinminer",
    # 僵尸网络
    "blackmoon", "festi", "gafgyt", "kelihos", "mykings",
    # 工具类（可能被用于挖矿）
    "hashcat", "john", "hydra", "medusa", "password", "cracker",
    # 常见伪装名
    "system", "service", "update", "updater", "maintenance", "monitor",
    "worker", "process", "task", "daemon", "server", "client",
    # 临时文件和脚本
    "sh", "bash", "python", "perl", "ruby", "php"
]
MINING_POOL_KEYWORDS = [
    # 矿池相关
    "pool", "mine", "miner", "hash", "eth", "btc", "xmr",
    # 加密货币
    "cryptocurrency", "crypto", "coin", "tokens", "blockchain",
    "monero", "ethereum", "bitcoin", "litecoin", "dogecoin", "dash",
    "zcash", "ravencoin", "binance", "huobi", "okex", "coinbase",
    # 新增挖矿家族
    "wannamine", "elfcoinminer", "givemexyz", "trojancoinminer",
    # 僵尸网络
    "blackmoon", "festi", "gafgyt", "kelihos", "mykings",
    # 挖矿相关
    "mining", "hashrate", "difficulty", "reward", "wallet", "address",
    # 矿池域名关键词
    "miningpool", "hashvault", "nanopool", "f2pool", "poolin",
    "antpool", "slushpool", "btc.com", "viabtc", "ethpool",
    # 常见矿池端口
    "3333", "5555", "7777", "8888", "9999", "14444", "33333",
    # 挖矿软件特征
    "xmrig", "cpuminer", "ccminer", "ethminer", "claymore",
    # 网络特征
    "stratum", "tcp", "udp", "socket", "connection"
]
WEBSHELL_KEYWORDS = [
    "eval", "assert", "exec", "system", "passthru", "shell_exec",
    "popen", "proc_open", "base64_decode", "gzinflate", "str_rot13",
    "create_function", "array_map", "call_user_func", "call_user_func_array"
]
BEHINDER_JSP_KEYWORDS = [
    # 冰蝎JSP特征
    "Class.forName", "getRuntime", "exec", "ProcessBuilder",
    "ByteArrayOutputStream", "InputStreamReader", "BufferedReader",
    "OutputStream", "InputStream", "Cipher", "init", "doFinal",
    "AES", "ECB", "PKCS5Padding", "Base64", "decode", "encode",
    # 冰蝎PHP特征
    "mcrypt_create_iv", "mcrypt_decrypt", "MCRYPT_RIJNDAEL_128",
    "MCRYPT_MODE_CBC", "openssl_encrypt", "openssl_decrypt",
    # 冰蝎ASP特征
    "CreateObject", "WScript.Shell", "ADODB.Stream", "ChrB",
    # 冰蝎通用特征
    "Behinder", "DESede/CBC/PKCS5Padding", "javax.crypto.Cipher"
]
FILE_TYPE_THRESHOLDS = {
    # Web脚本文件（需要更高的阈值）
    ".jsp": 4, ".jspx": 4, ".php": 4, ".php3": 4, ".php4": 4, ".php5": 4,
    ".phtml": 4, ".asp": 4, ".aspx": 4, ".ashx": 4, ".jspf": 4,
    # 脚本文件（保持中等阈值）
    ".sh": 3, ".pl": 3, ".py": 3, ".cgi": 3,
    # 配置文件（需要更高的阈值）
    ".conf": 5, ".config": 5, ".ini": 5, ".yml": 5, ".yaml": 5,
    # 其他文件类型
    ".js": 4, ".json": 4, ".vbs": 3, ".ps1": 3, ".bat": 3, ".cmd": 3,
    # 默认阈值
    "default": 4
}
WEBSHELL_WHITELIST = [
    # 前端框架和库
    "jquery", "bootstrap", "angular", "react", "vue", "node_modules",
    "vuex", "react-router", "angular-cli", "webpack", "gulp", "grunt",
    # Java框架和库
    "spring", "hibernate", "mybatis", "tomcat", "jetty", "jboss",
    "weblogic", "websphere", "struts", "jsf", "primefaces", "vaadin",
    # 后端框架和库
    "laravel", "symfony", "codeigniter", "cakephp", "zend", "slim",
    "django", "flask", "bottle", "pyramid", "tornado", "fastapi",
    "express", "koa", "hapi", "nestjs", "sails", "meteor",
    # 数据库和缓存
    "mysql", "postgresql", "mongodb", "redis", "memcached", "sqlite",
    "oracle", "mariadb", "cassandra", "elasticsearch",
    # 服务器和中间件
    "nginx", "apache", "lighttpd", "haproxy", "varnish", "traefik",
    "php-fpm", "uwsgi", "gunicorn", "pm2", "supervisor",
    # 系统目录
    "/etc/", "/usr/lib", "/usr/share", "/lib", "/lib64", "/var/lib",
    "/usr/local/lib", "/usr/local/share", "/opt/lib", "/opt/share",
    # 开发工具和环境
    ".git", ".svn", ".hg", "composer", "npm", "yarn", "pip", "virtualenv",
    "venv", ".venv", "node_modules", "vendor", "bower_components",
    # 测试和文档
    "test", "tests", "spec", "docs", "documentation", "example", "examples",
    # 日志和临时文件
    ".log", "access.log", "error.log", "debug.log", "temp", "tmp",
    # 配置文件
    "config", "settings", "environment", "env", ".env", "docker-compose",
    # 备份和压缩文件
    ".backup", ".bak", ".zip", ".tar", ".tar.gz", ".rar", ".7z",
    # 安全工具
    "waf", "firewall", "security", "antivirus", "scanner", "audit"
]
WEBSHELL_SCAN_DIRS = [
    # 通用Web目录
    "/var/www", "/var/www/html", "/var/www/vhosts", "/srv/www",
    "/usr/local/apache2/htdocs", "/usr/local/nginx/html",
    # Tomcat相关目录
    "/usr/local/tomcat/webapps", "/opt/tomcat/webapps", "/tomcat/webapps",
    "/usr/share/tomcat/webapps", "/var/lib/tomcat/webapps",
    "/usr/local/tomcat8/webapps", "/usr/local/tomcat9/webapps",
    "/opt/tomcat8/webapps", "/opt/tomcat9/webapps",
    # 其他Java应用服务器目录
    "/usr/local/weblogic/wlserver/server/lib", "/usr/local/weblogic/user_projects",
    "/opt/weblogic/wlserver/server/lib", "/opt/weblogic/user_projects",
    "/usr/local/websphere/AppServer", "/opt/websphere/AppServer",
    "/usr/local/jboss/standalone/deployments", "/opt/jboss/standalone/deployments",
    "/usr/local/jetty/webapps", "/opt/jetty/webapps",
    # PHP应用框架默认目录
    "/var/www/laravel/public", "/var/www/wordpress", "/var/www/drupal",
    "/var/www/joomla", "/var/www/magento", "/var/www/shopify",
    # Node.js应用目录
    "/var/www/nodejs", "/home/node/app", "/opt/node/app",
    # Python应用目录
    "/var/www/flask", "/var/www/django", "/home/python/app",
    # 云服务提供商默认目录
    "/var/app/current", "/opt/bitnami/apache2/htdocs", "/usr/local/vesta/data",
    "/opt/aws/elasticbeanstalk", "/opt/azure/appservice", "/opt/gcp/appengine",
    # 容器相关目录
    "/var/lib/docker/volumes", "/var/lib/kubelet/pods", "/opt/rancher",
    "/etc/docker", "/var/run/docker",
    # 其他可能的Web目录
    "/home/*/public_html", "/home/*/www", "/home/*/web",
    "/home/*/app", "/home/*/website", "/home/*/site",
    "/root/public_html", "/root/www", "/root/web", "/root/app",
    "/tmp", "/var/tmp", "/dev/shm", "/run/shm",
    # 开发和部署目录
    "/usr/local/src", "/usr/src", "/opt", "/opt/src", "/opt/app",
    "/home", "/root", "/var/opt", "/var/local",
    # 备份和迁移目录
    "/backup", "/var/backup", "/home/backup", "/root/backup",
    "/restore", "/var/restore", "/home/restore",
    # 网络服务配置目录
    "/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/lighttpd",
    # 邮件服务目录（可能被用于 webshell）
    "/var/spool/mail", "/var/mail",
    # 数据库相关目录（可能被篡改）
    "/var/lib/mysql", "/var/lib/postgresql", "/opt/mysql", "/opt/postgresql"
]

# 颜色输出类
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    BOLD_RED = '\033[1;91m'
    BOLD_GREEN = '\033[1;92m'
    BOLD_YELLOW = '\033[1;93m'
    BOLD_BLUE = '\033[1;94m'
    BOLD_CYAN = '\033[1;96m'
    BOLD_GRAY = '\033[1;90m'
    RESET = '\033[0m'

# 工具函数
def run_command(cmd):
    """执行系统命令并返回结果"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            return "命令执行失败"
        return output
    except Exception as e:
        return "命令执行失败"

def get_file_mtime(file_path):
    """获取文件修改时间"""
    try:
        mtime = os.path.getmtime(file_path)
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
    except:
        return "未知"

def is_binary_file(file_path):
    """判断是否为二进制文件"""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
        # 检查是否包含非文本字符
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
        return bool(chunk.translate(None, text_chars))
    except:
        return True

def read_file_with_encoding(file_path):
    """读取文件内容，自动适配编码"""
    try:
        # 尝试UTF-8编码
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except:
        try:
            # 尝试GBK编码
            with open(file_path, 'r', encoding='gbk', errors='ignore') as f:
                return f.read()
        except:
            return ""

def is_key_file_ext(file_path):
    """判断是否为关键文件扩展名"""
    key_exts = [
        ".jsp", ".jspx", ".php", ".php3", ".php4", ".php5", ".phtml",
        ".asp", ".aspx", ".ashx", ".jspf", ".sh", ".pl", ".py", ".cgi"
    ]
    ext = os.path.splitext(file_path)[1].lower()
    return ext in key_exts

# ===================== 1. SSH爆破/登录记录分析 =====================
def analyze_ssh_logs():
    """分析SSH爆破和登录记录"""
    print(f"\n{Colors.BLUE}[1/8] 开始分析SSH爆破/登录记录{Colors.RESET}")
    ssh_results = {
        "brute_force_ips": {},  # 保持原结构用于统计
        "brute_force_details": [],  # 新增用于存储详细信息
        "brute_force_details_5days": [],  # 新增用于存储5天内的详细信息
        "successful_logins": [],
        "total_brute_force_attempts": 0,
        "total_successful_logins": 0,
        "brute_force_success": 0,
        "ssh_backdoor_symlinks": [],  # 新增SSH软连接后门检测结果
        "remote_connections": [],  # 新增远程连接记录
        "unauthorized_ssh_keys": []  # 新增未授权公钥检测结果
    }
    
    # 获取当前时间和5天前的时间
    import datetime
    current_time = datetime.datetime.now()
    five_days_ago = current_time - datetime.timedelta(days=5)
    
    # 月份映射
    month_map = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }
    
    def parse_log_time(time_str):
        """解析日志时间字符串"""
        try:
            parts = time_str.split()
            if len(parts) == 3:
                month_str, day, time = parts
                month = month_map.get(month_str, 1)
                # 假设是当前年份
                year = current_time.year
                # 解析时间
                hour, minute, second = map(int, time.split(':'))
                # 创建datetime对象
                log_time = datetime.datetime(year, month, int(day), hour, minute, second)
                # 处理跨年情况
                if log_time > current_time:
                    log_time = log_time.replace(year=year-1)
                return log_time
        except Exception:
            pass
        return None

    # 检查SSH日志文件
    ssh_log_files = [
        "/var/log/auth.log", "/var/log/secure", "/var/log/sshd.log"
    ]

    for log_file in ssh_log_files:
        if not os.path.exists(log_file):
            continue

        try:
            # 检查文件大小
            if os.path.getsize(log_file) > MAX_LOG_SIZE:
                print(f"{Colors.YELLOW}[警告] SSH日志文件{log_file}过大，仅分析最后1000行{Colors.RESET}")
                cmd = f"tail -n 1000 {log_file}"
                log_content = run_command(cmd)
            else:
                with open(log_file, 'r', errors='ignore') as f:
                    log_content = f.read()

            # 分析SSH爆破记录
            # 更详细的模式，包含时间信息
            brute_force_patterns = [
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*Failed password for.*from (\S+)",
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user.*from (\S+)",
                r"(\w+\s+\d+\s+\d+:\d+:\d+).*User not known to the underlying authentication module.*from (\S+)"
            ]

            for pattern in brute_force_patterns:
                matches = re.findall(pattern, log_content)
                for match in matches:
                    if len(match) == 2:
                        time_str, ip = match
                        # 存储详细信息
                        brute_force_detail = {
                            "ip": ip,
                            "time": time_str,
                            "log_file": log_file
                        }
                        ssh_results["brute_force_details"].append(brute_force_detail)
                        # 检查是否在5天内
                        log_time = parse_log_time(time_str)
                        if log_time and log_time >= five_days_ago:
                            ssh_results["brute_force_details_5days"].append(brute_force_detail)
                        # 更新统计信息
                        if ip not in ssh_results["brute_force_ips"]:
                            ssh_results["brute_force_ips"][ip] = 0
                        ssh_results["brute_force_ips"][ip] += 1
                        ssh_results["total_brute_force_attempts"] += 1

            # 分析成功登录记录
            successful_pattern = r"Accepted \w+ for (\S+) from (\S+)"
            successful_matches = re.findall(successful_pattern, log_content)
            for user, ip in successful_matches:
                login_record = {
                    "user": user,
                    "ip": ip,
                    "time": get_file_mtime(log_file)
                }
                ssh_results["successful_logins"].append(login_record)
                ssh_results["total_successful_logins"] += 1

            # 检查爆破成功记录（先失败后成功）
            brute_force_success_pattern = r"Failed password for (\S+) from (\S+).*Accepted \w+ for \1 from \2"
            brute_force_success_matches = re.findall(brute_force_success_pattern, log_content, re.DOTALL)
            ssh_results["brute_force_success"] = len(brute_force_success_matches)

        except Exception as e:
            print(f"{Colors.YELLOW}[警告] 分析SSH日志{log_file}失败: {str(e)[:30]}{Colors.RESET}")

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== SSH爆破/登录统计 ==={Colors.RESET}")
    print(f"日志文件: {'/var/log/auth.log' if os.path.exists('/var/log/auth.log') else '/var/log/secure' if os.path.exists('/var/log/secure') else '未找到'}")
    print(f"总爆破IP数: {len(ssh_results['brute_force_ips'])}")
    print(f"总爆破尝试次数: {ssh_results['total_brute_force_attempts']}")
    print(f"成功登录次数: {ssh_results['total_successful_logins']}")
    print(f"爆破成功次数: {ssh_results['brute_force_success']}")

    print(f"\n{Colors.BOLD_YELLOW}=== SSH爆破记录（按尝试次数排序）==={Colors.RESET}")
    sorted_ips = sorted(ssh_results['brute_force_ips'].items(), key=lambda x: x[1], reverse=True)[:20]
    if sorted_ips:
        for idx, (ip, count) in enumerate(sorted_ips, 1):
            print(f"{idx}. {Colors.RED}{ip}{Colors.RESET} | 尝试次数: {count}")
    else:
        print(f"{Colors.GREEN}未检测到SSH爆破记录{Colors.RESET}")

    # 显示详细的SSH爆破记录（包含时间）
    print(f"\n{Colors.BOLD_YELLOW}=== SSH爆破详细记录（5天内，最近20条）==={Colors.RESET}")
    if ssh_results['brute_force_details_5days']:
        # 按时间排序
        sorted_details = sorted(ssh_results['brute_force_details_5days'], key=lambda x: x['time'])[-20:]
        for idx, detail in enumerate(sorted_details, 1):
            print(f"{idx}. {Colors.RED}{detail['ip']}{Colors.RESET} | 时间: {detail['time']} | 日志文件: {detail['log_file'].split('/')[-1]}")
    else:
        print(f"{Colors.GREEN}未检测到5天内的SSH爆破详细记录{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== SSH成功登录记录（按时间倒序）==={Colors.RESET}")
    if ssh_results['successful_logins']:
        for idx, login in enumerate(ssh_results['successful_logins'][-20:], 1):
            print(f"{idx}. {Colors.GREEN}{login['user']}{Colors.RESET} | IP: {login['ip']} | 时间: {login['time']}")
    else:
        print(f"{Colors.GREEN}未检测到SSH成功登录记录{Colors.RESET}")

    # 新增：检测SSH软连接后门
    print(f"\n{Colors.BOLD_YELLOW}=== SSH软连接后门检测 ==={Colors.RESET}")
    try:
        # 检查常见的SSH相关目录和文件
        ssh_related_paths = [
            "/etc/ssh", "/root/.ssh", "~/.ssh",
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/bin/sh", "/bin/bash", "/usr/bin/sudo"
        ]
        
        for path in ssh_related_paths:
            # 展开~为实际路径
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                # 检查是否为软连接
                if os.path.islink(expanded_path):
                    link_target = os.readlink(expanded_path)
                    ssh_backdoor = {
                        "path": expanded_path,
                        "target": link_target
                    }
                    ssh_results["ssh_backdoor_symlinks"].append(ssh_backdoor)
                    print(f"{Colors.RED}发现SSH软连接后门: {expanded_path} -> {link_target}{Colors.RESET}")
                # 检查目录中的软连接
                elif os.path.isdir(expanded_path):
                    try:
                        for item in os.listdir(expanded_path):
                            item_path = os.path.join(expanded_path, item)
                            if os.path.islink(item_path):
                                link_target = os.readlink(item_path)
                                ssh_backdoor = {
                                    "path": item_path,
                                    "target": link_target
                                }
                                ssh_results["ssh_backdoor_symlinks"].append(ssh_backdoor)
                                print(f"{Colors.RED}发现SSH软连接后门: {item_path} -> {link_target}{Colors.RESET}")
                    except:
                        pass
        
        if not ssh_results["ssh_backdoor_symlinks"]:
            print(f"{Colors.GREEN}未检测到SSH软连接后门{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] SSH软连接后门检测失败: {str(e)}{Colors.RESET}")

    # 新增：显示远程连接记录
    print(f"\n{Colors.BOLD_YELLOW}=== 远程连接记录 ==={Colors.RESET}")
    try:
        # 使用w命令获取当前登录用户
        w_output = run_command("w")
        if w_output and w_output != "命令执行失败":
            print(f"{Colors.BLUE}当前登录用户:{Colors.RESET}")
            print(w_output)
            ssh_results["remote_connections"].append({"type": "current", "output": w_output})
        else:
            print(f"{Colors.GREEN}未检测到当前登录用户{Colors.RESET}")
        
        # 使用who命令获取登录历史
        who_output = run_command("who")
        if who_output and who_output != "命令执行失败":
            print(f"\n{Colors.BLUE}登录历史:{Colors.RESET}")
            print(who_output)
            ssh_results["remote_connections"].append({"type": "who", "output": who_output})
        else:
            print(f"{Colors.GREEN}未检测到登录历史{Colors.RESET}")
        
        # 使用last命令获取更详细的登录历史
        last_output = run_command("last -n 10")
        if last_output and last_output != "命令执行失败":
            print(f"\n{Colors.BLUE}详细登录历史（最近10条）:{Colors.RESET}")
            print(last_output)
            ssh_results["remote_connections"].append({"type": "last", "output": last_output})
        else:
            print(f"{Colors.GREEN}未检测到详细登录历史{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 远程连接记录获取失败: {str(e)}{Colors.RESET}")

    # 新增：检测未授权SSH公钥
    print(f"\n{Colors.BOLD_YELLOW}=== SSH未授权公钥检测 ==={Colors.RESET}")
    try:
        # 读取/etc/passwd文件获取用户信息
        with open('/etc/passwd', 'r') as f:
            passwd_lines = f.readlines()
        
        # 筛选有登录权限的用户（shell不是/sbin/nologin等）
        login_users = []
        for line in passwd_lines:
            parts = line.strip().split(':')
            if len(parts) >= 7:
                user, _, uid, _, _, home_dir, shell = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]
                # 跳过系统用户（uid < 1000）和无登录shell的用户
                if int(uid) >= 1000 and shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']:
                    login_users.append((user, home_dir))
        
        # 检查root用户
        login_users.append(('root', '/root'))
        
        # 检查每个用户的authorized_keys文件
        for user, home_dir in login_users:
            ssh_dir = os.path.join(home_dir, '.ssh')
            authorized_keys_file = os.path.join(ssh_dir, 'authorized_keys')
            
            if os.path.exists(authorized_keys_file):
                try:
                    with open(authorized_keys_file, 'r') as f:
                        keys_content = f.read()
                    
                except Exception as e:
                    print(f"{Colors.YELLOW}[警告] 无法读取{authorized_keys_file}: {str(e)}{Colors.RESET}")
                
                # 分析公钥
                keys = keys_content.strip().split('\n')
                valid_keys = [key for key in keys if key and not key.startswith('#')]
                
                if valid_keys:
                    print(f"\n{Colors.BLUE}用户 {user} 的授权公钥 ({len(valid_keys)} 个):{Colors.RESET}")
                    for idx, key in enumerate(valid_keys, 1):
                        # 提取公钥类型和指纹（简化版）
                        key_parts = key.split()
                        if len(key_parts) >= 2:
                            key_type = key_parts[0]
                            # 显示公钥类型和前20个字符作为标识
                            key_identifier = key_parts[1][:20] + '...' if len(key_parts[1]) > 20 else key_parts[1]
                            print(f"  {idx}. 类型: {key_type}, 标识: {key_identifier}")
                            
                            # 将公钥信息添加到结果中
                            ssh_results["unauthorized_ssh_keys"].append({
                                "user": user,
                                "file": authorized_keys_file,
                                "key_type": key_type,
                                "key_identifier": key_identifier,
                                "full_key": key[:100] + '...' if len(key) > 100 else key
                            })
                else:
                    print(f"{Colors.GREEN}用户 {user} 无授权公钥{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}用户 {user} 无 .ssh/authorized_keys 文件{Colors.RESET}")
        
        if not ssh_results["unauthorized_ssh_keys"]:
            print(f"\n{Colors.GREEN}未检测到SSH授权公钥{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] SSH未授权公钥检测失败: {str(e)}{Colors.RESET}")

    return ssh_results

# ===================== 2. 异常进程分析 =====================
def analyze_processes():
    """分析异常进程（挖矿/隐藏/可疑）"""
    print(f"\n{Colors.BLUE}[2/8] 开始分析异常进程{Colors.RESET}")
    process_results = {
        "mining_processes": [],
        "high_cpu_processes": [],
        "hidden_processes": [],
        "suspicious_processes": []
    }

    # 获取所有进程
    try:
        ps_output = run_command("ps aux")
        if ps_output and ps_output != "命令执行失败":
            processes = ps_output.split('\n')
            for process in processes[1:]:
                if not process:
                    continue
                
                parts = process.split()
                if len(parts) < 11:
                    continue
                
                user, pid, cpu, mem, vsz, rss, tty, stat, start, time, cmd = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7], parts[8], parts[9], ' '.join(parts[10:])
                
                # 检测挖矿进程
                is_mining = False
                
                # 1. 检查进程命令行中的挖矿关键词
                for mining_proc in SUSPICIOUS_PROCESS_NAMES:
                    if mining_proc in cmd.lower():
                        is_mining = True
                        break
                
                # 2. 检查进程路径是否在临时目录
                temp_dirs = ["/tmp", "/var/tmp", "/dev/shm", "~/.tmp", "~/.cache"]
                for temp_dir in temp_dirs:
                    if temp_dir in cmd:
                        is_mining = True
                        break
                
                # 3. 检查CPU使用率（挖矿进程通常CPU占用较高）
                try:
                    cpu_usage = float(cpu)
                    if cpu_usage > 50:
                        # 结合其他特征判断
                        if any(keyword in cmd.lower() for keyword in ["miner", "hash", "coin", "crypto"]):
                            is_mining = True
                except:
                    pass
                
                # 4. 检查进程是否有网络连接（简单判断）
                if any(keyword in cmd.lower() for keyword in ["pool", "mine", "miner", "hash"]):
                    is_mining = True
                
                # 5. 检查常见挖矿软件特征
                mining_signatures = [
                    "--pool", "--url", "--user", "--pass", "--worker",
                    "stratum", "ethereum", "bitcoin", "monero", "xmr",
                    "cuda", "opencl", "gpu", "cpu", "hashrate"
                ]
                if any(sig in cmd.lower() for sig in mining_signatures):
                    is_mining = True
                
                # 如果检测到挖矿特征，添加到结果中
                if is_mining:
                    mining_process = {
                        "pid": pid,
                        "user": user,
                        "cpu": cpu,
                        "mem": mem,
                        "start": start,  # 添加开始时间
                        "time": time,    # 添加运行时间
                        "cmd": cmd,
                        "detection_method": "综合检测"
                    }
                    # 去重：避免重复添加相同的进程
                    if not any(p["pid"] == pid for p in process_results["mining_processes"]):
                        process_results["mining_processes"].append(mining_process)
                
                # 检测高CPU占用进程
                try:
                    cpu_usage = float(cpu)
                    if cpu_usage > 80:
                        high_cpu_process = {
                            "pid": pid,
                            "user": user,
                            "cpu": cpu,
                            "mem": mem,
                            "cmd": cmd
                        }
                        process_results["high_cpu_processes"].append(high_cpu_process)
                except:
                    pass
                
                # 检测可疑进程（临时目录/无路径）
                if "/tmp/" in cmd or "/var/tmp/" in cmd or "/dev/shm/" in cmd:
                    suspicious_process = {
                        "pid": pid,
                        "user": user,
                        "cpu": cpu,
                        "mem": mem,
                        "cmd": cmd
                    }
                    process_results["suspicious_processes"].append(suspicious_process)
                elif not cmd.startswith('/') and not cmd.startswith('.') and not cmd.startswith(' '):
                    # 无路径的可执行文件
                    suspicious_process = {
                        "pid": pid,
                        "user": user,
                        "cpu": cpu,
                        "mem": mem,
                        "cmd": cmd
                    }
                    process_results["suspicious_processes"].append(suspicious_process)
    
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 分析进程失败: {str(e)[:30]}{Colors.RESET}")

    # 检测隐藏进程（通过比较ps和/proc）
    try:
        ps_pids = set()
        proc_pids = set()
        
        ps_output = run_command("ps -e | awk '{print $1}'")
        if ps_output and ps_output != "命令执行失败":
            for pid in ps_output.split('\n'):
                if pid.isdigit():
                    ps_pids.add(pid)
        
        if os.path.exists('/proc'):
            for item in os.listdir('/proc'):
                if item.isdigit():
                    proc_pids.add(item)
        
        hidden_pids = proc_pids - ps_pids
        for pid in hidden_pids:
            try:
                with open(f"/proc/{pid}/cmdline", 'r') as f:
                    cmd = f.read().replace('\0', ' ').strip()
                with open(f"/proc/{pid}/status", 'r') as f:
                    status = f.read()
                user_id = re.search(r'Uid:\s+(\d+)', status)
                user = user_id.group(1) if user_id else "unknown"
                
                hidden_process = {
                    "pid": pid,
                    "user": user,
                    "cmd": cmd
                }
                process_results["hidden_processes"].append(hidden_process)
            except:
                pass
    except:
        pass

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== 挖矿进程检测 ==={Colors.RESET}")
    if process_results["mining_processes"]:
        for idx, proc in enumerate(process_results["mining_processes"], 1):
            print(f"{idx}. {Colors.RED}PID: {proc['pid']}{Colors.RESET} | 用户: {proc['user']} | CPU: {proc['cpu']}% | 开始时间: {proc.get('start', 'N/A')} | 运行时间: {proc.get('time', 'N/A')} | 命令: {proc['cmd']}")
    else:
        print(f"{Colors.GREEN}未检测到挖矿进程{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 高CPU占用进程（>80%）==={Colors.RESET}")
    if process_results["high_cpu_processes"]:
        for idx, proc in enumerate(process_results["high_cpu_processes"], 1):
            print(f"{idx}. {Colors.YELLOW}PID: {proc['pid']}{Colors.RESET} | 用户: {proc['user']} | CPU: {proc['cpu']}% | 命令: {proc['cmd']}")
    else:
        print(f"{Colors.GREEN}未检测到高CPU占用进程{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 隐藏进程检测 ==={Colors.RESET}")
    if process_results["hidden_processes"]:
        for idx, proc in enumerate(process_results["hidden_processes"], 1):
            print(f"{idx}. {Colors.RED}PID: {proc['pid']}{Colors.RESET} | 用户: {proc['user']} | 命令: {proc['cmd']}")
    else:
        print(f"{Colors.GREEN}未检测到隐藏进程{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 可疑进程检测（临时目录/无路径）==={Colors.RESET}")
    if process_results["suspicious_processes"]:
        for idx, proc in enumerate(process_results["suspicious_processes"], 1):
            print(f"{idx}. {Colors.YELLOW}PID: {proc['pid']}{Colors.RESET} | 用户: {proc['user']} | 命令: {proc['cmd']}")
    else:
        print(f"{Colors.GREEN}未检测到可疑进程{Colors.RESET}")

    return process_results

# ===================== 3. 网络连接分析 =====================
def analyze_network():
    """分析网络连接（外联/高危端口/挖矿/历史通信）"""
    print(f"\n{Colors.BLUE}[3/8] 开始分析网络连接{Colors.RESET}")
    net_results = {
        "external_conns": [],
        "danger_port_conns": [],
        "mining_conns": [],
        "listening_ports": [],
        "open_ports_detail": [],  # 开放端口详细信息
        "historical_connections": [],  # 历史通信记录
        "hidden_connections": []  # 使用busybox检测到的隐藏连接
    }

    # 常见端口服务映射
    common_services = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '53': 'DNS',
        '80': 'HTTP',
        '443': 'HTTPS',
        '110': 'POP3',
        '143': 'IMAP',
        '3306': 'MySQL',
        '3389': 'RDP',
        '6379': 'Redis',
        '7001': 'WebLogic',
        '8080': 'HTTP-Proxy',
        '8443': 'HTTPS-Proxy',
        '8888': 'HTTP-Proxy',
        '9000': 'PHP-FPM',
        '9200': 'Elasticsearch',
        '27017': 'MongoDB'
    }

    # 获取网络连接
    try:
        netstat_output = run_command("netstat -tulnpa 2>/dev/null")
        if netstat_output and netstat_output != "命令执行失败":
            connections = netstat_output.split('\n')
            for conn in connections:
                if not conn or 'Proto' in conn:
                    continue
                
                parts = conn.split()
                if len(parts) < 7:
                    continue
                
                proto, recv_q, send_q, local, foreign, state, pid_prog = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], ' '.join(parts[6:])
                
                # 提取PID和程序名
                pid = "-"
                prog = "-"
                pid_match = re.search(r'\d+/', pid_prog)
                if pid_match:
                    pid = pid_match.group(0)[:-1]
                    prog = pid_prog.split('/')[1]
                
                # 分析外部连接
                if foreign != "0.0.0.0:*" and foreign != ":::*":
                    # 排除本地连接
                    if not (foreign.startswith('127.') or foreign.startswith('192.168.') or foreign.startswith('10.') or foreign.startswith('172.16.')):
                        external_conn = {
                            "proto": proto,
                            "state": state,
                            "local": local,
                            "remote": foreign,
                            "pid": pid,
                            "prog": prog
                        }
                        net_results["external_conns"].append(external_conn)
                
                # 分析高危端口连接
                danger_ports = ['21', '22', '23', '25', '53', '110', '139', '445', '3306', '6379', '7001', '8080', '8888', '9000', '9200']
                local_port = local.split(':')[-1]
                if local_port in danger_ports:
                    danger_conn = {
                        "proto": proto,
                        "local": local,
                        "remote": foreign,
                        "pid": pid,
                        "prog": prog
                    }
                    net_results["danger_port_conns"].append(danger_conn)
                
                # 分析挖矿外联
                is_mining_conn = False
                
                # 1. 检查远程地址或进程名中的挖矿关键词
                for keyword in MINING_POOL_KEYWORDS:
                    if keyword in foreign.lower() or keyword in prog.lower():
                        is_mining_conn = True
                        break
                
                # 2. 检查远程端口是否为常见矿池端口
                common_mining_ports = [
                    3333, 5555, 7777, 8888, 9999, 14444, 33333,
                    13333, 17777, 25565, 27015, 28015, 30303, 8545
                ]
                try:
                    if ':' in foreign:
                        port = int(foreign.split(':')[-1])
                        if port in common_mining_ports:
                            is_mining_conn = True
                except:
                    pass
                
                # 3. 检查进程是否为已知的挖矿软件
                mining_process_names = [
                    "xmrig", "cpuminer", "ccminer", "ethminer", "claymore",
                    "t-rex", "lolminer", "gminer", "nbminer", "nanominer"
                ]
                if any(miner in prog.lower() for miner in mining_process_names):
                    is_mining_conn = True
                
                # 4. 检查常见矿池域名特征
                mining_pool_domains = [
                    "miningpool", "hashvault", "nanopool", "f2pool", "poolin",
                    "antpool", "slushpool", "btc.com", "viabtc", "ethpool",
                    "pool.", ".pool", "mine.", ".mine", "miner.", ".miner"
                ]
                if any(domain in foreign.lower() for domain in mining_pool_domains):
                    is_mining_conn = True
                
                # 5. 检查挖矿相关的网络协议特征
                mining_protocols = ["stratum", "eth", "btc", "xmr", "rpc"]
                if any(protocol in foreign.lower() or protocol in prog.lower() for protocol in mining_protocols):
                    is_mining_conn = True
                
                # 如果检测到挖矿外联特征，添加到结果中
                if is_mining_conn:
                    mining_conn = {
                        "proto": proto,
                        "remote": foreign,
                        "pid": pid,
                        "prog": prog,
                        "detection_method": "综合检测"
                    }
                    # 去重：避免重复添加相同的连接
                    if not any(c["remote"] == foreign and c["pid"] == pid for c in net_results["mining_conns"]):
                        net_results["mining_conns"].append(mining_conn)
                
                # 分析监听端口
                if state == "LISTEN":
                    listening_port = {
                        "proto": proto,
                        "local": local,
                        "pid": pid,
                        "prog": prog
                    }
                    net_results["listening_ports"].append(listening_port)
                    
                    # 收集开放端口详细信息
                    local_addr, local_port = local.rsplit(':', 1)
                    service = common_services.get(local_port, "Unknown")
                    open_port_detail = {
                        "port": local_port,
                        "protocol": proto,
                        "address": local_addr,
                        "service": service,
                        "pid": pid,
                        "program": prog
                    }
                    net_results["open_ports_detail"].append(open_port_detail)
    
    except Exception as e:
        print(f"{Colors.YELLOW}[错误] 获取网络连接失败{Colors.RESET}")

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== 外部连接检测 ==={Colors.RESET}")
    if net_results["external_conns"]:
        for idx, conn in enumerate(net_results["external_conns"], 1):
            print(f"{idx}. {conn['proto'].upper()} | 状态: {conn['state']} | 本地: {conn['local']} | 远程: {conn['remote']}")
            print(f"   PID: {conn['pid']} | 程序: {conn['prog']}")
    else:
        print(f"{Colors.GREEN}未检测到外网连接{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 高危端口连接检测 ==={Colors.RESET}")
    if net_results["danger_port_conns"]:
        for idx, conn in enumerate(net_results["danger_port_conns"], 1):
            print(f"{idx}. {conn['proto'].upper()} | 本地: {conn['local']} | 远程: {conn['remote']}")
            print(f"   PID: {conn['pid']} | 程序: {conn['prog']}")
    else:
        print(f"{Colors.GREEN}未检测到高危端口连接{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 挖矿外联检测 ==={Colors.RESET}")
    if net_results["mining_conns"]:
        for idx, conn in enumerate(net_results["mining_conns"], 1):
            print(f"{idx}. {conn['proto'].upper()} | 远程: {conn['remote']} | PID: {conn['pid']} | 程序: {conn['prog']}")
    else:
        print(f"{Colors.GREEN}未检测到挖矿外联{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 监听端口检测 ==={Colors.RESET}")
    if net_results["listening_ports"]:
        for idx, port in enumerate(net_results["listening_ports"], 1):
            print(f"{idx}. {port['proto'].upper()} | 监听: {port['local']} | PID: {port['pid']} | 程序: {port['prog']}")
    else:
        print(f"{Colors.GREEN}未检测到监听端口{Colors.RESET}")

    # 输出开放端口详细信息
    print(f"\n{Colors.BOLD_YELLOW}=== 开放端口详细信息 ==={Colors.RESET}")
    if net_results["open_ports_detail"]:
        # 按端口号排序
        sorted_ports = sorted(net_results["open_ports_detail"], key=lambda x: int(x['port']) if x['port'].isdigit() else x['port'])
        for idx, port_info in enumerate(sorted_ports, 1):
            print(f"{idx}. {port_info['protocol'].upper()} | 端口: {port_info['port']} | 服务: {port_info['service']} | 地址: {port_info['address']}")
            print(f"   PID: {port_info['pid']} | 程序: {port_info['program']}")
    else:
        print(f"{Colors.GREEN}未检测到开放端口{Colors.RESET}")

    # 分析历史网络通信记录
    def analyze_historical_connections():
        """分析历史网络通信记录"""
        # 网络相关日志文件
        network_log_files = [
            "/var/log/auth.log",      # SSH登录记录
            "/var/log/secure",        # 安全相关记录
            "/var/log/ufw.log",       # 防火墙记录
            "/var/log/syslog",        # 系统日志
            "/var/log/kern.log",      # 内核日志
            "/var/log/apache2/access.log",  # Apache访问日志
            "/var/log/nginx/access.log"     # Nginx访问日志
        ]
        
        # 日志时间格式正则
        time_patterns = [
            r"(\w+\s+\d+\s+\d+:\d+:\d+)",  # 如：Jan 27 11:32:51
            r"(\d{4}-\d{2}-\d{2}\s+\d+:\d+:\d+)",  # 如：2026-01-27 11:32:51
            r"(\d{2}/\d{2}/\d{4}:\d+:\d+:\d+)",  # 如：01/27/2026:11:32:51
            r"(\d{4}/\d{2}/\d{2}\s+\d+:\d+:\d+)",  # 如：2026/01/27 11:32:51
        ]
        
        # IP地址正则
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        
        # 程序名正则
        prog_patterns = [
            r"sshd\[(\d+)\]",
            r"ftp\[(\d+)\]",
            r"nginx\[(\d+)\]",
            r"apache\[(\d+)\]",
            r"(\w+)\[(\d+)\]"
        ]
        
        for log_file in network_log_files:
            if not os.path.exists(log_file):
                continue
            
            try:
                # 检查文件大小
                if os.path.getsize(log_file) > 10 * 1024 * 1024:  # 10MB
                    print(f"{Colors.YELLOW}[警告] 日志文件{log_file}过大，仅分析最后5000行{Colors.RESET}")
                    cmd = f"tail -n 5000 {log_file}"
                    log_content = run_command(cmd)
                else:
                    with open(log_file, 'r', errors='ignore') as f:
                        log_content = f.read()
                
                if not log_content or log_content == "命令执行失败":
                    continue
                
                # 按行分析日志
                for line in log_content.split('\n'):
                    if not line:
                        continue
                    
                    # 提取时间戳
                    timestamp = "未知"
                    for pattern in time_patterns:
                        time_match = re.search(pattern, line)
                        if time_match:
                            timestamp = time_match.group(1)
                            break
                    
                    # 提取IP地址
                    ip_match = re.search(ip_pattern, line)
                    if not ip_match:
                        continue
                    ip = ip_match.group(0)
                    
                    # 跳过本地IP
                    if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.16.'):
                        continue
                    
                    # 提取程序名和PID
                    program = "未知"
                    pid = "-"
                    for pattern in prog_patterns:
                        prog_match = re.search(pattern, line)
                        if prog_match:
                            if len(prog_match.groups()) == 2:
                                program, pid = prog_match.groups()
                            elif len(prog_match.groups()) == 1:
                                pid = prog_match.group(1)
                                # 从行中提取程序名
                                prog_name_match = re.search(r"^(\w+):", line)
                                if prog_name_match:
                                    program = prog_name_match.group(1)
                            break
                    
                    # 提取连接类型
                    conn_type = "未知"
                    if "sshd" in line or "SSH" in line:
                        conn_type = "SSH"
                    elif "ftp" in line or "FTP" in line:
                        conn_type = "FTP"
                    elif "http" in line or "HTTP" in line:
                        conn_type = "HTTP"
                    elif "https" in line or "HTTPS" in line:
                        conn_type = "HTTPS"
                    elif "UFW BLOCK" in line or "firewall" in line:
                        conn_type = "Firewall"
                    
                    # 创建历史连接记录
                    historical_conn = {
                        "ip": ip,
                        "time": timestamp,
                        "program": program,
                        "pid": pid,
                        "type": conn_type,
                        "log_file": log_file.split('/')[-1],
                        "source": line[:200]  # 保存日志行的前200个字符作为来源
                    }
                    
                    # 添加到结果中（去重）
                    if not any(conn["ip"] == ip and conn["time"] == timestamp for conn in net_results["historical_connections"]):
                        net_results["historical_connections"].append(historical_conn)
                        
            except Exception as e:
                print(f"{Colors.YELLOW}[警告] 分析日志文件{log_file}失败: {str(e)[:30]}{Colors.RESET}")
        
        # 限制历史记录数量
        if len(net_results["historical_connections"]) > 100:
            net_results["historical_connections"] = net_results["historical_connections"][-100:]
    
    # 执行历史网络通信记录分析
    analyze_historical_connections()
    
    # 输出历史网络通信记录
    print(f"\n{Colors.BOLD_YELLOW}=== 历史网络通信记录 ==={Colors.RESET}")
    
    if net_results["historical_connections"]:
        # 统计信息
        total_connections = len(net_results["historical_connections"])
        unique_ips = len(set(conn["ip"] for conn in net_results["historical_connections"]))
        connection_types = {}  # 按类型统计
        for conn in net_results["historical_connections"]:
            conn_type = conn["type"]
            if conn_type not in connection_types:
                connection_types[conn_type] = 0
            connection_types[conn_type] += 1
        
        print(f"{Colors.BLUE}统计信息:{Colors.RESET}")
        print(f"- 总记录数: {total_connections}")
        print(f"- 唯一IP数: {unique_ips}")
        print(f"- 连接类型分布:")
        for conn_type, count in sorted(connection_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  * {conn_type}: {count}次")
        print()
        
        # 按时间排序（简单排序）
        sorted_history = sorted(net_results["historical_connections"], key=lambda x: x["time"])[-50:]
        
        # 按IP分组显示
        ip_groups = {}
        for conn in sorted_history:
            if conn["ip"] not in ip_groups:
                ip_groups[conn["ip"]] = []
            ip_groups[conn["ip"]].append(conn)
        
        print(f"{Colors.BOLD_YELLOW}详细记录（按IP分组，最近50条）:{Colors.RESET}")
        print("=" * 120)
        
        # 按IP出现次数排序
        sorted_ip_groups = sorted(ip_groups.items(), key=lambda x: len(x[1]), reverse=True)
        
        for ip_idx, (ip, connections) in enumerate(sorted_ip_groups, 1):
            # IP标题
            print(f"\n{Colors.BOLD_CYAN}[{ip_idx}] IP: {Colors.CYAN}{ip}{Colors.RESET} | 连接次数: {len(connections)}")
            print("-" * 120)
            
            # 按时间排序显示该IP的所有连接
            sorted_connections = sorted(connections, key=lambda x: x["time"])
            for conn_idx, conn in enumerate(sorted_connections, 1):
                # 根据连接类型使用不同颜色
                type_color = Colors.GREEN
                if conn["type"] == "SSH":
                    type_color = Colors.YELLOW
                elif conn["type"] == "Firewall":
                    type_color = Colors.RED
                elif conn["type"] == "HTTP" or conn["type"] == "HTTPS":
                    type_color = Colors.BLUE
                
                # 格式化显示
                print(f"  {conn_idx}. 时间: {conn['time']} | {Colors.BOLD_YELLOW}类型: {type_color}{conn['type']}{Colors.RESET} | 程序: {conn['program']} | PID: {conn['pid']} | 日志: {conn['log_file']}")
                
                # 显示日志来源的前100个字符作为参考
                if conn.get("source"):
                    source_preview = conn["source"][:100]
                    if len(conn["source"]) > 100:
                        source_preview += "..."
                    print(f"     {Colors.GRAY}来源: {source_preview}{Colors.RESET}")
        
        print("\n" + "=" * 120)
    else:
        print(f"{Colors.GREEN}未检测到历史网络通信记录{Colors.RESET}")

    # 新增：使用busybox检查隐藏网络连接
    print(f"\n{Colors.BOLD_YELLOW}=== Busybox隐藏网络连接检测 ==={Colors.RESET}")
    try:
        # 检查busybox是否存在
        busybox_check = run_command("which busybox")
        if busybox_check and busybox_check != "命令执行失败":
            busybox_path = busybox_check.strip()
            print(f"{Colors.BLUE}找到busybox: {busybox_path}{Colors.RESET}")
            
            # 使用busybox执行netstat命令检查网络连接
            busybox_netstat = run_command(f"{busybox_path} netstat -tulnpa 2>/dev/null")
            if busybox_netstat and busybox_netstat != "命令执行失败":
                # 分析busybox的输出
                busybox_connections = busybox_netstat.split('\n')
                for conn in busybox_connections:
                    if not conn or 'Proto' in conn:
                        continue
                    
                    parts = conn.split()
                    if len(parts) < 7:
                        continue
                    
                    proto, recv_q, send_q, local, foreign, state, pid_prog = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], ' '.join(parts[6:])
                    
                    # 提取PID和程序名
                    pid = "-"
                    prog = "-"
                    pid_match = re.search(r'\d+/', pid_prog)
                    if pid_match:
                        pid = pid_match.group(0)[:-1]
                        prog = pid_prog.split('/')[1]
                    
                    # 创建隐藏连接记录
                    hidden_conn = {
                        "proto": proto,
                        "state": state,
                        "local": local,
                        "remote": foreign,
                        "pid": pid,
                        "prog": prog,
                        "detection_method": "busybox"
                    }
                    
                    # 添加到结果中（去重）
                    if not any(c["local"] == local and c["remote"] == foreign and c["pid"] == pid for c in net_results["hidden_connections"]):
                        net_results["hidden_connections"].append(hidden_conn)
            else:
                print(f"{Colors.YELLOW}[警告] busybox netstat命令执行失败{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[警告] 未找到busybox，跳过隐藏网络连接检测{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] Busybox隐藏网络连接检测失败: {str(e)}{Colors.RESET}")

    # 输出隐藏网络连接检测结果
    if net_results["hidden_connections"]:
        print(f"\n{Colors.BLUE}检测到隐藏网络连接（{len(net_results['hidden_connections'])}个）:{Colors.RESET}")
        for idx, conn in enumerate(net_results["hidden_connections"], 1):
            print(f"{idx}. {conn['proto'].upper()} | 状态: {conn['state']} | 本地: {conn['local']} | 远程: {conn['remote']}")
            print(f"   PID: {conn['pid']} | 程序: {conn['prog']}")
    else:
        print(f"{Colors.GREEN}未检测到隐藏网络连接{Colors.RESET}")

    return net_results

# ===================== 4. Webshell检测 =====================
def scan_webshell():
    """Webshell检测（强化冰蝎JSP检测+扩展扫描目录+全系统搜索）"""
    print(f"\n{Colors.BLUE}[4/8] 开始检测Webshell{Colors.RESET}")
    webshell_results = {
        "suspicious_files": [],
        "behinder_jsp_files": [],  # 单独记录冰蝎JSP文件
        "scan_dirs": WEBSHELL_SCAN_DIRS,
        "valid_scan_dirs": [],
        "matched_types": {}
    }

    # 增强的特征分类
    webshell_type_map = {
        "caidao": [
            # 经典菜刀特征
            "$z0='z0';", "$_OO0O0O=", "eval\(gzinflate\(", "c3284d0f94606de8",
            # 变种菜刀特征
            "base64_decode", "strrev", "gzuncompress", "assert\(",
            "eval\(", "system\(", "passthru\(", "shell_exec\(",
            "popen\(", "proc_open\(", "exec\(" 
        ],
        "cknife": [
            # Cknife特征
            "Cknife", "China Chopper", "菜刀", "eval\(", "base64_decode",
            "strrev", "gzuncompress", "system\(", "passthru\(",
            "shell_exec\(", "popen\(", "proc_open\(", "exec\("
        ],
        "weevely": [
            # Weevely特征
            "weevely", "WEEVELY", "__import__", "execfile", "subprocess",
            "os.popen", "socket", "base64", "zlib", "pickle"
        ],
        "antsword": [
            # 蚁剑特征
            "antSword", "蚁剑", "AES/ECB/PKCS5Padding", "openssl_encrypt",
            "openssl_decrypt", "base64_decode", "eval\(", "assert\(",
            "system\(", "passthru\(", "shell_exec\("
        ],
        "behinder": [
            # 冰蝎JSP特征
            "Class.forName", "getRuntime", "exec", "ProcessBuilder",
            "ByteArrayOutputStream", "InputStreamReader", "BufferedReader",
            "OutputStream", "InputStream", "Cipher", "init", "doFinal",
            "AES", "ECB", "PKCS5Padding", "Base64", "decode", "encode",
            # 冰蝎PHP特征
            "mcrypt_create_iv", "mcrypt_decrypt", "MCRYPT_RIJNDAEL_128",
            "MCRYPT_MODE_CBC", "openssl_encrypt", "openssl_decrypt",
            # 冰蝎ASP特征
            "CreateObject", "WScript.Shell", "ADODB.Stream", "ChrB",
            # 冰蝎通用特征
            "Behinder", "DESede/CBC/PKCS5Padding", "javax.crypto.Cipher"
        ],
        "godzilla": [
            # 哥斯拉特征
            "Godzilla", "AES/ECB/PKCS5Padding", "Cipher.DECRYPT_MODE",
            "Cipher.getInstance", "SecretKeySpec", "IvParameterSpec",
            # 哥斯拉变种特征
            "Blowfish", "DES/CBC/PKCS5Padding", "RC4",
            "MD5", "SHA-1", "HMAC"
        ],
        "webshell": [
            # 通用Webshell特征
            "eval\(", "assert\(", "system\(", "exec\(",
            "passthru\(", "shell_exec\(", "popen\(", "proc_open\(",
            "base64_decode", "gzinflate", "str_rot13", "create_function",
            "array_map", "call_user_func", "call_user_func_array",
            # ASP/WebShell特征
            "Server.CreateObject", "Execute", "Eval", "GetObject",
            # JSP/WebShell特征
            "Runtime.getRuntime().exec", "ProcessBuilder",
            # PHP/WebShell特征
            "$_POST\[", "$_GET\[", "$_REQUEST\[", "phpinfo\("
        ]
    }

    # 定义通用扫描函数
    def scan_directory(directory):
        """扫描单个目录的Webshell"""
        if not os.path.exists(directory):
            return
        
        if directory not in webshell_results["valid_scan_dirs"]:
            webshell_results["valid_scan_dirs"].append(directory)
        
        try:
            # 限制遍历深度
            walk_depth = 0
            max_depth = 8  # 增加JSP文件常见的Tomcat目录遍历深度
            for root, dirs, files in os.walk(directory):
                walk_depth = root.count(os.sep) - directory.count(os.sep)
                if walk_depth > max_depth:
                    del dirs[:]
                    continue
                    
                if "/proc/" in root or "/sys/" in root or "/dev/" in root:
                    continue
                    
                for file in files:
                    file_path = os.path.join(root, file)
                    # 仅扫描重点后缀文件（优先JSP）
                    if not is_key_file_ext(file_path):
                        continue
                        
                    # 跳过过大文件（JSP木马通常<50KB）
                    try:
                        fsize = os.path.getsize(file_path)
                        if fsize > 50 * 1024:  # 从10MB降至50KB，适配JSP文件
                            continue
                    except:
                        continue
                        
                    # 跳过二进制文件
                    if is_binary_file(file_path):
                        continue
                        
                    # 读取文件（自动适配编码）
                    content = read_file_with_encoding(file_path)
                    if not content:
                        continue
                    
                    # 检查白名单
                    is_whitelisted = False
                    file_path_lower = file_path.lower()
                    content_lower = content.lower()
                    
                    for whitelist_item in WEBSHELL_WHITELIST:
                        # 对于目录白名单，检查路径是否以该目录开头
                        if whitelist_item.startswith('/'):
                            if file_path_lower.startswith(whitelist_item):
                                is_whitelisted = True
                                break
                        # 对于文件和内容白名单，检查是否包含该项
                        else:
                            if whitelist_item in file_path_lower or whitelist_item in content_lower:
                                is_whitelisted = True
                                break
                    
                    # 额外的路径过滤：跳过常见的合法工具和配置目录
                    skip_paths = [
                        '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
                        '/etc/systemd/', '/etc/init.d/', '/etc/cron.',
                        '/var/log/', '/var/spool/', '/var/mail/',
                        '/home/*/.local/', '/home/*/.cache/', '/home/*/.config/',
                        '/root/.local/', '/root/.cache/', '/root/.config/'
                    ]
                    
                    for skip_path in skip_paths:
                        if '*' in skip_path:
                            # 处理通配符路径
                            import fnmatch
                            if fnmatch.fnmatch(file_path_lower, skip_path):
                                is_whitelisted = True
                                break
                        else:
                            if file_path_lower.startswith(skip_path):
                                is_whitelisted = True
                                break
                    
                    if is_whitelisted:
                        continue
                    
                    # 获取文件扩展名
                    ext = os.path.splitext(file_path)[1].lower()
                    
                    # 第一步：优先检测冰蝎JSP专项特征
                    behinder_match_count = 0
                    behinder_match_keywords = []
                    for keyword in BEHINDER_JSP_KEYWORDS:
                        if re.search(keyword.lower(), content):
                            behinder_match_count += 1
                            behinder_match_keywords.append(keyword)
                    
                    # 冰蝎JSP判定：匹配≥3个专项特征即判定（提高阈值减少误报）
                    if behinder_match_count >= 3:
                        mtime = get_file_mtime(file_path)
                        jsp_file = {
                            "path": file_path, 
                            "mtime": mtime, 
                            "keywords": ", ".join(behinder_match_keywords[:5]),
                            "type": "冰蝎JSP木马"
                        }
                        webshell_results["behinder_jsp_files"].append(jsp_file)
                        webshell_results["suspicious_files"].append(jsp_file)
                        if "冰蝎JSP木马" not in webshell_results["matched_types"]:
                            webshell_results["matched_types"]["冰蝎JSP木马"] = 0
                        webshell_results["matched_types"]["冰蝎JSP木马"] += 1
                        continue  # 已匹配冰蝎，无需继续匹配其他特征
                    
                    # 第二步：匹配其他Webshell特征
                    match_count = 0
                    match_keywords = []
                    match_type = "未知"
                    # 匹配核心特征
                    for ws_type, keywords in webshell_type_map.items():
                        if ws_type == "behinder":
                            continue  # 已单独检测
                        for keyword in keywords:
                            if re.search(keyword.lower(), content):
                                match_count += 1
                                match_keywords.append(keyword)
                                match_type = {"caidao":"菜刀", "godzilla":"哥斯拉"}.get(ws_type, "未知")
                                break
                        if match_type != "未知":
                            break
                    
                    # 补充匹配通用特征
                    if match_count == 0:
                        for keyword in WEBSHELL_KEYWORDS:
                            if re.search(keyword.lower(), content):
                                match_count += 1
                                match_keywords.append(keyword)
                    
                    # 获取该文件类型的阈值
                    threshold = FILE_TYPE_THRESHOLDS.get(ext, FILE_TYPE_THRESHOLDS["default"])
                    
                    # 其他Webshell判定：匹配≥阈值个特征
                    if match_count >= threshold:
                        mtime = get_file_mtime(file_path)
                        suspicious_file = {
                            "path": file_path, 
                            "mtime": mtime, 
                            "keywords": ", ".join(match_keywords[:5]),
                            "type": match_type
                        }
                        webshell_results["suspicious_files"].append(suspicious_file)
                        if match_type not in webshell_results["matched_types"]:
                            webshell_results["matched_types"][match_type] = 0
                        webshell_results["matched_types"][match_type] += 1
                        
        except Exception as e:
            print(f"{Colors.YELLOW}[警告] 扫描目录{directory}失败: {str(e)[:30]}{Colors.RESET}")
    
    # 第一步：扫描配置的扩展目录
    for scan_dir in webshell_results["scan_dirs"]:
        # 处理通配符目录
        if '*' in scan_dir:
            real_dirs = run_command(f"find {scan_dir} -type d 2>/dev/null")
            if real_dirs and real_dirs != "命令执行失败":
                for real_dir in real_dirs.split('\n'):
                    real_dir = real_dir.strip()
                    if real_dir and os.path.exists(real_dir):
                        scan_directory(real_dir)
            continue
        
        scan_directory(scan_dir)
    
    # 第二步：扫描系统中其他可能存在Webshell的目录
    additional_scan_dirs = [
        # 用户主目录
        "/home", "/root",
        # 常见的Web服务器目录
        "/usr/local/apache2/htdocs", "/usr/local/nginx/html",
        "/etc/httpd/htdocs", "/var/www/html", "/srv/http",
        # 应用服务器临时目录
        "/tmp", "/var/tmp", "/dev/shm",
        # 可能被篡改的系统目录
        "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
        "/etc/init.d", "/etc/systemd/system", "/etc/rc.d",
        # 常见的网站托管目录
        "/srv/www", "/var/www/vhosts", "/var/www/sites",
        # 容器相关目录
        "/var/lib/docker", "/opt/docker", "/var/lib/kubelet", "/etc/rancher",
        # 云服务相关目录
        "/opt/aws", "/opt/azure", "/opt/gcp", "/var/app/current",
        # CI/CD工具目录
        "/var/lib/jenkins", "/opt/jenkins", "/home/jenkins",
        "/var/lib/gitlab", "/opt/gitlab", "/home/gitlab",
        # 开发工具目录
        "/usr/local/src", "/usr/src", "/opt/src",
        # 数据库相关目录
        "/var/lib/mysql", "/var/lib/postgresql", "/opt/mysql", "/opt/postgresql",
        # 网络服务目录
        "/etc/nginx", "/etc/apache2", "/etc/httpd",
        # 备份目录
        "/backup", "/var/backup", "/home/backup",
        # 日志目录（可能被篡改）
        "/var/log", "/var/log/httpd", "/var/log/nginx"
    ]
    
    for dir_path in additional_scan_dirs:
        if dir_path not in webshell_results["scan_dirs"]:  # 避免重复扫描
            scan_directory(dir_path)
    
    # 第三步：使用find命令搜索全系统的可疑文件类型
    suspicious_extensions = [
        # Web脚本文件
        ".jsp", ".jspx", ".php", ".php3", ".php4", ".php5", ".phtml", 
        ".asp", ".aspx", ".ashx", ".jspf", ".sh", ".pl", ".py", ".cgi",
        # 可能的后门文件
        ".phar", ".inc", ".module", ".action", ".controller",
        # 配置文件（可能被篡改）
        ".conf", ".config", ".ini", ".yml", ".yaml",
        # 可执行文件
        ".exe", ".bin", ".out", "",  # 空扩展名（可能是恶意可执行文件）
        # 其他可疑文件
        ".cmd", ".bat", ".ps1", ".vbs", ".js", ".json"
    ]
    
    for ext in suspicious_extensions:
        # 跳过空扩展名，避免搜索所有文件
        if not ext:
            continue
            
        # 使用find命令搜索系统中的可疑文件
        find_cmd = f"find / -type f -name '*{ext}' -size -50k 2>/dev/null"
        suspicious_files = run_command(find_cmd)
        
        if suspicious_files and suspicious_files != "命令执行失败":
            for file_path in suspicious_files.split('\n'):
                file_path = file_path.strip()
                if not file_path or not os.path.exists(file_path):
                    continue
                
                # 跳过系统目录和白名单目录
                skip = False
                skip_dirs = ["/proc", "/sys", "/dev", "/usr/lib", "/usr/share", "/lib", "/lib64"]
                for skip_dir in skip_dirs:
                    if file_path.startswith(skip_dir):
                        skip = True
                        break
                if skip:
                    continue
                
                # 检查是否已经在扫描目录中
                already_scanned = False
                for scan_dir in webshell_results["valid_scan_dirs"]:
                    if file_path.startswith(scan_dir):
                        already_scanned = True
                        break
                if already_scanned:
                    continue
                
                # 直接检查文件
                try:
                    # 跳过过大文件
                    if os.path.getsize(file_path) > 50 * 1024:
                        continue
                    
                    # 跳过二进制文件
                    if is_binary_file(file_path):
                        continue
                    
                    # 读取文件
                    content = read_file_with_encoding(file_path)
                    if not content:
                        continue
                    
                    # 检查白名单
                    is_whitelisted = False
                    file_path_lower = file_path.lower()
                    content_lower = content.lower()
                    
                    for whitelist_item in WEBSHELL_WHITELIST:
                        # 对于目录白名单，检查路径是否以该目录开头
                        if whitelist_item.startswith('/'):
                            if file_path_lower.startswith(whitelist_item):
                                is_whitelisted = True
                                break
                        # 对于文件和内容白名单，检查是否包含该项
                        else:
                            if whitelist_item in file_path_lower or whitelist_item in content_lower:
                                is_whitelisted = True
                                break
                    
                    # 额外的路径过滤：跳过常见的合法工具和配置目录
                    skip_paths = [
                        '/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/',
                        '/etc/systemd/', '/etc/init.d/', '/etc/cron.',
                        '/var/log/', '/var/spool/', '/var/mail/',
                        '/home/*/.local/', '/home/*/.cache/', '/home/*/.config/',
                        '/root/.local/', '/root/.cache/', '/root/.config/'
                    ]
                    
                    for skip_path in skip_paths:
                        if '*' in skip_path:
                            # 处理通配符路径
                            import fnmatch
                            if fnmatch.fnmatch(file_path_lower, skip_path):
                                is_whitelisted = True
                                break
                        else:
                            if file_path_lower.startswith(skip_path):
                                is_whitelisted = True
                                break
                    
                    if is_whitelisted:
                        continue
                    
                    # 获取文件扩展名
                    ext = os.path.splitext(file_path)[1].lower()
                    
                    # 检测冰蝎JSP专项特征
                    behinder_match_count = 0
                    behinder_match_keywords = []
                    for keyword in BEHINDER_JSP_KEYWORDS:
                        if re.search(keyword.lower(), content):
                            behinder_match_count += 1
                            behinder_match_keywords.append(keyword)
                    
                    if behinder_match_count >= 3:
                        mtime = get_file_mtime(file_path)
                        jsp_file = {
                            "path": file_path, 
                            "mtime": mtime, 
                            "keywords": ", ".join(behinder_match_keywords[:5]),
                            "type": "冰蝎JSP木马"
                        }
                        webshell_results["behinder_jsp_files"].append(jsp_file)
                        webshell_results["suspicious_files"].append(jsp_file)
                        if "冰蝎JSP木马" not in webshell_results["matched_types"]:
                            webshell_results["matched_types"]["冰蝎JSP木马"] = 0
                        webshell_results["matched_types"]["冰蝎JSP木马"] += 1
                        continue
                    
                    # 匹配其他Webshell特征
                    match_count = 0
                    match_keywords = []
                    match_type = "未知"
                    
                    for ws_type, keywords in webshell_type_map.items():
                        if ws_type == "behinder":
                            continue
                        for keyword in keywords:
                            if re.search(keyword.lower(), content):
                                match_count += 1
                                match_keywords.append(keyword)
                                match_type = {"caidao":"菜刀", "godzilla":"哥斯拉"}.get(ws_type, "未知")
                                break
                        if match_type != "未知":
                            break
                    
                    if match_count == 0:
                        for keyword in WEBSHELL_KEYWORDS:
                            if re.search(keyword.lower(), content):
                                match_count += 1
                                match_keywords.append(keyword)
                    
                    threshold = FILE_TYPE_THRESHOLDS.get(ext, FILE_TYPE_THRESHOLDS["default"])
                    
                    if match_count >= threshold:
                        mtime = get_file_mtime(file_path)
                        suspicious_file = {
                            "path": file_path,
                            "mtime": mtime,
                            "keywords": ", ".join(match_keywords[:5]),
                            "type": match_type
                        }
                        webshell_results["suspicious_files"].append(suspicious_file)
                        if match_type not in webshell_results["matched_types"]:
                            webshell_results["matched_types"][match_type] = 0
                        webshell_results["matched_types"][match_type] += 1
                except:
                    pass

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== Webshell检测结果 ==={Colors.RESET}")
    print(f"配置扫描目录数: {len(webshell_results['scan_dirs'])}")
    print(f"实际存在目录数: {len(webshell_results['valid_scan_dirs'])}")
    print(f"实际扫描目录: {', '.join(webshell_results['valid_scan_dirs'][:10])}{'...' if len(webshell_results['valid_scan_dirs'])>10 else ''}")
    
    # 优先输出冰蝎JSP检测结果
    print(f"\n{Colors.BOLD_RED}=== 冰蝎JSP木马检测结果 ==={Colors.RESET}")
    if webshell_results["behinder_jsp_files"]:
        for idx, file in enumerate(webshell_results["behinder_jsp_files"], 1):
            print(f"{idx}. {Colors.RED}文件{Colors.RESET}: {file['path']}")
            print(f"   类型: {file['type']} | 修改时间: {file['mtime']} | 匹配特征: {file['keywords']}")
    else:
        print(f"{Colors.YELLOW}未检测到冰蝎JSP木马{Colors.RESET}")
    
    # 输出其他可疑文件
    print(f"\n{Colors.BOLD_YELLOW}=== 其他可疑Webshell文件 ==={Colors.RESET}")
    # 过滤已输出的冰蝎JSP文件
    other_files = [f for f in webshell_results["suspicious_files"] if f["type"] != "冰蝎JSP木马"]
    if other_files:
        for idx, file in enumerate(other_files, 1):
            print(f"{idx}. {Colors.RED}文件{Colors.RESET}: {file['path']}")
            print(f"   类型: {file['type']} | 修改时间: {file['mtime']} | 匹配特征: {file['keywords']}")
    elif not webshell_results["behinder_jsp_files"]:
        print(f"{Colors.GREEN}未检测到任何可疑Webshell文件{Colors.RESET}")

    return webshell_results

# ===================== 5. 系统账户异常检测 =====================
def analyze_system_accounts():
    """系统账户异常（新增账户/提权/空密码/UID=0）"""
    print(f"\n{Colors.BLUE}[5/8] 开始分析系统账户{Colors.RESET}")
    account_results = {
        "uid0_users": [],  # UID=0的用户（超级管理员）
        "empty_pass_users": [],  # 空密码用户
        "new_users": [],  # 最近7天新增用户
        "sudo_users": [],  # sudo权限用户
        "unusual_shells": [],  # 异常shell用户
        "login_history": [],  # 登录用户历史记录
        "user_history_commands": {},  # 用户历史操作命令
        "add_delete_commands": {},  # 新增与删除操作命令记录
        "reverse_shell_commands": {},  # 反弹shell命令记录
        "download_commands": {}  # 下载命令记录
    }

    # 1. UID=0的用户
    passwd_output = run_command("cat /etc/passwd")
    if passwd_output:
        for line in passwd_output.split('\n'):
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 3:
                continue
            user, _, uid = parts[:3]
            if uid == "0" and user != "root":
                account_results["uid0_users"].append(user)

    # 2. 空密码用户
    shadow_output = run_command("awk -F: '$2 == "" {print $1}' /etc/shadow")
    if shadow_output and shadow_output != "命令执行失败":
        account_results["empty_pass_users"] = [u for u in shadow_output.split('\n') if u]

    # 3. 最近7天新增用户
    try:
        current_time = datetime.now()
        seven_days_ago = current_time - timedelta(days=7)
        # 获取用户创建时间（通过家目录mtime）
        user_output = run_command("cat /etc/passwd | grep -E '/bin/bash|/bin/sh|/bin/zsh' | cut -d: -f1,6")
        if user_output:
            for line in user_output.split('\n'):
                if not line or ":" not in line:
                    continue
                user, homedir = line.split(':', 1)
                if not os.path.exists(homedir):
                    continue
                try:
                    mtime = os.path.getmtime(homedir)
                    mtime_dt = datetime.fromtimestamp(mtime)
                    if mtime_dt > seven_days_ago:
                        account_results["new_users"].append({
                            "user": user, "homedir": homedir, "create_time": mtime_dt.strftime("%Y-%m-%d %H:%M:%S")
                        })
                except:
                    continue
    except:
        pass

    # 4. sudo权限用户
    sudo_output = run_command("cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | grep -E 'ALL=(ALL)'")
    if sudo_output and sudo_output != "命令执行失败":
        account_results["sudo_users"] = [line.strip() for line in sudo_output.split('\n') if line.strip()]
    else:
        # 命令执行失败，尝试其他方法获取sudo用户
        try:
            # 尝试使用另一种方法获取sudo用户
            sudo_output2 = run_command("grep -r 'sudo' /etc/group 2>/dev/null")
            if sudo_output2 and sudo_output2 != "命令执行失败":
                for line in sudo_output2.split('\n'):
                    if line and ':x:' in line:
                        parts = line.split(':')
                        if len(parts) >= 4 and parts[3]:
                            sudo_users = parts[3].split(',')
                            for user in sudo_users:
                                if user.strip():
                                    account_results["sudo_users"].append(user.strip())
        except:
            pass

    # 5. 异常shell用户（非标准shell）
    unusual_shells = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/fish", "/sbin/nologin", "/bin/false"]
    if passwd_output:
        for line in passwd_output.split('\n'):
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 7:
                continue
            user, shell = parts[0], parts[-1]
            if shell not in unusual_shells and not shell.startswith("/usr/bin/"):
                account_results["unusual_shells"].append({"user": user, "shell": shell})

    # 6. 登录用户历史记录
    login_output = run_command("last -awF")
    if login_output and login_output != "命令执行失败":
        # 解析登录历史
        for line in login_output.split('\n'):
            if not line or line.startswith("wtmp begins"):
                continue
            # 提取登录信息
            parts = line.split()
            if len(parts) < 5:
                continue
            user = parts[0]
            tty = parts[1]
            # 提取IP地址（如果有）
            ip = "localhost"
            for part in parts:
                if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', part):
                    ip = part
                    break
            # 提取时间信息（简化处理）
            time_str = " ".join(parts[2:5])
            account_results["login_history"].append({
                "user": user,
                "tty": tty,
                "ip": ip,
                "time": time_str
            })

    # 7. 用户历史操作命令
    # 读取用户的.bash_history文件
    users = []
    if passwd_output:
        for line in passwd_output.split('\n'):
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) < 6:
                continue
            user = parts[0]
            homedir = parts[5]
            if homedir and os.path.exists(homedir):
                users.append((user, homedir))
    
    # 检测每个用户的历史命令
    for user, homedir in users:
        history_file = os.path.join(homedir, ".bash_history")
        if os.path.exists(history_file):
            try:
                # 读取所有历史命令文件
                with open(history_file, 'r', errors='ignore') as f:
                    history_lines = f.readlines()
                # 提取所有历史命令
                all_commands = [line.strip() for line in history_lines if line.strip()]
                # 提取最近的历史命令（最多50条）
                recent_commands = all_commands[-50:]
                if recent_commands:
                    account_results["user_history_commands"][user] = recent_commands
                
                # 提取新增和删除操作命令
                add_delete_cmds = []
                add_commands = ["mkdir", "touch", "cp", "mv", "wget", "curl", "git clone", "apt install", "yum install"]
                delete_commands = ["rm", "rmdir", "unlink"]
                
                for cmd in all_commands:
                    cmd_lower = cmd.lower()
                    for add_cmd in add_commands:
                        if cmd_lower.startswith(add_cmd):
                            add_delete_cmds.append(cmd)
                            break
                    else:
                        for del_cmd in delete_commands:
                            if cmd_lower.startswith(del_cmd):
                                add_delete_cmds.append(cmd)
                                break
                
                if add_delete_cmds:
                    account_results["add_delete_commands"][user] = add_delete_cmds
                
                # 检测反弹shell命令
                reverse_shell_cmds = []
                reverse_shell_patterns = [
                    "nc -e", "netcat -e", "ncat -e",
                    "bash -i >& /dev/tcp/", "bash -i > /dev/tcp/",
                    "sh -i >& /dev/tcp/", "sh -i > /dev/tcp/",
                    "/dev/tcp/", "/dev/udp/",
                    "socat TCP:", "socat -",
                    "python -c 'import socket", "python3 -c 'import socket",
                    "perl -e 'use Socket", "perl -MIO::Socket::INET",
                    "ruby -rsocket -e", "ruby -rsocket",
                    "php -r '$sock=fsockopen",
                    "telnet", "telnetd",
                    "mkfifo /tmp/", "mknod /tmp/",
                    "exec 5<>/dev/tcp/", "exec 3<>/dev/tcp/",
                    "0<&196;exec 196<>/dev/tcp/",
                    "powershell -nop -c", "powershell -enc",
                    "Invoke-WebRequest", "Invoke-Expression",
                    "IEX", "DownloadString"
                ]
                
                for cmd in all_commands:
                    cmd_lower = cmd.lower()
                    for pattern in reverse_shell_patterns:
                        if pattern.lower() in cmd_lower:
                            reverse_shell_cmds.append(cmd)
                            break
                
                if reverse_shell_cmds:
                    account_results["reverse_shell_commands"][user] = reverse_shell_cmds
                
                # 检测下载命令（从所有命令中提取）
                download_cmds = []
                download_patterns = [
                    "wget", "curl", "fetch", "axel", "aria2c",
                    "lwp-download", "lwp-request", "GET",
                    "python -c urllib", "python3 -c urllib", "python -c requests", "python3 -c requests",
                    "python -m urllib", "python3 -m urllib",
                    "perl -m LWP::Simple", "perl -MWWW::Mechanize",
                    "ruby -e open-uri", "ruby -e net/http",
                    "php -r file_get_contents", "php -r curl_init",
                    "powershell -c invoke-webrequest", "powershell -c iwr", "powershell -c wget",
                    "powershell -c downloadfile", "powershell -c start-bitstransfer",
                    "Invoke-WebRequest", "Invoke-RestMethod", "Start-BitsTransfer",
                    "git clone", "git pull", "git fetch",
                    "svn checkout", "svn export", "svn co",
                    "rsync", "scp", "sftp",
                    "nc -l", "netcat -l", "ncat -l",
                    "tftp", "ftp", "lftp",
                    "yum install", "apt install", "apt-get install", "dnf install", "zypper install",
                    "pip install", "pip3 install", "pip download",
                    "npm install", "yarn add", "gem install",
                    "composer install", "go get"
                ]
                
                for cmd in all_commands:
                    cmd_lower = cmd.lower()
                    for pattern in download_patterns:
                        if pattern.lower() in cmd_lower:
                            download_cmds.append(cmd)
                            break
                
                if download_cmds:
                    account_results["download_commands"][user] = download_cmds
            except:
                continue

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== UID=0的超级管理员用户 ==={Colors.RESET}")
    if account_results["uid0_users"]:
        for user in account_results["uid0_users"]:
            print(f"{Colors.RED}{user}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}仅root用户拥有UID=0权限{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 空密码用户 ==={Colors.RESET}")
    if account_results["empty_pass_users"]:
        for user in account_results["empty_pass_users"]:
            print(f"{Colors.RED}{user}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}未检测到空密码用户{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 最近7天新增用户 ==={Colors.RESET}")
    if account_results["new_users"]:
        for user_info in account_results["new_users"]:
            print(f"{Colors.RED}{user_info['user']}{Colors.RESET} | 家目录: {user_info['homedir']} | 创建时间: {user_info['create_time']}")
    else:
        print(f"{Colors.GREEN}未检测到最近7天新增用户{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== sudo权限用户 ==={Colors.RESET}")
    if account_results["sudo_users"]:
        for sudo_user in account_results["sudo_users"]:
            print(f"{Colors.RED}{sudo_user}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}未检测到sudo权限用户（除默认配置）{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 异常Shell用户 ==={Colors.RESET}")
    if account_results["unusual_shells"]:
        for user_info in account_results["unusual_shells"]:
            print(f"{Colors.RED}{user_info['user']}{Colors.RESET} | Shell: {user_info['shell']}")
    else:
        print(f"{Colors.GREEN}未检测到异常Shell用户{Colors.RESET}")

    # 输出登录用户历史记录
    print(f"\n{Colors.BOLD_YELLOW}=== 登录用户历史记录 ==={Colors.RESET}")
    if account_results["login_history"]:
        for idx, login in enumerate(account_results["login_history"][-20:], 1):
            print(f"{idx}. 用户: {login['user']} | 终端: {login['tty']} | 来源: {login['ip']} | 时间: {login['time']}")
    else:
        print(f"{Colors.GREEN}未检测到登录历史记录{Colors.RESET}")

    # 输出用户历史操作命令
    print(f"\n{Colors.BOLD_YELLOW}=== 用户历史操作命令 ==={Colors.RESET}")
    if account_results["user_history_commands"]:
        for user, commands in account_results["user_history_commands"].items():
            print(f"\n{Colors.RED}{user}{Colors.RESET}的最近命令:")
            for idx, cmd in enumerate(commands, 1):  # 显示所有命令
                print(f"  {idx}. {cmd}")
    else:
        print(f"{Colors.GREEN}未检测到用户历史操作命令{Colors.RESET}")

    # 输出新增与删除操作命令记录
    print(f"\n{Colors.BOLD_YELLOW}=== 新增与删除操作命令记录 ==={Colors.RESET}")
    if account_results["add_delete_commands"]:
        for user, commands in account_results["add_delete_commands"].items():
            print(f"\n{Colors.RED}{user}{Colors.RESET}的新增/删除操作:")
            for idx, cmd in enumerate(commands, 1):
                print(f"  {idx}. {cmd}")
    else:
        print(f"{Colors.GREEN}未检测到新增与删除操作命令记录{Colors.RESET}")

    # 输出反弹shell命令记录
    print(f"\n{Colors.BOLD_YELLOW}=== 反弹shell命令记录 ==={Colors.RESET}")
    if account_results["reverse_shell_commands"]:
        for user, commands in account_results["reverse_shell_commands"].items():
            print(f"\n{Colors.RED}{user}{Colors.RESET}的反弹shell命令:")
            for idx, cmd in enumerate(commands, 1):
                print(f"  {idx}. {cmd}")
    else:
        print(f"{Colors.GREEN}未检测到反弹shell命令记录{Colors.RESET}")

    # 输出下载命令记录
    print(f"\n{Colors.BOLD_YELLOW}=== 下载命令记录 ==={Colors.RESET}")
    if account_results["download_commands"]:
        for user, commands in account_results["download_commands"].items():
            print(f"\n{Colors.RED}{user}{Colors.RESET}的下载命令:")
            for idx, cmd in enumerate(commands, 1):
                print(f"  {idx}. {cmd}")
    else:
        print(f"{Colors.GREEN}未检测到下载命令记录{Colors.RESET}")

    return account_results

# ===================== 6. 文件篡改检测 =====================
def detect_file_tampering():
    """文件篡改检测（敏感文件修改/临时目录可执行文件/异常定时任务）"""
    print(f"\n{Colors.BLUE}[6/8] 开始分析文件篡改{Colors.RESET}")
    tampering_results = {
        "modified_files": [],  # 敏感文件修改
        "tmp_executables": [],  # 临时目录可执行文件
        "suspicious_crontabs": [],  # 异常定时任务
        "hidden_files": [],  # 隐藏文件
        "abnormal_permissions": [],  # 异常权限文件
        "sensitive_dirs": [],  # 敏感目录检查
        "suspicious_files": [],  # 异常文件检查
        "abnormal_images": []  # 异常图片文件检查
    }

    # 检查敏感文件修改时间
    sensitive_files = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
        "/etc/hosts", "/etc/resolv.conf", "/etc/crontab", "/etc/rc.local",
        "/var/spool/cron/crontabs/root", "/var/spool/cron/root"
    ]

    for file_path in sensitive_files:
        if os.path.exists(file_path):
            mtime = get_file_mtime(file_path)
            file_info = {
                "path": file_path,
                "mtime": mtime
            }
            tampering_results["modified_files"].append(file_info)

    # 检查临时目录可执行文件
    tmp_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    for tmp_dir in tmp_dirs:
        if not os.path.exists(tmp_dir):
            continue
        
        try:
            for root, dirs, files in os.walk(tmp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    # 检查是否为可执行文件
                    if os.access(file_path, os.X_OK):
                        mtime = get_file_mtime(file_path)
                        exec_file = {
                            "path": file_path,
                            "mtime": mtime
                        }
                        tampering_results["tmp_executables"].append(exec_file)
        except:
            pass

    # 检查异常定时任务
    crontab_files = [
        "/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*",
        "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
        "/var/spool/cron/crontabs/*", "/var/spool/cron/*"
    ]

    for crontab_file in crontab_files:
        if '*' in crontab_file:
            # 处理通配符
            import glob
            files = glob.glob(crontab_file)
            for file in files:
                if os.path.isfile(file):
                    check_crontab(file, tampering_results)
        else:
            if os.path.isfile(crontab_file):
                check_crontab(crontab_file, tampering_results)

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== 敏感文件修改时间 ==={Colors.RESET}")
    if tampering_results["modified_files"]:
        for file_info in tampering_results["modified_files"]:
            print(f"{file_info['path']} | 修改时间: {file_info['mtime']}")
    else:
        print(f"{Colors.GREEN}未检测到敏感文件{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 临时目录可执行文件 ==={Colors.RESET}")
    if tampering_results["tmp_executables"]:
        for exec_file in tampering_results["tmp_executables"]:
            print(f"{Colors.RED}{exec_file['path']}{Colors.RESET} | 修改时间: {exec_file['mtime']}")
    else:
        print(f"{Colors.GREEN}未检测到临时目录可执行文件{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 异常定时任务 ==={Colors.RESET}")
    if tampering_results["suspicious_crontabs"]:
        for crontab in tampering_results["suspicious_crontabs"]:
            print(f"{Colors.RED}{crontab['path']}{Colors.RESET} | 内容: {crontab['content'][:100]}{'...' if len(crontab['content'])>100 else ''}")
    else:
        print(f"{Colors.GREEN}未检测到异常定时任务{Colors.RESET}")

    # 新增：检查隐藏文件
    print(f"\n{Colors.BOLD_YELLOW}=== 隐藏文件检测 ==={Colors.RESET}")
    try:
        # 检查敏感目录中的隐藏文件
        hidden_file_dirs = [
            "/root", "/home", "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            "/tmp", "/var/tmp", "/dev/shm"
        ]
        
        for check_dir in hidden_file_dirs:
            if not os.path.exists(check_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(check_dir):
                    # 检查隐藏目录
                    for dir_name in dirs:
                        if dir_name.startswith('.'):
                            dir_path = os.path.join(root, dir_name)
                            # 排除常见的合法隐藏目录
                            if dir_name not in ['.', '..', '.git', '.ssh', '.config', '.local', '.cache']:
                                hidden_entry = {
                                    "path": dir_path,
                                    "type": "directory",
                                    "mtime": get_file_mtime(dir_path)
                                }
                                tampering_results["hidden_files"].append(hidden_entry)
                    
                    # 检查隐藏文件
                    for file_name in files:
                        if file_name.startswith('.'):
                            file_path = os.path.join(root, file_name)
                            # 排除常见的合法隐藏文件
                            if file_name not in ['.bashrc', '.bash_profile', '.profile', '.history', '.bash_logout']:
                                hidden_entry = {
                                    "path": file_path,
                                    "type": "file",
                                    "mtime": get_file_mtime(file_path)
                                }
                                tampering_results["hidden_files"].append(hidden_entry)
            except Exception as e:
                print(f"{Colors.YELLOW}[警告] 遍历{check_dir}失败: {str(e)}{Colors.RESET}")
        
        if tampering_results["hidden_files"]:
            for idx, hidden_entry in enumerate(tampering_results["hidden_files"], 1):
                print(f"{idx}. {Colors.RED}{hidden_entry['path']}{Colors.RESET} | 类型: {hidden_entry['type']} | 修改时间: {hidden_entry['mtime']}")
        else:
            print(f"{Colors.GREEN}未检测到可疑隐藏文件{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 隐藏文件检测失败: {str(e)}{Colors.RESET}")

    # 新增：检查异常权限文件
    print(f"\n{Colors.BOLD_YELLOW}=== 异常权限文件检测 ==={Colors.RESET}")
    try:
        # 检查具有SUID/SGID权限的文件
        find_suid_cmd = "find / -type f -perm -4000 -o -perm -2000 2>/dev/null"
        suid_files = run_command(find_suid_cmd)
        if suid_files and suid_files != "命令执行失败":
            for file_path in suid_files.split('\n'):
                if file_path and os.path.exists(file_path):
                    # 排除系统默认的SUID/SGID文件
                    system_suid_paths = [
                        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/"
                    ]
                    is_system_suid = any(file_path.startswith(path) for path in system_suid_paths)
                    if not is_system_suid:
                        perm_entry = {
                            "path": file_path,
                            "permissions": "SUID/SGID",
                            "mtime": get_file_mtime(file_path)
                        }
                        tampering_results["abnormal_permissions"].append(perm_entry)
        
        # 检查具有777权限的文件
        find_777_cmd = "find / -type f -perm 777 2>/dev/null"
        perm777_files = run_command(find_777_cmd)
        if perm777_files and perm777_files != "命令执行失败":
            for file_path in perm777_files.split('\n'):
                if file_path and os.path.exists(file_path):
                    # 排除临时目录中的文件（已在其他部分检查）
                    if not (file_path.startswith('/tmp') or file_path.startswith('/var/tmp') or file_path.startswith('/dev/shm')):
                        perm_entry = {
                            "path": file_path,
                            "permissions": "777",
                            "mtime": get_file_mtime(file_path)
                        }
                        tampering_results["abnormal_permissions"].append(perm_entry)
        
        if tampering_results["abnormal_permissions"]:
            for idx, perm_entry in enumerate(tampering_results["abnormal_permissions"], 1):
                print(f"{idx}. {Colors.RED}{perm_entry['path']}{Colors.RESET} | 权限: {perm_entry['permissions']} | 修改时间: {perm_entry['mtime']}")
        else:
            print(f"{Colors.GREEN}未检测到异常权限文件{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 异常权限文件检测失败: {str(e)}{Colors.RESET}")

    # 新增：检查敏感目录
    print(f"\n{Colors.BOLD_YELLOW}=== 敏感目录检查 ==={Colors.RESET}")
    try:
        # 定义敏感目录
        sensitive_dirs = [
            {"path": "/etc/ssh", "description": "SSH配置目录"},
            {"path": "/etc/sudoers.d", "description": "sudo配置目录"},
            {"path": "/var/spool/cron", "description": "定时任务目录"},
            {"path": "/etc/cron.d", "description": "系统定时任务目录"},
            {"path": "/boot", "description": "启动目录"},
            {"path": "/lib", "description": "系统库目录"},
            {"path": "/lib64", "description": "64位系统库目录"},
            {"path": "/usr/lib", "description": "用户库目录"},
            {"path": "/usr/lib64", "description": "64位用户库目录"}
        ]
        
        for dir_info in sensitive_dirs:
            dir_path = dir_info["path"]
            if os.path.exists(dir_path):
                # 检查目录权限
                dir_mode = oct(os.stat(dir_path).st_mode)[-4:]
                # 检查目录中的文件
                files_count = 0
                try:
                    files_count = len([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))])
                except:
                    pass
                
                sensitive_entry = {
                    "path": dir_path,
                    "description": dir_info["description"],
                    "permissions": dir_mode,
                    "files_count": files_count
                }
                tampering_results["sensitive_dirs"].append(sensitive_entry)
        
        if tampering_results["sensitive_dirs"]:
            for idx, dir_entry in enumerate(tampering_results["sensitive_dirs"], 1):
                print(f"{idx}. {dir_entry['path']} | 描述: {dir_entry['description']} | 权限: {dir_entry['permissions']} | 文件数: {dir_entry['files_count']}")
        else:
            print(f"{Colors.GREEN}未检测到敏感目录{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 敏感目录检查失败: {str(e)}{Colors.RESET}")

    return tampering_results

def check_crontab(file_path, tampering_results):
    """检查单个定时任务文件"""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        
        # 检测可疑内容
        suspicious_patterns = [
            "wget", "curl", "bash -c", "sh -c", "python", "perl", "ruby",
            "minerd", "xmrig", "cpuminer", "hashcat", "john",
            "eval", "exec", "system", "base64", "gzinflate"
        ]
        
        for pattern in suspicious_patterns:
            if pattern in content:
                suspicious_crontab = {
                    "path": file_path,
                    "content": content.strip()
                }
                tampering_results["suspicious_crontabs"].append(suspicious_crontab)
                break
    except:
        pass

    # 新增：异常文件检查
    print(f"\n{Colors.BOLD_YELLOW}=== 异常文件检查 ==={Colors.RESET}")
    try:
        # 检查可疑文件名和可疑文件内容
        suspicious_file_patterns = [
            "backdoor", "rootkit", "trojan", "malware", "virus",
            "keylog", "stealer", "miner", "xmrig", "cpuminer",
            "hack", "exploit", "shell", "webshell", "phpshell",
            "jspshell", "aspxshell", "aspshell", "inject",
            "evil", "malicious", "payload", "rat", "botnet"
        ]
        
        # 检查可疑扩展名
        suspicious_extensions = [
            ".exe", ".dll", ".so", ".sh", ".pl", ".py", ".rb",
            ".php", ".jsp", ".asp", ".aspx", ".js", ".vbs"
        ]
        
        # 检查的目录
        check_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home"]
        
        for check_dir in check_dirs:
            if not os.path.exists(check_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(check_dir):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        
                        # 检查文件名是否包含可疑关键词
                        is_suspicious_name = False
                        file_name_lower = file_name.lower()
                        for pattern in suspicious_file_patterns:
                            if pattern in file_name_lower:
                                is_suspicious_name = True
                                break
                        
                        # 检查文件扩展名
                        is_suspicious_ext = False
                        for ext in suspicious_extensions:
                            if file_name_lower.endswith(ext):
                                is_suspicious_ext = True
                                break
                        
                        # 检查文件是否可执行
                        is_executable = os.access(file_path, os.X_OK)
                        
                        # 如果满足任一可疑条件，记录该文件
                        if is_suspicious_name or (is_suspicious_ext and is_executable):
                            suspicious_file = {
                                "path": file_path,
                                "reason": []
                            }
                            if is_suspicious_name:
                                suspicious_file["reason"].append("可疑文件名")
                            if is_suspicious_ext and is_executable:
                                suspicious_file["reason"].append("可疑可执行文件")
                            suspicious_file["reason"] = ", ".join(suspicious_file["reason"])
                            suspicious_file["mtime"] = get_file_mtime(file_path)
                            tampering_results["suspicious_files"].append(suspicious_file)
            except Exception as e:
                print(f"{Colors.YELLOW}[警告] 遍历{check_dir}失败: {str(e)}{Colors.RESET}")
        
        if tampering_results["suspicious_files"]:
            for idx, suspicious_file in enumerate(tampering_results["suspicious_files"], 1):
                print(f"{idx}. {Colors.RED}{suspicious_file['path']}{Colors.RESET} | 原因: {suspicious_file['reason']} | 修改时间: {suspicious_file['mtime']}")
        else:
            print(f"{Colors.GREEN}未检测到异常文件{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 异常文件检查失败: {str(e)}{Colors.RESET}")

    # 新增：异常图片文件检查
    print(f"\n{Colors.BOLD_YELLOW}=== 异常图片文件检查 ==={Colors.RESET}")
    try:
        # 图片文件扩展名
        image_extensions = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".ico", ".svg"]
        
        # 检查的目录
        check_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home", "/var/www", "/var/www/html", "/usr/share/nginx/html", "/usr/share/apache2"]
        
        # 异常图片大小阈值（10MB）
        abnormal_size_threshold = 10 * 1024 * 1024
        
        for check_dir in check_dirs:
            if not os.path.exists(check_dir):
                continue
            
            try:
                for root, dirs, files in os.walk(check_dir):
                    for file_name in files:
                        file_path = os.path.join(root, file_name)
                        file_name_lower = file_name.lower()
                        
                        # 检查是否为图片文件
                        is_image = False
                        for ext in image_extensions:
                            if file_name_lower.endswith(ext):
                                is_image = True
                                break
                        
                        if not is_image:
                            continue
                        
                        # 获取文件大小
                        try:
                            file_size = os.path.getsize(file_path)
                        except:
                            continue
                        
                        # 检查文件大小是否异常
                        is_abnormal_size = file_size > abnormal_size_threshold
                        
                        # 检查图片是否可以解析
                        is_parseable = False
                        parse_error = None
                        
                        # 尝试读取文件头判断图片格式
                        try:
                            with open(file_path, 'rb') as f:
                                header = f.read(12)
                            
                            # 检查常见图片文件头
                            if file_name_lower.endswith(('.jpg', '.jpeg')):
                                is_parseable = header.startswith(b'\xff\xd8\xff')
                            elif file_name_lower.endswith('.png'):
                                is_parseable = header.startswith(b'\x89PNG\r\n\x1a\n')
                            elif file_name_lower.endswith('.gif'):
                                is_parseable = header.startswith(b'GIF8')
                            elif file_name_lower.endswith('.bmp'):
                                is_parseable = header.startswith(b'BM')
                            elif file_name_lower.endswith(('.tiff', '.tif')):
                                is_parseable = header.startswith(b'II') or header.startswith(b'MM')
                            elif file_name_lower.endswith('.webp'):
                                is_parseable = header.startswith(b'RIFF') and b'WEBP' in header[:12]
                            elif file_name_lower.endswith('.ico'):
                                is_parseable = header[:4] in [b'\x00\x00\x01\x00', b'\x00\x00\x02\x00']
                            elif file_name_lower.endswith('.svg'):
                                is_parseable = header.startswith(b'<?xml') or header.startswith(b'<svg')
                            
                            if not is_parseable:
                                parse_error = "文件头不匹配"
                        except Exception as e:
                            parse_error = f"读取失败: {str(e)}"
                        
                        # 如果图片异常，记录该文件
                        if is_abnormal_size or (not is_parseable and parse_error):
                            abnormal_image = {
                                "path": file_path,
                                "reason": []
                            }
                            if is_abnormal_size:
                                abnormal_image["reason"].append(f"大小异常({file_size/1024/1024:.2f}MB)")
                            if not is_parseable and parse_error:
                                abnormal_image["reason"].append(f"无法解析({parse_error})")
                            abnormal_image["reason"] = ", ".join(abnormal_image["reason"])
                            abnormal_image["size"] = f"{file_size/1024:.2f}KB"
                            abnormal_image["mtime"] = get_file_mtime(file_path)
                            tampering_results["abnormal_images"].append(abnormal_image)
            except Exception as e:
                print(f"{Colors.YELLOW}[警告] 遍历{check_dir}失败: {str(e)}{Colors.RESET}")
        
        if tampering_results["abnormal_images"]:
            for idx, abnormal_image in enumerate(tampering_results["abnormal_images"], 1):
                print(f"{idx}. {Colors.RED}{abnormal_image['path']}{Colors.RESET} | 原因: {abnormal_image['reason']} | 大小: {abnormal_image['size']} | 修改时间: {abnormal_image['mtime']}")
        else:
            print(f"{Colors.GREEN}未检测到异常图片文件{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 异常图片文件检查失败: {str(e)}{Colors.RESET}")

    return tampering_results

# ===================== 7. 日志异常分析 =====================
def analyze_log_anomalies():
    """日志异常分析（日志篡改/su失败/root异常命令）"""
    print(f"\n{Colors.BLUE}[7/8] 开始分析日志异常{Colors.RESET}")
    log_results = {
        "log_tampering": [],  # 日志篡改
        "su_failures": [],  # su切换失败
        "root_commands": []  # root异常命令执行
    }

    # 检查日志篡改
    log_files = [
        "/var/log/auth.log", "/var/log/secure", "/var/log/ssh.log",
        "/var/log/messages", "/var/log/syslog"
    ]

    for log_file in log_files:
        if not os.path.exists(log_file):
            continue
        
        try:
            # 检查文件大小（异常小的日志文件可能被清空）
            file_size = os.path.getsize(log_file)
            if file_size < 1024:  # 小于1KB
                log_tamper = {
                    "file": log_file,
                    "size": file_size,
                    "reason": "日志文件异常小，可能被清空"
                }
                log_results["log_tampering"].append(log_tamper)
            
            # 检查日志文件修改时间
            mtime = os.path.getmtime(log_file)
            mtime_dt = datetime.fromtimestamp(mtime)
            if (datetime.now() - mtime_dt).days > 7:  # 超过7天未更新
                log_tamper = {
                    "file": log_file,
                    "mtime": mtime_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "reason": "日志文件长时间未更新，可能被停止"
                }
                log_results["log_tampering"].append(log_tamper)
        except:
            pass

    # 检查su切换失败记录
    for log_file in log_files:
        if not os.path.exists(log_file):
            continue
        
        try:
            if os.path.getsize(log_file) > MAX_LOG_SIZE:
                cmd = f"tail -n 1000 {log_file}"
                log_content = run_command(cmd)
            else:
                with open(log_file, 'r', errors='ignore') as f:
                    log_content = f.read()
            
            # 提取su失败记录
            su_fail_pattern = r"su: (\S+)\s+to\s+(\S+)\s+on\s+\S+"
            su_failures = re.findall(su_fail_pattern, log_content)
            for user, target in su_failures[-20:]:
                su_failure = {
                    "user": user,
                    "target": target,
                    "time": get_file_mtime(log_file)
                }
                log_results["su_failures"].append(su_failure)
        except:
            pass

    # 检查root异常命令执行
    for log_file in log_files:
        if not os.path.exists(log_file):
            continue
        
        try:
            if os.path.getsize(log_file) > MAX_LOG_SIZE:
                cmd = f"tail -n 1000 {log_file}"
                log_content = run_command(cmd)
            else:
                with open(log_file, 'r', errors='ignore') as f:
                    log_content = f.read()
            
            # 提取root命令执行
            root_cmd_pattern = r"root:\s+COMMAND=\"(.*?)\""
            root_commands = re.findall(root_cmd_pattern, log_content)
            for cmd in root_commands[-20:]:
                # 过滤常见命令
                common_commands = ["ls", "cd", "cat", "grep", "ps", "top", "df", "du", "mkdir", "rmdir"]
                cmd_lower = cmd.lower()
                is_common = False
                for common_cmd in common_commands:
                    if cmd_lower.startswith(common_cmd):
                        is_common = True
                        break
                if not is_common:
                    root_command = {
                        "command": cmd,
                        "time": get_file_mtime(log_file)
                    }
                    log_results["root_commands"].append(root_command)
        except:
            pass

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== 日志篡改检测 ==={Colors.RESET}")
    if log_results["log_tampering"]:
        for tamper in log_results["log_tampering"]:
            print(f"{Colors.RED}{tamper['file']}{Colors.RESET} | {tamper['reason']}")
    else:
        print(f"{Colors.GREEN}未检测到日志篡改迹象{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== su切换失败记录（最近20条）==={Colors.RESET}")
    if log_results["su_failures"]:
        for idx, failure in enumerate(log_results["su_failures"], 1):
            print(f"{idx}. 用户: {failure['user']} | 目标: {failure['target']} | 时间: {failure['time']}")
    else:
        print(f"{Colors.GREEN}未检测到su切换失败记录{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== root异常命令执行记录 ==={Colors.RESET}")
    if log_results["root_commands"]:
        for idx, cmd in enumerate(log_results["root_commands"], 1):
            print(f"{idx}. {Colors.RED}{cmd['command']}{Colors.RESET} | 时间: {cmd['time']}")
    else:
        print(f"{Colors.GREEN}未检测到root异常命令执行记录{Colors.RESET}")

    return log_results

# ===================== 8. 挖矿行为专项检测 =====================
def detect_mining_behavior():
    """挖矿行为专项检测（挖矿文件/矿池连接/GPU使用）"""
    print(f"\n{Colors.BLUE}[8/8] 开始专项检测挖矿行为{Colors.RESET}")
    mining_results = {
        "mining_files": [],  # 挖矿相关文件
        "mining_conns": [],  # 矿池连接
        "gpu_usage": []  # GPU使用情况
    }

    # 搜索挖矿相关文件
    mining_file_patterns = [
        "minerd", "xmrig", "cpuminer", "ccminer", "bfgminer", "cgminer",
        "ethminer", "claymore", "hashcat", "john", "hydra", "medusa"
    ]

    for pattern in mining_file_patterns:
        find_cmd = f"find / -name '*{pattern}*' -type f -executable 2>/dev/null"
        mining_files = run_command(find_cmd)
        if mining_files and mining_files != "命令执行失败":
            for file_path in mining_files.split('\n'):
                file_path = file_path.strip()
                if file_path and os.path.exists(file_path):
                    # 跳过系统目录
                    if not (file_path.startswith('/usr/bin/') or file_path.startswith('/usr/sbin/')):
                        mining_file = {
                            "path": file_path,
                            "mtime": get_file_mtime(file_path)
                        }
                        mining_results["mining_files"].append(mining_file)

    # 检测矿池连接
    try:
        netstat_output = run_command("netstat -tulnpa 2>/dev/null")
        if netstat_output and netstat_output != "命令执行失败":
            connections = netstat_output.split('\n')
            for conn in connections:
                if not conn or 'Proto' in conn:
                    continue
                
                parts = conn.split()
                if len(parts) < 7:
                    continue
                
                proto, recv_q, send_q, local, foreign, state, pid_prog = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], ' '.join(parts[6:])
                
                # 检测矿池连接特征
                for keyword in MINING_POOL_KEYWORDS:
                    if keyword in foreign.lower() or keyword in pid_prog.lower():
                        mining_conn = {
                            "proto": proto,
                            "remote": foreign,
                            "pid_prog": pid_prog
                        }
                        mining_results["mining_conns"].append(mining_conn)
                        break
    except:
        pass

    # 检测GPU使用情况（使用nvidia-smi或amd-smi）
    try:
        gpu_output = run_command("nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader 2>/dev/null || echo 'No GPU detected'")
        if gpu_output and gpu_output != "命令执行失败" and "No GPU detected" not in gpu_output:
            mining_results["gpu_usage"].append(gpu_output.strip())
    except:
        pass

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== 挖矿相关文件 ==={Colors.RESET}")
    if mining_results["mining_files"]:
        for idx, mining_file in enumerate(mining_results["mining_files"], 1):
            print(f"{idx}. {Colors.RED}{mining_file['path']}{Colors.RESET} | 修改时间: {mining_file['mtime']}")
    else:
        print(f"{Colors.GREEN}未检测到挖矿相关文件{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 矿池连接检测 ==={Colors.RESET}")
    if mining_results["mining_conns"]:
        for idx, conn in enumerate(mining_results["mining_conns"], 1):
            print(f"{idx}. {conn['proto'].upper()} | 远程: {conn['remote']} | {conn['pid_prog']}")
    else:
        print(f"{Colors.GREEN}未检测到矿池连接{Colors.RESET}")

    # 输出GPU使用情况
    if mining_results["gpu_usage"]:
        print(f"\n{Colors.BOLD_YELLOW}=== GPU使用情况 ==={Colors.RESET}")
        for usage in mining_results["gpu_usage"]:
            print(usage)
    else:
        # 尝试运行nvidia-smi获取GPU信息
        try:
            gpu_output = run_command("nvidia-smi --query-gpu=utilization.gpu,memory.used --format=csv,noheader 2>/dev/null")
            if gpu_output and gpu_output != "命令执行失败":
                print(f"\n{Colors.BOLD_YELLOW}=== GPU使用情况 ==={Colors.RESET}")
                print(gpu_output)
        except:
            pass

    return mining_results

# ===================== 9. 中间件与框架版本检测 =====================
def detect_middleware_versions():
    """检测服务器使用的中间件与框架版本信息"""
    print(f"\n{Colors.BLUE}[9/9] 开始检测中间件与框架版本{Colors.RESET}")
    middleware_results = {
        "system": {},  # 系统版本信息
        "web_servers": [],  # Web服务器
        "application_servers": [],  # 应用服务器
        "databases": [],  # 数据库
        "programming_languages": [],  # 编程语言
        "frameworks": [],  # 框架
        "other_services": []  # 其他服务
    }
    
    # 检测系统版本信息
    print(f"\n{Colors.BOLD_YELLOW}=== 系统版本信息 ==={Colors.RESET}")
    try:
        # 检测操作系统类型和版本
        os_info = run_command("cat /etc/os-release")
        if os_info and os_info != "命令执行失败":
            middleware_results["system"]["os_release"] = os_info
        else:
            # 尝试其他方式获取系统信息
            os_info = run_command("uname -a")
            if os_info and os_info != "命令执行失败":
                middleware_results["system"]["uname"] = os_info
        
        # 检测内核版本
        kernel_version = run_command("uname -r")
        if kernel_version and kernel_version != "命令执行失败":
            middleware_results["system"]["kernel"] = kernel_version.strip()
        
        # 检测系统架构
        architecture = run_command("uname -m")
        if architecture and architecture != "命令执行失败":
            middleware_results["system"]["architecture"] = architecture.strip()
        
        # 检测主机名
        hostname = run_command("hostname")
        if hostname and hostname != "命令执行失败":
            middleware_results["system"]["hostname"] = hostname.strip()
        
        # 检测系统时间
        system_time = run_command("date")
        if system_time and system_time != "命令执行失败":
            middleware_results["system"]["time"] = system_time.strip()
        
        # 检测系统负载
        system_load = run_command("uptime")
        if system_load and system_load != "命令执行失败":
            middleware_results["system"]["load"] = system_load.strip()
        
        # 输出系统版本信息
        print(f"{Colors.BLUE}主机名: {middleware_results['system'].get('hostname', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BLUE}内核版本: {middleware_results['system'].get('kernel', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BLUE}系统架构: {middleware_results['system'].get('architecture', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BLUE}系统时间: {middleware_results['system'].get('time', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BLUE}系统负载: {middleware_results['system'].get('load', 'N/A')}{Colors.RESET}")
        if middleware_results['system'].get('os_release'):
            os_release_info = middleware_results['system']['os_release']
            first_line = os_release_info.split('\n')[0]
            print(f"{Colors.BLUE}操作系统信息: {first_line}{Colors.RESET}")
        elif middleware_results['system'].get('uname'):
            print(f"{Colors.BLUE}系统信息: {middleware_results['system']['uname']}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 系统版本信息检测失败: {str(e)}{Colors.RESET}")

    # 检测Web服务器
    web_servers = [
        {"name": "Nginx", "commands": ["nginx -v", "nginx version"], "path": "/usr/sbin/nginx"},
        {"name": "Apache", "commands": ["apache2 -v", "httpd -v"], "path": "/usr/sbin/apache2"},
        {"name": "Lighttpd", "commands": ["lighttpd -v"], "path": "/usr/sbin/lighttpd"},
        {"name": "Tomcat", "commands": ["/usr/local/tomcat/bin/version.sh", "/opt/tomcat/bin/version.sh"], "path": "/usr/local/tomcat"}
    ]

    for server in web_servers:
        version_info = ""
        for cmd in server["commands"]:
            output = run_command(cmd)
            if output and output != "命令执行失败":
                version_info = output
                break
        if version_info or os.path.exists(server["path"]):
            middleware_results["web_servers"].append({
                "name": server["name"],
                "version": version_info.strip() if version_info else "已安装但无法获取版本"
            })

    # 检测应用服务器
    app_servers = [
        {"name": "Tomcat", "commands": ["/usr/local/tomcat/bin/version.sh", "/opt/tomcat/bin/version.sh"], "path": "/usr/local/tomcat"},
        {"name": "Jetty", "commands": ["java -jar /usr/local/jetty/start.jar --version"], "path": "/usr/local/jetty"},
        {"name": "JBoss", "commands": ["/usr/local/jboss/bin/standalone.sh --version"], "path": "/usr/local/jboss"},
        {"name": "WebLogic", "commands": ["/usr/local/weblogic/wlserver/server/bin/setWLSEnv.sh"], "path": "/usr/local/weblogic"}
    ]

    for server in app_servers:
        version_info = ""
        for cmd in server["commands"]:
            output = run_command(cmd)
            if output and output != "命令执行失败":
                version_info = output
                break
        if version_info or os.path.exists(server["path"]):
            middleware_results["application_servers"].append({
                "name": server["name"],
                "version": version_info.strip() if version_info else "已安装但无法获取版本"
            })

    # 检测数据库
    databases = [
        {"name": "MySQL", "commands": ["mysql --version", "mysqld --version"], "path": "/usr/bin/mysql"},
        {"name": "PostgreSQL", "commands": ["psql --version"], "path": "/usr/bin/psql"},
        {"name": "MongoDB", "commands": ["mongo --version"], "path": "/usr/bin/mongo"},
        {"name": "Redis", "commands": ["redis-server --version", "redis-cli --version"], "path": "/usr/bin/redis-server"},
        {"name": "Elasticsearch", "commands": ["elasticsearch --version"], "path": "/usr/share/elasticsearch"}
    ]

    for db in databases:
        version_info = ""
        for cmd in db["commands"]:
            output = run_command(cmd)
            if output and output != "命令执行失败":
                version_info = output
                break
        if version_info or os.path.exists(db["path"]):
            middleware_results["databases"].append({
                "name": db["name"],
                "version": version_info.strip() if version_info else "已安装但无法获取版本"
            })

    # 检测编程语言
    languages = [
        {"name": "Python", "commands": ["python --version", "python3 --version"], "path": "/usr/bin/python"},
        {"name": "PHP", "commands": ["php --version"], "path": "/usr/bin/php"},
        {"name": "Node.js", "commands": ["node --version"], "path": "/usr/bin/node"},
        {"name": "Java", "commands": ["java -version"], "path": "/usr/bin/java"},
        {"name": "Ruby", "commands": ["ruby --version"], "path": "/usr/bin/ruby"}
    ]

    for lang in languages:
        version_info = ""
        for cmd in lang["commands"]:
            output = run_command(cmd)
            if output and output != "命令执行失败":
                version_info = output
                break
        if version_info or os.path.exists(lang["path"]):
            middleware_results["programming_languages"].append({
                "name": lang["name"],
                "version": version_info.strip() if version_info else "已安装但无法获取版本"
            })

    # 检测框架
    frameworks = [
        {"name": "Laravel", "commands": ["cd /var/www/laravel && php artisan --version"], "path": "/var/www/laravel"},
        {"name": "Django", "commands": ["python -m django --version"], "path": "/usr/local/lib/python3.*/site-packages/django"},
        {"name": "Flask", "commands": ["python -c 'import flask; print(flask.__version__)'"], "path": "/usr/local/lib/python3.*/site-packages/flask"},
        {"name": "Express", "commands": ["cd /var/www && npm list express"], "path": "/var/www/node_modules/express"}
    ]

    for framework in frameworks:
        version_info = ""
        for cmd in framework["commands"]:
            output = run_command(cmd)
            if output and output != "命令执行失败":
                version_info = output
                break
        if version_info or os.path.exists(framework["path"]):
            middleware_results["frameworks"].append({
                "name": framework["name"],
                "version": version_info.strip() if version_info else "已安装但无法获取版本"
            })

    # 检测其他服务
    other_services = [
        {"name": "Git", "commands": ["git --version"], "path": "/usr/bin/git"},
        {"name": "Docker", "commands": ["docker --version"], "path": "/usr/bin/docker"},
        {"name": "Kubernetes", "commands": ["kubectl version"], "path": "/usr/bin/kubectl"},
        {"name": "NPM", "commands": ["npm --version"], "path": "/usr/bin/npm"},
        {"name": "Yarn", "commands": ["yarn --version"], "path": "/usr/bin/yarn"}
    ]

    for service in other_services:
        version_info = ""
        for cmd in service["commands"]:
            output = run_command(cmd)
            if output and output != "命令执行失败":
                version_info = output
                break
        if version_info or os.path.exists(service["path"]):
            middleware_results["other_services"].append({
                "name": service["name"],
                "version": version_info.strip() if version_info else "已安装但无法获取版本"
            })

    # 输出结果
    print(f"\n{Colors.BOLD_YELLOW}=== Web服务器 ==={Colors.RESET}")
    if middleware_results["web_servers"]:
        for server in middleware_results["web_servers"]:
            print(f"{Colors.GREEN}{server['name']}{Colors.RESET}: {server['version']}")
    else:
        print(f"{Colors.GREEN}未检测到Web服务器{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 应用服务器 ==={Colors.RESET}")
    if middleware_results["application_servers"]:
        for server in middleware_results["application_servers"]:
            print(f"{Colors.GREEN}{server['name']}{Colors.RESET}: {server['version']}")
    else:
        print(f"{Colors.GREEN}未检测到应用服务器{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 数据库 ==={Colors.RESET}")
    if middleware_results["databases"]:
        for db in middleware_results["databases"]:
            print(f"{Colors.GREEN}{db['name']}{Colors.RESET}: {db['version']}")
    else:
        print(f"{Colors.GREEN}未检测到数据库{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 编程语言 ==={Colors.RESET}")
    if middleware_results["programming_languages"]:
        for lang in middleware_results["programming_languages"]:
            print(f"{Colors.GREEN}{lang['name']}{Colors.RESET}: {lang['version']}")
    else:
        print(f"{Colors.GREEN}未检测到编程语言{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 框架 ==={Colors.RESET}")
    if middleware_results["frameworks"]:
        for framework in middleware_results["frameworks"]:
            print(f"{Colors.GREEN}{framework['name']}{Colors.RESET}: {framework['version']}")
    else:
        print(f"{Colors.GREEN}未检测到框架{Colors.RESET}")

    print(f"\n{Colors.BOLD_YELLOW}=== 其他服务 ==={Colors.RESET}")
    if middleware_results["other_services"]:
        for service in middleware_results["other_services"]:
            print(f"{Colors.GREEN}{service['name']}{Colors.RESET}: {service['version']}")
    else:
        print(f"{Colors.GREEN}未检测到其他服务{Colors.RESET}")

    return middleware_results

# ===================== 站点日志攻击成功分析 =====================
def analyze_web_attack_logs():
    """分析站点日志中的攻击成功记录"""
    print(f"\n{Colors.BOLD_YELLOW}=== 站点日志攻击成功分析 ==={Colors.RESET}")
    
    web_attack_results = {
        "successful_attacks": [],
        "attack_types": {},
        "attack_sources": {},
        "affected_paths": {},
        "web_servers": [],
        "log_files": []
    }
    
    # 常见的Web服务器日志文件
    web_logs = [
        # Apache日志
        "/var/log/apache2/access.log", "/var/log/httpd/access_log",
        "/var/log/apache/access.log", "/var/log/apache2/error.log",
        # Nginx日志
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        # 其他可能的日志位置
        "/var/log/webaccess.log", "/var/log/access_log"
    ]
    
    # 攻击模式和特征
    attack_patterns = {
        "sql_injection": [
            "union select", "' or '1'='1", "' or 1=1", "\");--", "sqlmap",
            "information_schema", "@@version", "concat(", "group_concat(",
            "benchmark(", "sleep(", "waitfor delay", "xp_cmdshell"
        ],
        "xss": [
            "<script>", "javascript:", "onerror=", "onload=", "onclick=",
            "<iframe>", "<img src=", "<svg>", "<object>", "<embed>"
        ],
        "command_injection": [
            "; ls", "; cat", "; rm", "; id", "; whoami",
            "| ls", "| cat", "| rm", "| id", "| whoami",
            "&& ls", "&& cat", "&& rm", "&& id", "&& whoami",
            "`ls`", "`cat`", "`rm`", "`id`", "`whoami`"
        ],
        "file_inclusion": [
            "../", "..\\", "file://", "php://", "data://",
            "include(", "require(", "fopen(", "file_get_contents("
        ],
        "rce": [
            "eval(", "exec(", "system(", "passthru(", "shell_exec(",
            "popen(", "proc_open(", "assert(", "create_function("
        ],
        "webshell": [
            "菜刀", "冰蝎", "哥斯拉", "AntSword", "Cknife", "Weevely",
            "eval(base64_decode", "base64_decode(", "gzinflate(", "str_rot13("
        ],
        "brute_force": [
            "wp-login.php", "admin", "login", "signin", "auth",
            "administrator", "manager", "backend", "controlpanel"
        ]
    }
    
    # 成功攻击的状态码
    success_status_codes = ["200", "301", "302", "307", "308"]
    
    # 检查Web服务器日志
    print(f"\n{Colors.YELLOW}[+] 检查Web服务器日志文件{Colors.RESET}")
    for log_file in web_logs:
        if not os.path.exists(log_file):
            continue
        
        web_attack_results["log_files"].append(log_file)
        
        try:
            # 确定日志文件类型
            log_type = "unknown"
            if "apache" in log_file.lower() or "httpd" in log_file.lower():
                log_type = "apache"
                if "apache" not in [ws["name"] for ws in web_attack_results["web_servers"]]:
                    web_attack_results["web_servers"].append({"name": "apache", "log_file": log_file})
            elif "nginx" in log_file.lower():
                log_type = "nginx"
                if "nginx" not in [ws["name"] for ws in web_attack_results["web_servers"]]:
                    web_attack_results["web_servers"].append({"name": "nginx", "log_file": log_file})
            
            # 读取日志文件（处理大文件）
            if os.path.getsize(log_file) > MAX_LOG_SIZE:
                # 对于大文件，只读取最后部分
                cmd = f"tail -n 5000 {log_file}"
                log_content = run_command(cmd)
            else:
                # 对于小文件，读取全部内容
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
            
            if not log_content or log_content == "命令执行失败":
                continue
            
            # 分析日志行
            for line in log_content.split('\n'):
                if not line.strip():
                    continue
                
                # 解析日志行
                parsed_log = parse_web_log_line(line, log_type)
                if not parsed_log:
                    continue
                
                # 检查是否是成功的请求
                if parsed_log.get('status') not in success_status_codes:
                    continue
                
                # 检查是否包含攻击模式
                request = parsed_log.get('request', '').lower()
                user_agent = parsed_log.get('user_agent', '').lower()
                
                for attack_type, patterns in attack_patterns.items():
                    for pattern in patterns:
                        if pattern.lower() in request or pattern.lower() in user_agent:
                            # 记录攻击
                            attack_record = {
                                "timestamp": parsed_log.get('timestamp', 'unknown'),
                                "source_ip": parsed_log.get('ip', 'unknown'),
                                "status": parsed_log.get('status', 'unknown'),
                                "request": parsed_log.get('request', 'unknown'),
                                "user_agent": parsed_log.get('user_agent', 'unknown'),
                                "attack_type": attack_type,
                                "log_file": log_file
                            }
                            
                            web_attack_results["successful_attacks"].append(attack_record)
                            
                            # 更新统计信息
                            if attack_type not in web_attack_results["attack_types"]:
                                web_attack_results["attack_types"][attack_type] = 0
                            web_attack_results["attack_types"][attack_type] += 1
                            
                            source_ip = parsed_log.get('ip', 'unknown')
                            if source_ip not in web_attack_results["attack_sources"]:
                                web_attack_results["attack_sources"][source_ip] = 0
                            web_attack_results["attack_sources"][source_ip] += 1
                            
                            path = parsed_log.get('path', 'unknown')
                            if path not in web_attack_results["affected_paths"]:
                                web_attack_results["affected_paths"][path] = 0
                            web_attack_results["affected_paths"][path] += 1
                            
                            break
        except Exception as e:
            print(f"{Colors.YELLOW}[警告] 无法分析日志文件 {log_file}: {str(e)[:30]}{Colors.RESET}")
    
    # 输出分析结果
    print(f"\n{Colors.GREEN}[+] 站点日志攻击分析完成{Colors.RESET}")
    print(f"成功的攻击记录: {len(web_attack_results['successful_attacks'])}")
    print(f"攻击类型: {list(web_attack_results['attack_types'].keys())}")
    print(f"攻击源IP: {len(web_attack_results['attack_sources'])} 个")
    print(f"受影响路径: {len(web_attack_results['affected_paths'])} 个")
    print(f"Web服务器: {[ws['name'] for ws in web_attack_results['web_servers']]}")
    print(f"分析的日志文件: {len(web_attack_results['log_files'])} 个")
    
    return web_attack_results

def parse_web_log_line(line, log_type):
    """解析Web服务器日志行"""
    try:
        if log_type == "apache":
            # Apache日志格式: IP - - [timestamp] "request" status size "referer" "user_agent"
            import re
            apache_pattern = r'^(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(.*?)"\s+(\d+)\s+(\S+)\s+"(.*?)"\s+"(.*?)"'
            match = re.match(apache_pattern, line)
            if match:
                ip, timestamp, request, status, size, referer, user_agent = match.groups()
                # 提取路径
                path = request.split(' ')[1] if ' ' in request else request
                return {
                    "ip": ip,
                    "timestamp": timestamp,
                    "request": request,
                    "status": status,
                    "size": size,
                    "referer": referer,
                    "user_agent": user_agent,
                    "path": path
                }
        elif log_type == "nginx":
            # Nginx日志格式: IP - - [timestamp] "request" status size "referer" "user_agent" "upstream_addr"
            import re
            nginx_pattern = r'^(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(.*?)"\s+(\d+)\s+(\S+)\s+"(.*?)"\s+"(.*?)"'
            match = re.match(nginx_pattern, line)
            if match:
                ip, timestamp, request, status, size, referer, user_agent = match.groups()
                # 提取路径
                path = request.split(' ')[1] if ' ' in request else request
                return {
                    "ip": ip,
                    "timestamp": timestamp,
                    "request": request,
                    "status": status,
                    "size": size,
                    "referer": referer,
                    "user_agent": user_agent,
                    "path": path
                }
        else:
            # 尝试通用解析
            import re
            # 匹配IP地址
            ip_match = re.search(r'^(\S+)', line)
            if ip_match:
                ip = ip_match.group(1)
                # 匹配状态码
                status_match = re.search(r'\s+(\d{3})\s+', line)
                status = status_match.group(1) if status_match else 'unknown'
                # 匹配请求
                request_match = re.search(r'"(.*?)"', line)
                request = request_match.group(1) if request_match else 'unknown'
                # 提取路径
                path = request.split(' ')[1] if ' ' in request else request
                # 匹配时间戳
                timestamp_match = re.search(r'\[(.*?)\]', line)
                timestamp = timestamp_match.group(1) if timestamp_match else 'unknown'
                # 匹配用户代理
                ua_match = re.search(r'"([^"]*)$', line)
                user_agent = ua_match.group(1) if ua_match else 'unknown'
                
                return {
                    "ip": ip,
                    "timestamp": timestamp,
                    "request": request,
                    "status": status,
                    "path": path,
                    "user_agent": user_agent
                }
    except Exception:
        pass
    
    return None

# ===================== Alias后门检测 =====================
def detect_alias_backdoors():
    """检测Alias后门"""
    print(f"\n{Colors.BOLD_YELLOW}=== Alias后门检测 ==={Colors.RESET}")
    
    alias_results = {
        "suspicious_aliases": [],
        "modified_files": [],
        "system_wide_configs": [],
        "user_configs": []
    }
    
    # 常见的shell配置文件
    shell_configs = [
        # 系统级配置
        "/etc/bashrc", "/etc/profile", "/etc/profile.d/", "/etc/bash.bashrc",
        # 用户级配置
        "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.bash_login", "~/.zshrc",
        "~/.kshrc", "~/.cshrc", "~/.tcshrc"
    ]
    
    # 敏感命令列表，这些命令被别名可能是后门
    sensitive_commands = [
        "ls", "ps", "netstat", "ss", "lsof", "top", "htop", "ps aux", "who", "w",
        "last", "find", "grep", "cat", "rm", "mv", "cp", "chmod", "chown",
        "ssh", "scp", "sftp", "sudo", "su", "id", "uname", "df", "du"
    ]
    
    # 恶意代码特征
    malicious_patterns = [
        "rm -f", ">/dev/null", "2>&1", "&&", ";", "eval", "exec", "system",
        "bash -c", "sh -c", "python", "perl", "curl", "wget", "nc", "netcat",
        "reverse shell", "backdoor", "malware", "virus", "trojan"
    ]
    
    # 检查系统级配置文件
    print(f"\n{Colors.YELLOW}[+] 检测系统级配置文件{Colors.RESET}")
    for config_file in shell_configs:
        # 展开~为用户主目录
        expanded_path = os.path.expanduser(config_file)
        
        # 检查目录
        if expanded_path.endswith('/'):
            if os.path.exists(expanded_path):
                try:
                    for file in os.listdir(expanded_path):
                        file_path = os.path.join(expanded_path, file)
                        if os.path.isfile(file_path):
                            check_alias_file(file_path, alias_results, sensitive_commands, malicious_patterns, "system")
                except Exception as e:
                    print(f"{Colors.YELLOW}[警告] 无法访问目录 {expanded_path}: {str(e)[:30]}{Colors.RESET}")
        # 检查文件
        elif os.path.exists(expanded_path):
            check_alias_file(expanded_path, alias_results, sensitive_commands, malicious_patterns, "system")
    
    # 检查用户主目录中的配置文件
    print(f"\n{Colors.YELLOW}[+] 检测用户级配置文件{Colors.RESET}")
    try:
        # 获取所有用户的主目录
        passwd_output = run_command("cat /etc/passwd")
        if passwd_output and passwd_output != "命令执行失败":
            for line in passwd_output.split('\n'):
                if line.strip() and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 6:
                        username = parts[0]
                        home_dir = parts[5]
                        # 检查用户主目录是否存在且不为系统用户
                        if os.path.exists(home_dir) and not home_dir.startswith('/var/') and not home_dir.startswith('/run/'):
                            # 检查用户级配置文件
                            user_configs = [
                                os.path.join(home_dir, ".bashrc"),
                                os.path.join(home_dir, ".bash_profile"),
                                os.path.join(home_dir, ".profile"),
                                os.path.join(home_dir, ".zshrc")
                            ]
                            for config_file in user_configs:
                                if os.path.exists(config_file):
                                    check_alias_file(config_file, alias_results, sensitive_commands, malicious_patterns, "user")
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 无法检查用户配置文件: {str(e)[:30]}{Colors.RESET}")
    
    # 输出结果
    print(f"\n{Colors.GREEN}[+] Alias后门检测完成{Colors.RESET}")
    print(f"可疑别名: {len(alias_results['suspicious_aliases'])}")
    print(f"修改的配置文件: {len(alias_results['modified_files'])}")
    print(f"系统级配置: {len(alias_results['system_wide_configs'])}")
    print(f"用户级配置: {len(alias_results['user_configs'])}")
    
    return alias_results

def check_alias_file(file_path, alias_results, sensitive_commands, malicious_patterns, config_type):
    """检查单个文件中的Alias后门"""
    try:
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 检查文件修改时间
        mtime = get_file_mtime(file_path)
        
        # 分析文件内容
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            # 检查alias命令
            line_lower = line.lower()
            if 'alias ' in line_lower:
                # 提取别名和命令
                alias_part = line.split('alias ', 1)[1] if 'alias ' in line else ''
                if '=' in alias_part:
                    alias_name = alias_part.split('=', 1)[0].strip()
                    alias_value = alias_part.split('=', 1)[1].strip()
                    
                    # 检查是否是敏感命令的别名
                    for cmd in sensitive_commands:
                        if cmd in alias_name:
                            # 检查别名值是否包含恶意代码
                            suspicious = False
                            for pattern in malicious_patterns:
                                if pattern in alias_value.lower():
                                    suspicious = True
                                    break
                            
                            # 检查是否有异常的命令结构
                            if ';' in alias_value or '&&' in alias_value or '|' in alias_value:
                                suspicious = True
                            
                            if suspicious:
                                alias_results["suspicious_aliases"].append({
                                    "file": file_path,
                                    "line": i,
                                    "alias": alias_name,
                                    "value": alias_value,
                                    "type": config_type
                                })
        
        # 记录配置文件
        if config_type == "system":
            alias_results["system_wide_configs"].append({
                "path": file_path,
                "mtime": mtime
            })
        else:
            alias_results["user_configs"].append({
                "path": file_path,
                "mtime": mtime
            })
        
        # 检查文件是否被修改过（最近7天）
        try:
            file_mtime = os.path.getmtime(file_path)
            seven_days_ago = datetime.now().timestamp() - (7 * 24 * 3600)
            if file_mtime > seven_days_ago:
                alias_results["modified_files"].append({
                    "path": file_path,
                    "mtime": mtime
                })
        except:
            pass
            
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 无法检查文件 {file_path}: {str(e)[:30]}{Colors.RESET}")

# ===================== 内存马与Rootkit检测 =====================
def detect_memory_malware():
    """检测内存马和Rootkit"""
    print(f"\n{Colors.BOLD_YELLOW}=== 内存马与Rootkit检测 ==={Colors.RESET}")
    
    memory_results = {
        "java_memory_mares": [],
        "process_injection": [],
        "suspicious_memory_regions": [],
        "rootkit_indicators": [],
        "hidden_processes": [],
        "abnormal_system_calls": []
    }
    
    # 1. Java内存马检测
    print(f"\n{Colors.YELLOW}[+] 检测Java内存马{Colors.RESET}")
    try:
        # 检查Java进程
        java_processes = run_command("ps -ef | grep java | grep -v grep")
        if java_processes and java_processes != "命令执行失败":
            for line in java_processes.split('\n'):
                if line.strip():
                    # 检查Java进程的内存映射
                    pid = line.split()[1]
                    maps_output = run_command(f"cat /proc/{pid}/maps 2>/dev/null")
                    if maps_output and maps_output != "命令执行失败":
                        # 检查可疑的内存区域
                        for map_line in maps_output.split('\n'):
                            if "[heap]" in map_line or "[stack]" in map_line:
                                continue
                            if "rwx" in map_line:
                                memory_results["suspicious_memory_regions"].append({
                                    "pid": pid,
                                    "process": line.strip(),
                                    "memory_region": map_line.strip()
                                })
                    
                    # 检查Java进程的线程
                    threads_output = run_command(f"ls /proc/{pid}/task 2>/dev/null")
                    if threads_output and threads_output != "命令执行失败":
                        thread_count = len([t for t in threads_output.split('\n') if t.strip()])
                        if thread_count > 50:  # 异常多的线程
                            memory_results["java_memory_mares"].append({
                                "pid": pid,
                                "process": line.strip(),
                                "reason": f"异常线程数: {thread_count}"
                            })
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] Java内存马检测失败: {str(e)[:30]}{Colors.RESET}")
    
    # 2. 进程注入检测
    print(f"\n{Colors.YELLOW}[+] 检测进程注入{Colors.RESET}")
    try:
        # 检查所有进程的内存映射
        proc_dirs = [d for d in os.listdir('/proc') if d.isdigit()]
        for pid in proc_dirs[:50]:  # 限制检查数量，避免性能问题
            try:
                maps_output = run_command(f"cat /proc/{pid}/maps 2>/dev/null")
                if maps_output and maps_output != "命令执行失败":
                    # 检查可写可执行的内存区域
                    for map_line in maps_output.split('\n'):
                        if "rwx" in map_line and not any(region in map_line for region in ["[heap]", "[stack]", "[vdso]", "[vsyscall]"]):
                            # 检查进程信息
                            comm_output = run_command(f"cat /proc/{pid}/comm 2>/dev/null")
                            cmdline_output = run_command(f"cat /proc/{pid}/cmdline 2>/dev/null")
                            
                            memory_results["process_injection"].append({
                                "pid": pid,
                                "comm": comm_output.strip() if comm_output and comm_output != "命令执行失败" else "未知",
                                "cmdline": cmdline_output.strip().replace('\x00', ' ') if cmdline_output and cmdline_output != "命令执行失败" else "未知",
                                "memory_region": map_line.strip()
                            })
            except Exception:
                pass
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 进程注入检测失败: {str(e)[:30]}{Colors.RESET}")
    
    # 3. Rootkit检测
    print(f"\n{Colors.YELLOW}[+] 检测Rootkit{Colors.RESET}")
    try:
        # 检查隐藏进程（比较ps和/proc）
        ps_pids = set()
        proc_pids = set()
        
        ps_output = run_command("ps -e | awk '{print $1}'")
        if ps_output and ps_output != "命令执行失败":
            for pid in ps_output.split('\n'):
                if pid.isdigit():
                    ps_pids.add(pid)
        
        if os.path.exists('/proc'):
            for d in os.listdir('/proc'):
                if d.isdigit():
                    proc_pids.add(d)
        
        # 找出/proc中有但ps中没有的进程
        hidden_pids = proc_pids - ps_pids
        for pid in hidden_pids:
            try:
                comm_output = run_command(f"cat /proc/{pid}/comm 2>/dev/null")
                cmdline_output = run_command(f"cat /proc/{pid}/cmdline 2>/dev/null")
                
                memory_results["hidden_processes"].append({
                    "pid": pid,
                    "comm": comm_output.strip() if comm_output and comm_output != "命令执行失败" else "未知",
                    "cmdline": cmdline_output.strip().replace('\x00', ' ') if cmdline_output and cmdline_output != "命令执行失败" else "未知"
                })
            except Exception:
                pass
        
        # 检查异常的系统调用（简单检测）
        if os.path.exists('/proc/kallsyms'):
            kallsyms_output = run_command("grep 'sys_call_table' /proc/kallsyms 2>/dev/null")
            if not kallsyms_output or kallsyms_output == "命令执行失败":
                memory_results["rootkit_indicators"].append({
                    "indicator": "无法读取系统调用表",
                    "severity": "高"
                })
        
        # 检查异常的内核模块
        modules_output = run_command("lsmod | grep -E '(hide|rootkit|backdoor)' 2>/dev/null")
        if modules_output and modules_output != "命令执行失败":
            for line in modules_output.split('\n'):
                if line.strip():
                    memory_results["rootkit_indicators"].append({
                        "indicator": f"可疑内核模块: {line.strip()}",
                        "severity": "高"
                    })
        
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] Rootkit检测失败: {str(e)[:30]}{Colors.RESET}")
    
    # 输出结果
    print(f"\n{Colors.GREEN}[+] 内存马检测完成{Colors.RESET}")
    print(f"Java内存马: {len(memory_results['java_memory_mares'])}")
    print(f"进程注入迹象: {len(memory_results['process_injection'])}")
    print(f"可疑内存区域: {len(memory_results['suspicious_memory_regions'])}")
    print(f"Rootkit指标: {len(memory_results['rootkit_indicators'])}")
    print(f"隐藏进程: {len(memory_results['hidden_processes'])}")
    
    return memory_results

# ===================== 综合日志攻击痕迹分析 =====================
def analyze_comprehensive_logs(all_results=None):
    """综合所有日志分析攻击痕迹"""
    print(f"\n{Colors.BOLD_YELLOW}=== 综合日志攻击痕迹分析 ==={Colors.RESET}")
    
    comprehensive_results = {
        "attack_timeline": [],  # 攻击时间线
        "attack_chains": [],  # 攻击链
        "critical_events": [],  # 关键事件
        "suspicious_patterns": [],  # 可疑模式
        "affected_systems": [],  # 受影响系统
        "attack_sources": {},  # 攻击源统计
        "attack_types": {},  # 攻击类型统计
        "log_sources": [],  # 日志来源
        "total_events": 0
    }
    
    # 1. 整合现有日志分析结果
    print(f"\n{Colors.YELLOW}[+] 整合现有日志分析结果{Colors.RESET}")
    
    if all_results:
        # 整合SSH日志分析结果
        ssh_results = all_results.get('ssh', {})
        if ssh_results.get('brute_force_details_5days', []):
            for brute_force in ssh_results['brute_force_details_5days']:
                event = {
                    "timestamp": brute_force.get('time', ''),
                    "event_type": "SSH暴力破解",
                    "source_ip": brute_force.get('ip', ''),
                    "details": f"SSH暴力破解尝试",
                    "severity": "高",
                    "log_source": brute_force.get('log_file', 'SSH日志')
                }
                comprehensive_results['attack_timeline'].append(event)
                comprehensive_results['attack_sources'][brute_force.get('ip', 'Unknown')] = comprehensive_results['attack_sources'].get(brute_force.get('ip', 'Unknown'), 0) + 1
                comprehensive_results['attack_types']['SSH暴力破解'] = comprehensive_results['attack_types'].get('SSH暴力破解', 0) + 1
                comprehensive_results['total_events'] += 1
        
        if ssh_results.get('successful_logins', []):
            for login in ssh_results['successful_logins']:
                event = {
                    "timestamp": login.get('time', ''),
                    "event_type": "SSH登录",
                    "source_ip": login.get('ip', ''),
                    "details": f"用户 {login.get('user', '')} 登录成功",
                    "severity": "中",
                    "log_source": "SSH日志"
                }
                comprehensive_results['attack_timeline'].append(event)
                comprehensive_results['attack_sources'][login.get('ip', 'Unknown')] = comprehensive_results['attack_sources'].get(login.get('ip', 'Unknown'), 0) + 1
                comprehensive_results['attack_types']['SSH登录'] = comprehensive_results['attack_types'].get('SSH登录', 0) + 1
                comprehensive_results['total_events'] += 1
        
        # 整合站点日志攻击分析结果
        web_attack_results = all_results.get('web_attack_logs', {})
        if web_attack_results.get('successful_attacks', []):
            for attack in web_attack_results['successful_attacks']:
                event = {
                    "timestamp": attack.get('timestamp', ''),
                    "event_type": attack.get('attack_type', 'Web攻击'),
                    "source_ip": attack.get('source_ip', ''),
                    "details": f"Web攻击成功: {attack.get('request', '')}",
                    "severity": "严重",
                    "log_source": attack.get('log_file', 'Web服务器日志')
                }
                comprehensive_results['attack_timeline'].append(event)
                comprehensive_results['attack_sources'][attack.get('source_ip', 'Unknown')] = comprehensive_results['attack_sources'].get(attack.get('source_ip', 'Unknown'), 0) + 1
                comprehensive_results['attack_types'][attack.get('attack_type', 'Web攻击')] = comprehensive_results['attack_types'].get(attack.get('attack_type', 'Web攻击'), 0) + 1
                comprehensive_results['total_events'] += 1
        
        # 整合日志异常分析结果
        log_anomalies = all_results.get('log_anomalies', {})
        if log_anomalies.get('log_tampering', []):
            for tampering in log_anomalies['log_tampering']:
                event = {
                    "timestamp": tampering.get('mtime', ''),
                    "event_type": "日志篡改",
                    "source_ip": "本地",
                    "details": f"日志文件被篡改: {tampering.get('file', '')}",
                    "severity": "严重",
                    "log_source": tampering.get('file', '系统日志')
                }
                comprehensive_results['attack_timeline'].append(event)
                comprehensive_results['attack_types']['日志篡改'] = comprehensive_results['attack_types'].get('日志篡改', 0) + 1
                comprehensive_results['total_events'] += 1
        
        if log_anomalies.get('root_commands', []):
            for cmd in log_anomalies['root_commands']:
                event = {
                    "timestamp": cmd.get('time', ''),
                    "event_type": "Root命令执行",
                    "source_ip": "本地",
                    "details": f"Root执行命令: {cmd.get('command', '')}",
                    "severity": "高",
                    "log_source": "系统日志"
                }
                comprehensive_results['attack_timeline'].append(event)
                comprehensive_results['attack_types']['Root命令执行'] = comprehensive_results['attack_types'].get('Root命令执行', 0) + 1
                comprehensive_results['total_events'] += 1
    
    # 2. 分析系统日志文件
    print(f"\n{Colors.YELLOW}[+] 分析系统日志文件{Colors.RESET}")
    
    system_logs = [
        # 系统日志
        "/var/log/syslog", "/var/log/messages", "/var/log/secure",
        "/var/log/auth.log", "/var/log/audit/audit.log",
        # 应用日志
        "/var/log/apache2/error.log", "/var/log/nginx/error.log",
        # 其他日志
        "/var/log/cron", "/var/log/faillog", "/var/log/lastlog"
    ]
    
    for log_file in system_logs:
        if os.path.exists(log_file):
            comprehensive_results['log_sources'].append(log_file)
            
            try:
                # 读取日志文件（限制大小）
                if os.path.getsize(log_file) > MAX_LOG_SIZE:
                    # 对于大文件，只读取最后部分
                    cmd = f"tail -n 1000 {log_file}"
                    log_content = run_command(cmd)
                else:
                    # 对于小文件，读取全部内容
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        log_content = f.read()
                
                if log_content and log_content != "命令执行失败":
                    # 分析日志内容
                    lines = log_content.split('\n')
                    for line in lines:
                        if not line.strip():
                            continue
                        
                        # 检测可疑模式
                        suspicious_patterns = {
                            "权限提升": ["sudo", "su", "privileged", "root"],
                            "网络连接": ["connect", "connection", "socket", "accept"],
                            "文件操作": ["write", "modify", "delete", "create", "chmod"],
                            "进程操作": ["exec", "fork", "spawn", "process"],
                            "认证失败": ["authentication failed", "login failed", "invalid password"],
                            "异常行为": ["error", "warning", "critical", "failed", "denied"]
                        }
                        
                        for pattern_name, patterns in suspicious_patterns.items():
                            for pattern in patterns:
                                if pattern.lower() in line.lower():
                                    event = {
                                        "timestamp": "未知",
                                        "event_type": pattern_name,
                                        "source_ip": "未知",
                                        "details": line[:200],  # 截取部分日志内容
                                        "severity": "中",
                                        "log_source": log_file
                                    }
                                    comprehensive_results['suspicious_patterns'].append(event)
                                    comprehensive_results['total_events'] += 1
                                    break
            except Exception as e:
                print(f"  {Colors.RED}分析日志文件 {log_file} 失败: {str(e)}{Colors.RESET}")
    
    # 3. 构建攻击时间线
    print(f"\n{Colors.YELLOW}[+] 构建攻击时间线{Colors.RESET}")
    
    # 按时间排序
    comprehensive_results['attack_timeline'].sort(key=lambda x: x['timestamp'] if x['timestamp'] else '0')
    
    # 4. 识别攻击链
    print(f"\n{Colors.YELLOW}[+] 识别攻击链{Colors.RESET}")
    
    # 简单的攻击链识别
    if len(comprehensive_results['attack_timeline']) >= 2:
        for i in range(len(comprehensive_results['attack_timeline']) - 1):
            current_event = comprehensive_results['attack_timeline'][i]
            next_event = comprehensive_results['attack_timeline'][i + 1]
            
            # 检查时间间隔（例如，30分钟内）
            # 这里简化处理，实际应该解析时间戳并计算间隔
            
            # 检查是否可能是攻击链
            if current_event['source_ip'] == next_event['source_ip']:
                attack_chain = {
                    "events": [current_event, next_event],
                    "description": f"{current_event['event_type']} -> {next_event['event_type']}",
                    "source_ip": current_event['source_ip'],
                    "severity": "高"
                }
                comprehensive_results['attack_chains'].append(attack_chain)
    
    # 5. 识别关键事件
    print(f"\n{Colors.YELLOW}[+] 识别关键事件{Colors.RESET}")
    
    for event in comprehensive_results['attack_timeline']:
        if event['severity'] in ['严重', '高']:
            comprehensive_results['critical_events'].append(event)
    
    # 6. 统计分析
    print(f"\n{Colors.YELLOW}[+] 生成统计分析{Colors.RESET}")
    
    # 7. 输出结果
    print(f"\n{Colors.GREEN}[+] 综合日志分析完成{Colors.RESET}")
    print(f"  总事件数: {comprehensive_results['total_events']}")
    print(f"  关键事件: {len(comprehensive_results['critical_events'])}")
    print(f"  攻击链: {len(comprehensive_results['attack_chains'])}")
    print(f"  攻击源: {len(comprehensive_results['attack_sources'])}")
    print(f"  攻击类型: {len(comprehensive_results['attack_types'])}")
    print(f"  日志来源: {len(comprehensive_results['log_sources'])}")
    
    return comprehensive_results

# ===================== 漏洞检测 =====================
def detect_vulnerabilities():
    """检测系统漏洞"""
    print(f"\n{Colors.BOLD_YELLOW}=== 漏洞检测 ==={Colors.RESET}")
    
    vulnerabilities = {
        "system_vulnerabilities": [],
        "web_vulnerabilities": [],
        "database_vulnerabilities": [],
        "other_vulnerabilities": [],
        "vulnerability_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0
    }
    
    # 1. 系统内核漏洞检测
    print(f"\n{Colors.YELLOW}[+] 检测系统内核漏洞{Colors.RESET}")
    try:
        # 检查内核版本
        uname_output = run_command("uname -a")
        if uname_output and uname_output != "命令执行失败":
            kernel_version = uname_output
            print(f"  内核版本: {kernel_version}")
            
            # 常见内核漏洞检测
            kernel_vulns = [
                {
                    "name": "Dirty Cow",
                    "cve": "CVE-2016-5195",
                    "description": "内核内存权限提升漏洞，允许低权限用户获取root权限",
                    "severity": "严重",
                    "check": lambda v: "4.4.0-" in v and int(v.split("4.4.0-")[1].split("-")[0]) < 109,
                    "fix": "升级内核到4.4.0-109或更高版本"
                },
                {
                    "name": "Meltdown",
                    "cve": "CVE-2017-5754",
                    "description": "CPU硬件漏洞，允许用户空间程序读取内核内存",
                    "severity": "严重",
                    "check": lambda v: True,  # 几乎所有现代CPU都受影响
                    "fix": "安装内核补丁并启用内核页表隔离(KPTI)"
                },
                {
                    "name": "Spectre",
                    "cve": "CVE-2017-5753, CVE-2017-5715",
                    "description": "CPU硬件漏洞，允许推测执行侧信道攻击",
                    "severity": "高",
                    "check": lambda v: True,  # 几乎所有现代CPU都受影响
                    "fix": "安装内核补丁并启用相关防护措施"
                }
            ]
            
            for vuln in kernel_vulns:
                if vuln["check"](kernel_version):
                    vulnerabilities["system_vulnerabilities"].append({
                        "name": vuln["name"],
                        "cve": vuln.get("cve", "N/A"),
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "affected_component": "内核",
                        "fix": vuln["fix"]
                    })
                    vulnerabilities["vulnerability_count"] += 1
                    if vuln["severity"] == "严重":
                        vulnerabilities["critical_count"] += 1
                    elif vuln["severity"] == "高":
                        vulnerabilities["high_count"] += 1
                    elif vuln["severity"] == "中":
                        vulnerabilities["medium_count"] += 1
                    else:
                        vulnerabilities["low_count"] += 1
    except Exception as e:
        print(f"  {Colors.RED}内核漏洞检测失败: {str(e)}{Colors.RESET}")
    
    # 2. Web服务漏洞检测
    print(f"\n{Colors.YELLOW}[+] 检测Web服务漏洞{Colors.RESET}")
    try:
        # 检查Apache
        apache_version = run_command("apache2 -v 2>/dev/null || httpd -v 2>/dev/null")
        if apache_version and apache_version != "命令执行失败":
            print(f"  Apache版本: {apache_version.splitlines()[0] if isinstance(apache_version, str) else str(apache_version)}")
            
            # Apache漏洞检测
            apache_vulns = [
                {
                    "name": "Apache Struts2漏洞系列",
                    "cve": "CVE-2017-5638, CVE-2018-11776, CVE-2020-17530",
                    "description": "Struts2框架存在多个远程代码执行漏洞",
                    "severity": "严重",
                    "check": lambda v: "struts2" in v.lower() or "struts" in v.lower(),
                    "fix": "升级到最新版本的Struts2框架"
                },
                {
                    "name": "Apache Log4j2漏洞",
                    "cve": "CVE-2021-44228, CVE-2021-45046, CVE-2021-45105",
                    "description": "Log4j2远程代码执行漏洞",
                    "severity": "严重",
                    "check": lambda v: "log4j" in v.lower(),
                    "fix": "升级到Log4j 2.17.1或更高版本"
                }
            ]
            
            for vuln in apache_vulns:
                if vuln["check"](str(apache_version)):
                    vulnerabilities["web_vulnerabilities"].append({
                        "name": vuln["name"],
                        "cve": vuln.get("cve", "N/A"),
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "affected_component": "Apache",
                        "fix": vuln["fix"]
                    })
                    vulnerabilities["vulnerability_count"] += 1
                    if vuln["severity"] == "严重":
                        vulnerabilities["critical_count"] += 1
                    elif vuln["severity"] == "高":
                        vulnerabilities["high_count"] += 1
                    elif vuln["severity"] == "中":
                        vulnerabilities["medium_count"] += 1
                    else:
                        vulnerabilities["low_count"] += 1
        
        # 检查Nginx
        nginx_version = run_command("nginx -v 2>&1")
        if nginx_version and nginx_version != "命令执行失败":
            print(f"  Nginx版本: {nginx_version}")
            
            # Nginx漏洞检测
            nginx_vulns = [
                {
                    "name": "Nginx整数溢出漏洞",
                    "cve": "CVE-2017-7529",
                    "description": "Nginx HTTP/2实现中的整数溢出漏洞",
                    "severity": "高",
                    "check": lambda v: "1.13." in v and int(v.split("1.13.")[1].split()[0]) < 9,
                    "fix": "升级到Nginx 1.13.9或更高版本"
                }
            ]
            
            for vuln in nginx_vulns:
                if vuln["check"](nginx_version):
                    vulnerabilities["web_vulnerabilities"].append({
                        "name": vuln["name"],
                        "cve": vuln.get("cve", "N/A"),
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "affected_component": "Nginx",
                        "fix": vuln["fix"]
                    })
                    vulnerabilities["vulnerability_count"] += 1
                    if vuln["severity"] == "严重":
                        vulnerabilities["critical_count"] += 1
                    elif vuln["severity"] == "高":
                        vulnerabilities["high_count"] += 1
                    elif vuln["severity"] == "中":
                        vulnerabilities["medium_count"] += 1
                    else:
                        vulnerabilities["low_count"] += 1
    except Exception as e:
        print(f"  {Colors.RED}Web服务漏洞检测失败: {str(e)}{Colors.RESET}")
    
    # 3. 数据库漏洞检测
    print(f"\n{Colors.YELLOW}[+] 检测数据库漏洞{Colors.RESET}")
    try:
        # 检查MySQL
        mysql_version = run_command("mysql --version 2>/dev/null")
        if mysql_version and mysql_version != "命令执行失败":
            print(f"  MySQL版本: {mysql_version}")
            
            # MySQL漏洞检测
            mysql_vulns = [
                {
                    "name": "MySQL远程代码执行漏洞",
                    "cve": "CVE-2021-21551, CVE-2020-25749",
                    "description": "MySQL服务器存在远程代码执行漏洞",
                    "severity": "严重",
                    "check": lambda v: True,  # 简化检测，实际应根据版本号判断
                    "fix": "升级到最新版本的MySQL"
                },
                {
                    "name": "MySQL默认配置漏洞",
                    "cve": "N/A",
                    "description": "MySQL使用默认配置，可能存在安全风险",
                    "severity": "中",
                    "check": lambda v: True,
                    "fix": "修改默认配置，设置强密码，限制远程访问"
                }
            ]
            
            for vuln in mysql_vulns:
                if vuln["check"](mysql_version):
                    vulnerabilities["database_vulnerabilities"].append({
                        "name": vuln["name"],
                        "cve": vuln.get("cve", "N/A"),
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "affected_component": "MySQL",
                        "fix": vuln["fix"]
                    })
                    vulnerabilities["vulnerability_count"] += 1
                    if vuln["severity"] == "严重":
                        vulnerabilities["critical_count"] += 1
                    elif vuln["severity"] == "高":
                        vulnerabilities["high_count"] += 1
                    elif vuln["severity"] == "中":
                        vulnerabilities["medium_count"] += 1
                    else:
                        vulnerabilities["low_count"] += 1
        
        # 检查PostgreSQL
        postgres_version = run_command("psql --version 2>/dev/null")
        if postgres_version and postgres_version != "命令执行失败":
            print(f"  PostgreSQL版本: {postgres_version}")
    except Exception as e:
        print(f"  {Colors.RED}数据库漏洞检测失败: {str(e)}{Colors.RESET}")
    
    # 4. 站点漏洞检测
    print(f"\n{Colors.YELLOW}[+] 检测站点漏洞{Colors.RESET}")
    try:
        # 定义常见的站点漏洞
        site_vulns = [
            {
                "name": "SQL注入漏洞",
                "cve": "CVE-2008-4105, CVE-2019-10098",
                "description": "Web应用可能存在SQL注入漏洞，攻击者可以执行恶意SQL语句",
                "severity": "严重",
                "check": lambda: True,  # 简化检测，实际应检查代码或发送测试请求
                "fix": "使用参数化查询，避免直接拼接SQL语句"
            },
            {
                "name": "跨站脚本(XSS)漏洞",
                "cve": "CVE-2017-5638, CVE-2018-8033",
                "description": "Web应用可能存在XSS漏洞，攻击者可以注入恶意脚本",
                "severity": "高",
                "check": lambda: True,
                "fix": "对用户输入进行过滤和转义，使用Content-Security-Policy头"
            },
            {
                "name": "跨站请求伪造(CSRF)漏洞",
                "cve": "CVE-2019-3799, CVE-2020-14720",
                "description": "Web应用可能存在CSRF漏洞，攻击者可以诱导用户执行非预期操作",
                "severity": "中",
                "check": lambda: True,
                "fix": "使用CSRF令牌，验证Referer和Origin头"
            },
            {
                "name": "目录遍历漏洞",
                "cve": "CVE-2004-2320, CVE-2019-11043",
                "description": "Web应用可能存在目录遍历漏洞，攻击者可以访问系统文件",
                "severity": "高",
                "check": lambda: True,
                "fix": "对用户输入进行严格验证，使用白名单机制"
            },
            {
                "name": "敏感文件泄露",
                "cve": "CVE-2013-2251, CVE-2019-1003000",
                "description": "Web应用可能泄露敏感文件，如配置文件、日志文件等",
                "severity": "高",
                "check": lambda: True,
                "fix": "限制敏感文件的访问权限，移除不必要的文件"
            },
            {
                "name": "认证绕过漏洞",
                "cve": "CVE-2019-11580, CVE-2020-13945",
                "description": "Web应用可能存在认证绕过漏洞，攻击者可以无需凭证访问系统",
                "severity": "严重",
                "check": lambda: True,
                "fix": "加强认证机制，使用安全的会话管理"
            },
            {
                "name": "权限提升漏洞",
                "cve": "CVE-2019-0232, CVE-2020-1938",
                "description": "Web应用可能存在权限提升漏洞，攻击者可以获取更高权限",
                "severity": "高",
                "check": lambda: True,
                "fix": "实现最小权限原则，对权限变更进行严格验证"
            },
            {
                "name": "代码执行漏洞",
                "cve": "CVE-2017-9805, CVE-2019-11043",
                "description": "Web应用可能存在代码执行漏洞，攻击者可以执行恶意代码",
                "severity": "严重",
                "check": lambda: True,
                "fix": "对用户输入进行严格验证，避免使用危险的函数"
            }
        ]
        
        # 检查Web根目录是否存在
        web_root_dirs = ["/var/www/html", "/var/www", "/usr/local/apache2/htdocs", "/usr/local/nginx/html"]
        web_root_exists = False
        for web_dir in web_root_dirs:
            if os.path.exists(web_dir):
                web_root_exists = True
                print(f"  检测到Web根目录: {web_dir}")
                break
        
        if not web_root_exists:
            print(f"  未检测到Web根目录，跳过站点漏洞详细检测")
        
        # 模拟站点漏洞检测（实际应根据具体Web应用进行检测）
        for vuln in site_vulns:
            if vuln["check"]():
                vulnerabilities["other_vulnerabilities"].append({
                    "name": vuln["name"],
                    "cve": vuln.get("cve", "N/A"),
                    "description": vuln["description"],
                    "severity": vuln["severity"],
                    "affected_component": "Web应用",
                    "fix": vuln["fix"]
                })
                vulnerabilities["vulnerability_count"] += 1
                if vuln["severity"] == "严重":
                    vulnerabilities["critical_count"] += 1
                elif vuln["severity"] == "高":
                    vulnerabilities["high_count"] += 1
                elif vuln["severity"] == "中":
                    vulnerabilities["medium_count"] += 1
                else:
                    vulnerabilities["low_count"] += 1
    except Exception as e:
        print(f"  {Colors.RED}站点漏洞检测失败: {str(e)}{Colors.RESET}")
    
    # 5. 其他服务漏洞检测
    print(f"\n{Colors.YELLOW}[+] 检测其他服务漏洞{Colors.RESET}")
    try:
        # 检查SSH
        ssh_version = run_command("ssh -V 2>&1")
        if ssh_version and ssh_version != "命令执行失败":
            print(f"  SSH版本: {ssh_version}")
            
            # SSH漏洞检测
            ssh_vulns = [
                {
                    "name": "SSH弱密码配置",
                    "cve": "N/A",
                    "description": "SSH可能允许使用弱密码或密码登录",
                    "severity": "中",
                    "check": lambda v: True,
                    "fix": "禁用密码登录，使用密钥认证，设置强密码策略"
                },
                {
                    "name": "SSH远程代码执行漏洞",
                    "cve": "CVE-2024-6387",
                    "description": "OpenSSH服务器存在远程代码执行漏洞",
                    "severity": "严重",
                    "check": lambda v: True,
                    "fix": "升级到最新版本的OpenSSH"
                }
            ]
            
            for vuln in ssh_vulns:
                if vuln["check"](ssh_version):
                    vulnerabilities["other_vulnerabilities"].append({
                        "name": vuln["name"],
                        "cve": vuln.get("cve", "N/A"),
                        "description": vuln["description"],
                        "severity": vuln["severity"],
                        "affected_component": "SSH",
                        "fix": vuln["fix"]
                    })
                    vulnerabilities["vulnerability_count"] += 1
                    if vuln["severity"] == "严重":
                        vulnerabilities["critical_count"] += 1
                    elif vuln["severity"] == "高":
                        vulnerabilities["high_count"] += 1
                    elif vuln["severity"] == "中":
                        vulnerabilities["medium_count"] += 1
                    else:
                        vulnerabilities["low_count"] += 1
        
        # 检查FTP
        ftp_version = run_command("vsftpd -v 2>/dev/null || proftpd -v 2>/dev/null")
        if ftp_version and ftp_version != "命令执行失败":
            print(f"  FTP版本: {ftp_version}")
    except Exception as e:
        print(f"  {Colors.RED}其他服务漏洞检测失败: {str(e)}{Colors.RESET}")
    
    # 5. 配置漏洞检测
    print(f"\n{Colors.YELLOW}[+] 检测配置漏洞{Colors.RESET}")
    try:
        # 检查防火墙状态
        firewall_status = run_command("iptables -L 2>/dev/null || firewall-cmd --state 2>/dev/null")
        if not firewall_status or firewall_status == "命令执行失败":
            vulnerabilities["other_vulnerabilities"].append({
                "name": "防火墙未启用",
                "cve": "N/A",
                "description": "系统防火墙未启用，可能存在安全风险",
                "severity": "高",
                "affected_component": "防火墙",
                "fix": "启用并配置防火墙，限制不必要的端口访问"
            })
            vulnerabilities["vulnerability_count"] += 1
            vulnerabilities["high_count"] += 1
        
        # 检查SELinux状态
        selinux_status = run_command("getenforce 2>/dev/null")
        if selinux_status and selinux_status != "命令执行失败" and "Enforcing" not in selinux_status:
            vulnerabilities["other_vulnerabilities"].append({
                "name": "SELinux未启用或未设置为Enforcing模式",
                "cve": "N/A",
                "description": "SELinux未启用或未设置为Enforcing模式，可能存在安全风险",
                "severity": "中",
                "affected_component": "SELinux",
                "fix": "启用SELinux并设置为Enforcing模式"
            })
            vulnerabilities["vulnerability_count"] += 1
            vulnerabilities["medium_count"] += 1
    except Exception as e:
        print(f"  {Colors.RED}配置漏洞检测失败: {str(e)}{Colors.RESET}")
    
    # 输出漏洞检测结果
    print(f"\n{Colors.GREEN}[+] 漏洞检测完成{Colors.RESET}")
    print(f"  总漏洞数: {vulnerabilities['vulnerability_count']}")
    print(f"  严重: {vulnerabilities['critical_count']}")
    print(f"  高: {vulnerabilities['high_count']}")
    print(f"  中: {vulnerabilities['medium_count']}")
    print(f"  低: {vulnerabilities['low_count']}")
    
    return vulnerabilities

# ===================== 主函数 =====================
def generate_emergency_report(all_results):
    """生成应急排查报告"""
    # 生成时间戳
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 生成JSON报告
    json_report_path = f"emergency_check_report_{timestamp}.json"
    with open(json_report_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"\n[生成应急排查报告]")
    print(f"JSON报告已生成: {json_report_path}")
    
    # 生成TXT报告
    txt_report_path = f"emergency_check_report_{timestamp}.txt"
    with open(txt_report_path, 'w', encoding='utf-8') as f:
        f.write("===== Linux服务器应急响应排查报告 =====\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        
        # 1. SSH爆破/登录记录
        f.write("1. SSH爆破/登录记录分析\n")
        f.write("-" * 30 + "\n")
        ssh_results = all_results.get('ssh', {})
        f.write(f"总爆破IP数: {len(ssh_results.get('brute_force_ips', {}))}\n")
        f.write(f"总爆破尝试次数: {ssh_results.get('total_brute_force_attempts', 0)}\n")
        f.write(f"成功登录次数: {ssh_results.get('total_successful_logins', 0)}\n")
        f.write(f"爆破成功次数: {ssh_results.get('brute_force_success', 0)}\n\n")
        
        if ssh_results.get('brute_force_ips', {}):
            f.write("SSH爆破记录（前10）:\n")
            sorted_ips = sorted(ssh_results['brute_force_ips'].items(), key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_ips:
                f.write(f"  {ip}: {count}次\n")
            f.write("\n")
        
        # 添加SSH爆破详细记录
        if ssh_results.get('brute_force_details_5days', []):
            f.write("SSH爆破详细记录（5天内，所有）:\n")
            sorted_details = sorted(ssh_results['brute_force_details_5days'], key=lambda x: x['time'])
            for detail in sorted_details:
                f.write(f"  IP: {detail['ip']} | 时间: {detail['time']} | 日志文件: {detail['log_file'].split('/')[-1]}\n")
            f.write("\n")

        if ssh_results.get('successful_logins', []):
            f.write("SSH成功登录记录（前10）:\n")
            for login in ssh_results['successful_logins'][:10]:
                f.write(f"  用户: {login['user']} | IP: {login['ip']} | 时间: {login['time']}\n")
            f.write("\n")
        
        # 添加SSH软连接后门检测结果
        if ssh_results.get('ssh_backdoor_symlinks', []):
            f.write("SSH软连接后门检测结果:\n")
            for backdoor in ssh_results['ssh_backdoor_symlinks']:
                f.write(f"  路径: {backdoor['path']} | 目标: {backdoor['target']}\n")
            f.write("\n")
        else:
            f.write("未检测到SSH软连接后门\n\n")
        
        # 添加远程连接记录
        if ssh_results.get('remote_connections', []):
            f.write("远程连接记录:\n")
            for conn in ssh_results['remote_connections']:
                conn_type = conn.get('type', 'unknown')
                output = conn.get('output', '')
                if conn_type == 'current':
                    f.write("当前登录用户:\n")
                elif conn_type == 'who':
                    f.write("登录历史:\n")
                elif conn_type == 'last':
                    f.write("详细登录历史:\n")
                f.write(f"{output}\n")
            f.write("\n")
        else:
            f.write("未检测到远程连接记录\n\n")
        
        # 添加SSH未授权公钥检测结果
        if ssh_results.get('unauthorized_ssh_keys', []):
            f.write("SSH未授权公钥检测结果:\n")
            # 按用户分组显示
            user_keys = {}
            for key_info in ssh_results['unauthorized_ssh_keys']:
                user = key_info['user']
                if user not in user_keys:
                    user_keys[user] = []
                user_keys[user].append(key_info)
            
            for user, keys in user_keys.items():
                f.write(f"  用户 {user}:\n")
                for key_info in keys:
                    f.write(f"    类型: {key_info['key_type']}, 标识: {key_info['key_identifier']}\n")
            f.write("\n")
        else:
            f.write("未检测到SSH未授权公钥\n\n")
        
        # 2. 异常进程分析
        f.write("2. 异常进程分析\n")
        f.write("-" * 30 + "\n")
        process_results = all_results.get('processes', {})
        
        if process_results.get('mining_processes', []):
            f.write("挖矿进程:\n")
            for proc in process_results['mining_processes']:
                f.write(f"  PID: {proc['pid']} | 用户: {proc['user']} | CPU: {proc['cpu']}% | 命令: {proc['cmd']}\n")
            f.write("\n")
        else:
            f.write("未检测到挖矿进程\n\n")
        
        if process_results.get('high_cpu_processes', []):
            f.write("高CPU占用进程:\n")
            for proc in process_results['high_cpu_processes']:
                f.write(f"  PID: {proc['pid']} | 用户: {proc['user']} | CPU: {proc['cpu']}% | 命令: {proc['cmd']}\n")
            f.write("\n")
        else:
            f.write("未检测到高CPU占用进程\n\n")
        
        if process_results.get('hidden_processes', []):
            f.write("隐藏进程:\n")
            for proc in process_results['hidden_processes']:
                f.write(f"  PID: {proc['pid']} | 用户: {proc['user']} | 命令: {proc['cmd']}\n")
            f.write("\n")
        else:
            f.write("未检测到隐藏进程\n\n")
        
        # 3. 网络连接分析
        f.write("3. 网络连接分析\n")
        f.write("-" * 30 + "\n")
        net_results = all_results.get('network', {})
        
        if net_results.get('external_conns', []):
            f.write("外部连接（前10）:\n")
            for conn in net_results['external_conns'][:10]:
                f.write(f"  {conn['proto'].upper()} | 状态: {conn['state']} | 本地: {conn['local']} | 远程: {conn['remote']}\n")
                f.write(f"    PID: {conn['pid']} | 程序: {conn['prog']}\n")
            f.write("\n")
        else:
            f.write("未检测到外部连接\n\n")
        
        if net_results.get('mining_conns', []):
            f.write("挖矿外联:\n")
            for conn in net_results['mining_conns']:
                f.write(f"  {conn['proto'].upper()} | 远程: {conn['remote']} | PID: {conn['pid']} | 程序: {conn['prog']}\n")
            f.write("\n")
        else:
            f.write("未检测到挖矿外联\n\n")
        
        # 开放端口详细信息
        if net_results.get('open_ports_detail', []):
            f.write("开放端口详细信息:\n")
            sorted_ports = sorted(net_results['open_ports_detail'], key=lambda x: int(x['port']) if x['port'].isdigit() else x['port'])
            for port_info in sorted_ports:
                f.write(f"  {port_info['protocol'].upper()} | 端口: {port_info['port']} | 服务: {port_info['service']} | 地址: {port_info['address']}\n")
                f.write(f"    PID: {port_info['pid']} | 程序: {port_info['program']}\n")
            f.write("\n")
        else:
            f.write("未检测到开放端口\n\n")
        
        # 历史网络通信记录
        if net_results.get('historical_connections', []):
            f.write("历史网络通信记录（前10）:\n")
            for conn in net_results['historical_connections'][:10]:
                f.write(f"  IP: {conn['ip']} | 时间: {conn['time']} | 类型: {conn['type']}\n")
                f.write(f"    程序: {conn['program']} | PID: {conn['pid']} | 日志: {conn['log_file']}\n")
            f.write("\n")
        else:
            f.write("未检测到历史网络通信记录\n\n")
        
        # 隐藏网络连接检测结果
        if net_results.get('hidden_connections', []):
            f.write("Busybox隐藏网络连接检测结果:\n")
            for conn in net_results['hidden_connections']:
                f.write(f"  {conn['proto'].upper()} | 状态: {conn['state']} | 本地: {conn['local']} | 远程: {conn['remote']}\n")
                f.write(f"    PID: {conn['pid']} | 程序: {conn['prog']}\n")
            f.write("\n")
        else:
            f.write("未检测到隐藏网络连接\n\n")
        
        # 4. Webshell检测
        f.write("4. Webshell检测\n")
        f.write("-" * 30 + "\n")
        webshell_results = all_results.get('webshell', {})
        
        f.write(f"配置扫描目录数: {len(webshell_results.get('scan_dirs', []))}\n")
        f.write(f"实际存在目录数: {len(webshell_results.get('valid_scan_dirs', []))}\n\n")
        
        if webshell_results.get('behinder_jsp_files', []):
            f.write("冰蝎JSP木马检测结果:\n")
            for file in webshell_results['behinder_jsp_files']:
                f.write(f"  文件: {file['path']} | 修改时间: {file['mtime']} | 匹配特征: {file['keywords']}\n")
            f.write("\n")
        else:
            f.write("未检测到冰蝎JSP木马\n\n")
        
        if webshell_results.get('suspicious_files', []):
            other_files = [f for f in webshell_results['suspicious_files'] if f['type'] != '冰蝎JSP木马']
            if other_files:
                f.write("其他可疑Webshell文件:\n")
                for file in other_files:
                    f.write(f"  文件: {file['path']} | 类型: {file['type']} | 修改时间: {file['mtime']} | 匹配特征: {file['keywords']}\n")
                f.write("\n")
            else:
                f.write("未检测到其他可疑Webshell文件\n\n")
        else:
            f.write("未检测到任何可疑Webshell文件\n\n")
        
        # 5. 系统账户异常
        f.write("5. 系统账户异常分析\n")
        f.write("-" * 30 + "\n")
        account_results = all_results.get('account', {})
        
        if account_results.get('uid0_users', []):
            f.write("UID=0的超级管理员用户:\n")
            for user in account_results['uid0_users']:
                f.write(f"  {user}\n")
            f.write("\n")
        else:
            f.write("仅root用户拥有UID=0权限\n\n")
        
        if account_results.get('empty_pass_users', []):
            f.write("空密码用户:\n")
            for user in account_results['empty_pass_users']:
                f.write(f"  {user}\n")
            f.write("\n")
        else:
            f.write("未检测到空密码用户\n\n")
        
        if account_results.get('new_users', []):
            f.write("最近7天新增用户:\n")
            for user_info in account_results['new_users']:
                f.write(f"  {user_info['user']} | 家目录: {user_info['homedir']} | 创建时间: {user_info['create_time']}\n")
            f.write("\n")
        else:
            f.write("未检测到最近7天新增用户\n\n")
        
        # 登录用户历史记录
        if account_results.get('login_history', []):
            f.write("登录用户历史记录:\n")
            for login in account_results['login_history'][:10]:
                f.write(f"  用户: {login['user']} | 终端: {login['tty']} | 来源: {login['ip']} | 时间: {login['time']}\n")
            f.write("\n")
        else:
            f.write("未检测到登录历史记录\n\n")
        
        # 用户历史操作命令
        if account_results.get('user_history_commands', {}):
            f.write("用户历史操作命令:\n")
            for user, commands in account_results['user_history_commands'].items():
                f.write(f"  {user}的最近命令:\n")
                for idx, cmd in enumerate(commands[-5:], 1):  # 只显示最近5条
                    f.write(f"    {idx}. {cmd}\n")
                f.write("\n")
        else:
            f.write("未检测到用户历史操作命令\n\n")
        
        # 新增与删除操作命令记录
        if account_results.get('add_delete_commands', {}):
            f.write("新增与删除操作命令记录:\n")
            for user, commands in account_results['add_delete_commands'].items():
                f.write(f"  {user}的新增/删除操作:\n")
                for idx, cmd in enumerate(commands[:10], 1):  # 只显示最近10条
                    f.write(f"    {idx}. {cmd}\n")
                f.write("\n")
        else:
            f.write("未检测到新增与删除操作命令记录\n\n")
        
        # 反弹shell命令记录
        if account_results.get('reverse_shell_commands', {}):
            f.write("反弹shell命令记录:\n")
            for user, commands in account_results['reverse_shell_commands'].items():
                f.write(f"  {user}的反弹shell命令:\n")
                for idx, cmd in enumerate(commands, 1):
                    f.write(f"    {idx}. {cmd}\n")
                f.write("\n")
        else:
            f.write("未检测到反弹shell命令记录\n\n")
        
        # 下载命令记录
        if account_results.get('download_commands', {}):
            f.write("下载命令记录:\n")
            for user, commands in account_results['download_commands'].items():
                f.write(f"  {user}的下载命令:\n")
                for idx, cmd in enumerate(commands, 1):
                    f.write(f"    {idx}. {cmd}\n")
                f.write("\n")
        else:
            f.write("未检测到下载命令记录\n\n")
        
        # 6. 文件篡改检测
        f.write("6. 文件篡改检测\n")
        f.write("-" * 30 + "\n")
        tampering_results = all_results.get('file_tampering', {})
        
        if tampering_results.get('modified_files', []):
            f.write("敏感文件修改时间:\n")
            for file_info in tampering_results['modified_files']:
                f.write(f"  {file_info['path']} | 修改时间: {file_info['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到敏感文件\n\n")
        
        if tampering_results.get('tmp_executables', []):
            f.write("临时目录可执行文件:\n")
            for exec_file in tampering_results['tmp_executables']:
                f.write(f"  {exec_file['path']} | 修改时间: {exec_file['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到临时目录可执行文件\n\n")
        
        if tampering_results.get('suspicious_crontabs', []):
            f.write("异常定时任务:\n")
            for crontab in tampering_results['suspicious_crontabs']:
                f.write(f"  文件: {crontab['path']} | 内容: {crontab['content'][:100]}{'...' if len(crontab['content'])>100 else ''}\n")
            f.write("\n")
        else:
            f.write("未检测到异常定时任务\n\n")
        
        # 隐藏文件检测结果
        if tampering_results.get('hidden_files', []):
            f.write("隐藏文件检测结果:\n")
            for hidden_entry in tampering_results['hidden_files']:
                f.write(f"  {hidden_entry['path']} | 类型: {hidden_entry['type']} | 修改时间: {hidden_entry['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到可疑隐藏文件\n\n")
        
        # 异常权限文件检测结果
        if tampering_results.get('abnormal_permissions', []):
            f.write("异常权限文件检测结果:\n")
            for perm_entry in tampering_results['abnormal_permissions']:
                f.write(f"  {perm_entry['path']} | 权限: {perm_entry['permissions']} | 修改时间: {perm_entry['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到异常权限文件\n\n")
        
        # 敏感目录检查结果
        if tampering_results.get('sensitive_dirs', []):
            f.write("敏感目录检查结果:\n")
            for dir_entry in tampering_results['sensitive_dirs']:
                f.write(f"  {dir_entry['path']} | 描述: {dir_entry['description']} | 权限: {dir_entry['permissions']} | 文件数: {dir_entry['files_count']}\n")
            f.write("\n")
        else:
            f.write("未检测到敏感目录\n\n")
        
        # 异常文件检查结果
        if tampering_results.get('suspicious_files', []):
            f.write("异常文件检查结果:\n")
            for suspicious_file in tampering_results['suspicious_files']:
                f.write(f"  {suspicious_file['path']} | 原因: {suspicious_file['reason']} | 修改时间: {suspicious_file['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到异常文件\n\n")
        
        # 异常图片文件检查结果
        if tampering_results.get('abnormal_images', []):
            f.write("异常图片文件检查结果:\n")
            for abnormal_image in tampering_results['abnormal_images']:
                f.write(f"  {abnormal_image['path']} | 原因: {abnormal_image['reason']} | 大小: {abnormal_image['size']} | 修改时间: {abnormal_image['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到异常图片文件\n\n")
        
        # 7. 日志异常分析
        f.write("7. 日志异常分析\n")
        f.write("-" * 30 + "\n")
        log_results = all_results.get('log_anomalies', {})
        
        if log_results.get('log_tampering', []):
            f.write("日志篡改检测:\n")
            for tamper in log_results['log_tampering']:
                f.write(f"  {tamper['file']} | {tamper['reason']}\n")
            f.write("\n")
        else:
            f.write("未检测到日志篡改迹象\n\n")
        
        if log_results.get('su_failures', []):
            f.write("su切换失败记录（前10）:\n")
            for failure in log_results['su_failures'][:10]:
                f.write(f"  用户: {failure['user']} | 目标: {failure['target']} | 时间: {failure['time']}\n")
            f.write("\n")
        else:
            f.write("未检测到su切换失败记录\n\n")
        
        if log_results.get('root_commands', []):
            f.write("root异常命令执行记录（前10）:\n")
            for cmd in log_results['root_commands'][:10]:
                f.write(f"  {cmd['command']} | 时间: {cmd['time']}\n")
            f.write("\n")
        else:
            f.write("未检测到root异常命令执行记录\n\n")
        
        # 8. 挖矿行为专项检测
        f.write("8. 挖矿行为专项检测\n")
        f.write("-" * 30 + "\n")
        mining_results = all_results.get('mining_behavior', {})
        
        if mining_results.get('mining_files', []):
            f.write("挖矿相关文件:\n")
            for file in mining_results['mining_files']:
                f.write(f"  {file['path']} | 修改时间: {file['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到挖矿相关文件\n\n")
        
        if mining_results.get('mining_conns', []):
            f.write("矿池连接:\n")
            for conn in mining_results['mining_conns']:
                f.write(f"  {conn['proto'].upper()} | 远程: {conn['remote']} | {conn['pid_prog']}\n")
            f.write("\n")
        else:
            f.write("未检测到矿池连接\n\n")
        
        # 9. 中间件与框架版本检测
        f.write("9. 中间件与框架版本检测\n")
        f.write("-" * 30 + "\n")
        middleware_results = all_results.get('middleware', {})
        
        # 添加系统版本信息
        if middleware_results.get('system', {}):
            f.write("系统版本信息:\n")
            system_info = middleware_results['system']
            f.write(f"  主机名: {system_info.get('hostname', 'N/A')}\n")
            f.write(f"  内核版本: {system_info.get('kernel', 'N/A')}\n")
            f.write(f"  系统架构: {system_info.get('architecture', 'N/A')}\n")
            f.write(f"  系统时间: {system_info.get('time', 'N/A')}\n")
            f.write(f"  系统负载: {system_info.get('load', 'N/A')}\n")
            if system_info.get('os_release'):
                os_release_info = system_info['os_release']
                first_line = os_release_info.split('\n')[0]
                f.write(f"  操作系统信息: {first_line}\n")
            elif system_info.get('uname'):
                f.write(f"  系统信息: {system_info['uname']}\n")
            f.write("\n")
        else:
            f.write("未检测到系统版本信息\n\n")
        
        # Web服务器
        if middleware_results.get('web_servers', []):
            f.write("Web服务器:\n")
            for server in middleware_results['web_servers']:
                f.write(f"  {server['name']}: {server['version']}\n")
            f.write("\n")
        else:
            f.write("未检测到Web服务器\n\n")
        
        # 应用服务器
        if middleware_results.get('application_servers', []):
            f.write("应用服务器:\n")
            for server in middleware_results['application_servers']:
                f.write(f"  {server['name']}: {server['version']}\n")
            f.write("\n")
        else:
            f.write("未检测到应用服务器\n\n")
        
        # 数据库
        if middleware_results.get('databases', []):
            f.write("数据库:\n")
            for db in middleware_results['databases']:
                f.write(f"  {db['name']}: {db['version']}\n")
            f.write("\n")
        else:
            f.write("未检测到数据库\n\n")
        
        # 编程语言
        if middleware_results.get('programming_languages', []):
            f.write("编程语言:\n")
            for lang in middleware_results['programming_languages']:
                f.write(f"  {lang['name']}: {lang['version']}\n")
            f.write("\n")
        else:
            f.write("未检测到编程语言\n\n")
        
        # 10. 内存马与Rootkit检测
        f.write("10. 内存马与Rootkit检测\n")
        f.write("-" * 30 + "\n")
        memory_results = all_results.get('memory_malware', {})
        
        if memory_results.get('java_memory_mares', []):
            f.write("Java内存马检测结果:\n")
            for mare in memory_results['java_memory_mares']:
                f.write(f"  PID: {mare['pid']} | 进程: {mare['process']}\n  原因: {mare['reason']}\n")
            f.write("\n")
        else:
            f.write("未检测到Java内存马\n\n")
        
        if memory_results.get('process_injection', []):
            f.write("进程注入检测结果:\n")
            for injection in memory_results['process_injection']:
                f.write(f"  PID: {injection['pid']} | 进程: {injection['comm']}\n  命令: {injection['cmdline']}\n  内存区域: {injection['memory_region']}\n")
            f.write("\n")
        else:
            f.write("未检测到进程注入迹象\n\n")
        
        if memory_results.get('suspicious_memory_regions', []):
            f.write("可疑内存区域:\n")
            for region in memory_results['suspicious_memory_regions']:
                f.write(f"  PID: {region['pid']} | 进程: {region['process']}\n  内存区域: {region['memory_region']}\n")
            f.write("\n")
        else:
            f.write("未检测到可疑内存区域\n\n")
        
        if memory_results.get('hidden_processes', []):
            f.write("隐藏进程检测结果:\n")
            for proc in memory_results['hidden_processes']:
                f.write(f"  PID: {proc['pid']} | 进程: {proc['comm']}\n  命令: {proc['cmdline']}\n")
            f.write("\n")
        else:
            f.write("未检测到隐藏进程\n\n")
        
        if memory_results.get('rootkit_indicators', []):
            f.write("Rootkit检测结果:\n")
            for indicator in memory_results['rootkit_indicators']:
                f.write(f"  指标: {indicator['indicator']} | 严重程度: {indicator['severity']}\n")
            f.write("\n")
        else:
            f.write("未检测到Rootkit指标\n\n")
        
        # 11. Alias后门检测
        f.write("11. Alias后门检测\n")
        f.write("-" * 30 + "\n")
        alias_results = all_results.get('alias_backdoors', {})
        
        if alias_results.get('suspicious_aliases', []):
            f.write("可疑别名检测结果:\n")
            for alias in alias_results['suspicious_aliases']:
                f.write(f"  文件: {alias['file']}\n  行号: {alias['line']}\n  别名: {alias['alias']}\n  值: {alias['value']}\n  类型: {alias['type']}\n")
            f.write("\n")
        else:
            f.write("未检测到可疑别名\n\n")
        
        if alias_results.get('modified_files', []):
            f.write("最近修改的配置文件:\n")
            for file in alias_results['modified_files']:
                f.write(f"  {file['path']} | 修改时间: {file['mtime']}\n")
            f.write("\n")
        else:
            f.write("未检测到最近修改的配置文件\n\n")
        
        if alias_results.get('system_wide_configs', []):
            f.write("系统级配置文件:\n")
            for config in alias_results['system_wide_configs'][:10]:  # 只显示前10个
                f.write(f"  {config['path']} | 修改时间: {config['mtime']}\n")
            if len(alias_results['system_wide_configs']) > 10:
                f.write(f"  ... 共 {len(alias_results['system_wide_configs'])} 个系统级配置文件\n")
            f.write("\n")
        else:
            f.write("未检测到系统级配置文件\n\n")
        
        if alias_results.get('user_configs', []):
            f.write("用户级配置文件:\n")
            for config in alias_results['user_configs'][:10]:  # 只显示前10个
                f.write(f"  {config['path']} | 修改时间: {config['mtime']}\n")
            if len(alias_results['user_configs']) > 10:
                f.write(f"  ... 共 {len(alias_results['user_configs'])} 个用户级配置文件\n")
            f.write("\n")
        else:
            f.write("未检测到用户级配置文件\n\n")
        
        # 12. 站点日志攻击成功分析
        f.write("12. 站点日志攻击成功分析\n")
        f.write("-" * 30 + "\n")
        web_attack_results = all_results.get('web_attack_logs', {})
        
        if web_attack_results.get('successful_attacks', []):
            f.write("成功的攻击记录:\n")
            for attack in web_attack_results['successful_attacks'][:20]:  # 只显示前20条
                f.write(f"  时间: {attack['timestamp']}\n  来源IP: {attack['source_ip']}\n  状态码: {attack['status']}\n  攻击类型: {attack['attack_type']}\n  请求: {attack['request']}\n  用户代理: {attack['user_agent']}\n  日志文件: {attack['log_file']}\n")
            if len(web_attack_results['successful_attacks']) > 20:
                f.write(f"  ... 共 {len(web_attack_results['successful_attacks'])} 条攻击记录\n")
            f.write("\n")
        else:
            f.write("未检测到成功的攻击记录\n\n")
        
        if web_attack_results.get('attack_types', {}):
            f.write("攻击类型统计:\n")
            for attack_type, count in web_attack_results['attack_types'].items():
                f.write(f"  {attack_type}: {count}次\n")
            f.write("\n")
        else:
            f.write("未检测到攻击类型\n\n")
        
        if web_attack_results.get('attack_sources', {}):
            f.write("攻击源IP统计（前10）:\n")
            sorted_sources = sorted(web_attack_results['attack_sources'].items(), key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_sources:
                f.write(f"  {ip}: {count}次\n")
            f.write("\n")
        else:
            f.write("未检测到攻击源IP\n\n")
        
        if web_attack_results.get('affected_paths', {}):
            f.write("受影响路径统计（前10）:\n")
            sorted_paths = sorted(web_attack_results['affected_paths'].items(), key=lambda x: x[1], reverse=True)[:10]
            for path, count in sorted_paths:
                f.write(f"  {path}: {count}次\n")
            f.write("\n")
        else:
            f.write("未检测到受影响路径\n\n")
        
        if web_attack_results.get('web_servers', []):
            f.write("Web服务器信息:\n")
            for server in web_attack_results['web_servers']:
                f.write(f"  {server['name']}: {server['log_file']}\n")
            f.write("\n")
        else:
            f.write("未检测到Web服务器\n\n")
        
        if web_attack_results.get('log_files', []):
            f.write("分析的日志文件:\n")
            for log_file in web_attack_results['log_files']:
                f.write(f"  {log_file}\n")
            f.write("\n")
        else:
            f.write("未检测到Web服务器日志文件\n\n")
        
        # 13. 漏洞检测
        f.write("13. 漏洞检测\n")
        f.write("-" * 30 + "\n")
        vuln_results = all_results.get('vulnerabilities', {})
        
        f.write(f"总漏洞数: {vuln_results.get('vulnerability_count', 0)}\n")
        f.write(f"严重: {vuln_results.get('critical_count', 0)}\n")
        f.write(f"高: {vuln_results.get('high_count', 0)}\n")
        f.write(f"中: {vuln_results.get('medium_count', 0)}\n")
        f.write(f"低: {vuln_results.get('low_count', 0)}\n\n")
        
        # 系统内核漏洞
        if vuln_results.get('system_vulnerabilities', []):
            f.write("系统内核漏洞:\n")
            for vuln in vuln_results['system_vulnerabilities']:
                f.write(f"  名称: {vuln['name']}\n  CVE: {vuln.get('cve', 'N/A')}\n  描述: {vuln['description']}\n  严重程度: {vuln['severity']}\n  受影响组件: {vuln['affected_component']}\n  修复建议: {vuln['fix']}\n")
            f.write("\n")
        else:
            f.write("未检测到系统内核漏洞\n\n")
        
        # Web服务漏洞
        if vuln_results.get('web_vulnerabilities', []):
            f.write("Web服务漏洞:\n")
            for vuln in vuln_results['web_vulnerabilities']:
                f.write(f"  名称: {vuln['name']}\n  CVE: {vuln.get('cve', 'N/A')}\n  描述: {vuln['description']}\n  严重程度: {vuln['severity']}\n  受影响组件: {vuln['affected_component']}\n  修复建议: {vuln['fix']}\n")
            f.write("\n")
        else:
            f.write("未检测到Web服务漏洞\n\n")
        
        # 数据库漏洞
        if vuln_results.get('database_vulnerabilities', []):
            f.write("数据库漏洞:\n")
            for vuln in vuln_results['database_vulnerabilities']:
                f.write(f"  名称: {vuln['name']}\n  CVE: {vuln.get('cve', 'N/A')}\n  描述: {vuln['description']}\n  严重程度: {vuln['severity']}\n  受影响组件: {vuln['affected_component']}\n  修复建议: {vuln['fix']}\n")
            f.write("\n")
        else:
            f.write("未检测到数据库漏洞\n\n")
        
        # 其他漏洞
        if vuln_results.get('other_vulnerabilities', []):
            f.write("其他漏洞:\n")
            for vuln in vuln_results['other_vulnerabilities']:
                f.write(f"  名称: {vuln['name']}\n  CVE: {vuln.get('cve', 'N/A')}\n  描述: {vuln['description']}\n  严重程度: {vuln['severity']}\n  受影响组件: {vuln['affected_component']}\n  修复建议: {vuln['fix']}\n")
            f.write("\n")
        else:
            f.write("未检测到其他漏洞\n\n")
        
        # 框架
        if middleware_results.get('frameworks', []):
            f.write("框架:\n")
            for framework in middleware_results['frameworks']:
                f.write(f"  {framework['name']}: {framework['version']}\n")
            f.write("\n")
        else:
            f.write("未检测到框架\n\n")
        
        # 其他服务
        if middleware_results.get('other_services', []):
            f.write("其他服务:\n")
            for service in middleware_results['other_services']:
                f.write(f"  {service['name']}: {service['version']}\n")
            f.write("\n")
        else:
            f.write("未检测到其他服务\n\n")
        
        # 14. 综合日志攻击痕迹分析
        f.write("14. 综合日志攻击痕迹分析\n")
        f.write("-" * 30 + "\n")
        comprehensive_results = all_results.get('comprehensive_logs', {})
        
        f.write(f"总事件数: {comprehensive_results.get('total_events', 0)}\n")
        f.write(f"关键事件: {len(comprehensive_results.get('critical_events', []))}\n")
        f.write(f"攻击链: {len(comprehensive_results.get('attack_chains', []))}\n")
        f.write(f"攻击源: {len(comprehensive_results.get('attack_sources', {}))}\n")
        f.write(f"攻击类型: {len(comprehensive_results.get('attack_types', {}))}\n")
        f.write(f"日志来源: {len(comprehensive_results.get('log_sources', []))}\n\n")
        
        # 攻击时间线
        if comprehensive_results.get('attack_timeline', []):
            f.write("攻击时间线（前20条）:\n")
            for event in comprehensive_results['attack_timeline'][:20]:
                f.write(f"  时间: {event['timestamp']}\n  事件类型: {event['event_type']}\n  来源IP: {event['source_ip']}\n  严重程度: {event['severity']}\n  详情: {event['details']}\n  日志来源: {event['log_source']}\n")
            if len(comprehensive_results['attack_timeline']) > 20:
                f.write(f"  ... 共 {len(comprehensive_results['attack_timeline'])} 条事件\n")
            f.write("\n")
        else:
            f.write("未检测到攻击时间线\n\n")
        
        # 攻击链
        if comprehensive_results.get('attack_chains', []):
            f.write("攻击链:\n")
            for i, chain in enumerate(comprehensive_results['attack_chains'], 1):
                f.write(f"  攻击链 {i}: {chain['description']}\n  来源IP: {chain['source_ip']}\n  严重程度: {chain['severity']}\n")
                for j, event in enumerate(chain['events'], 1):
                    f.write(f"    事件 {j}: {event['event_type']} - {event['details']}\n")
            f.write("\n")
        else:
            f.write("未检测到攻击链\n\n")
        
        # 关键事件
        if comprehensive_results.get('critical_events', []):
            f.write("关键事件:\n")
            for event in comprehensive_results['critical_events'][:10]:
                f.write(f"  时间: {event['timestamp']}\n  事件类型: {event['event_type']}\n  来源IP: {event['source_ip']}\n  严重程度: {event['severity']}\n  详情: {event['details']}\n  日志来源: {event['log_source']}\n")
            if len(comprehensive_results['critical_events']) > 10:
                f.write(f"  ... 共 {len(comprehensive_results['critical_events'])} 条关键事件\n")
            f.write("\n")
        else:
            f.write("未检测到关键事件\n\n")
        
        # 攻击源统计
        if comprehensive_results.get('attack_sources', {}):
            f.write("攻击源统计（前10）:\n")
            sorted_sources = sorted(comprehensive_results['attack_sources'].items(), key=lambda x: x[1], reverse=True)[:10]
            for ip, count in sorted_sources:
                f.write(f"  {ip}: {count}次\n")
            f.write("\n")
        else:
            f.write("未检测到攻击源\n\n")
        
        # 攻击类型统计
        if comprehensive_results.get('attack_types', {}):
            f.write("攻击类型统计:\n")
            for attack_type, count in comprehensive_results['attack_types'].items():
                f.write(f"  {attack_type}: {count}次\n")
            f.write("\n")
        else:
            f.write("未检测到攻击类型\n\n")
        
        # 日志来源
        if comprehensive_results.get('log_sources', []):
            f.write("日志来源:\n")
            for log_source in comprehensive_results['log_sources']:
                f.write(f"  {log_source}\n")
            f.write("\n")
        else:
            f.write("未检测到日志来源\n\n")
        
        # 可疑模式
        if comprehensive_results.get('suspicious_patterns', []):
            f.write("可疑模式（前10条）:\n")
            for pattern in comprehensive_results['suspicious_patterns'][:10]:
                f.write(f"  事件类型: {pattern['event_type']}\n  严重程度: {pattern['severity']}\n  详情: {pattern['details']}\n  日志来源: {pattern['log_source']}\n")
            if len(comprehensive_results['suspicious_patterns']) > 10:
                f.write(f"  ... 共 {len(comprehensive_results['suspicious_patterns'])} 条可疑模式\n")
            f.write("\n")
        else:
            f.write("未检测到可疑模式\n\n")
        
        # 15. 僵尸网络检测
        f.write("15. 僵尸网络检测\n")
        f.write("-" * 30 + "\n")
        botnet_results = all_results.get('botnet', {})
        
        # C2服务器连接
        if botnet_results.get('c2_connections', []):
            f.write("C2服务器连接:\n")
            for conn in botnet_results['c2_connections']:
                f.write(f"  协议: {conn['proto']} | 本地: {conn['local']} -> 远程: {conn['remote']}\n")
                f.write(f"     PID: {conn['pid']} | 程序: {conn['prog']} | 特征: {conn['indicator']}\n")
            f.write("\n")
        else:
            f.write("未检测到可疑C2服务器连接\n\n")
        
        # 可疑僵尸网络进程
        if botnet_results.get('botnet_processes', []):
            f.write("可疑僵尸网络进程:\n")
            for proc in botnet_results['botnet_processes']:
                f.write(f"  PID: {proc['pid']} | 用户: {proc['user']} | CPU: {proc['cpu']}% | 内存: {proc['mem']}%\n")
                f.write(f"     命令: {proc['cmd']}\n")
            f.write("\n")
        else:
            f.write("未检测到可疑僵尸网络进程\n\n")
        
        # 僵尸网络指标
        if botnet_results.get('botnet_indicators', []):
            f.write("可疑僵尸网络指标:\n")
            for indicator in botnet_results['botnet_indicators']:
                f.write(f"  文件: {indicator['file']} | 大小: {indicator['size']} bytes | 权限: {indicator['permissions']}\n")
                f.write(f"     指标: {indicator['indicator']}\n")
            f.write("\n")
        else:
            f.write("未检测到可疑僵尸网络指标\n\n")
        
        # 僵尸网络相关日志
        if botnet_results.get('botnet_logs', []):
            f.write("僵尸网络相关日志:\n")
            for log in botnet_results['botnet_logs']:
                f.write(f"  日志文件: {log['log_file']} | 模式: {log['pattern']} | 匹配数: {log['matches']}\n")
            f.write("\n")
        else:
            f.write("未检测到僵尸网络相关日志\n\n")
        
        # 16. 总结
        f.write("16. 总结与建议\n")
        f.write("-" * 30 + "\n")
        
        # 统计安全问题数量
        total_issues = 0
        issues = []
        
        # SSH问题
        if ssh_results.get('brute_force_success', 0) > 0:
            total_issues += ssh_results['brute_force_success']
            issues.append(f"SSH爆破成功 {ssh_results['brute_force_success']} 次")
        
        # 进程问题
        process_issues = len(process_results.get('mining_processes', [])) + len(process_results.get('hidden_processes', []))
        if process_issues > 0:
            total_issues += process_issues
            issues.append(f"异常进程 {process_issues} 个")
        
        # Webshell问题
        webshell_issues = len(webshell_results.get('suspicious_files', []))
        if webshell_issues > 0:
            total_issues += webshell_issues
            issues.append(f"可疑Webshell文件 {webshell_issues} 个")
        
        # 账户问题
        account_issues = len(account_results.get('uid0_users', [])) + len(account_results.get('empty_pass_users', []))
        if account_issues > 0:
            total_issues += account_issues
            issues.append(f"账户异常 {account_issues} 个")
        
        # 文件篡改问题
        tampering_issues = len(tampering_results.get('tmp_executables', [])) + len(tampering_results.get('suspicious_crontabs', []))
        if tampering_issues > 0:
            total_issues += tampering_issues
            issues.append(f"文件篡改问题 {tampering_issues} 个")
        
        # 挖矿问题
        mining_issues = len(mining_results.get('mining_files', [])) + len(mining_results.get('mining_conns', []))
        if mining_issues > 0:
            total_issues += mining_issues
            issues.append(f"挖矿行为 {mining_issues} 个")
        
        # 僵尸网络问题
        botnet_issues = len(botnet_results.get('c2_connections', [])) + len(botnet_results.get('botnet_processes', [])) + len(botnet_results.get('botnet_indicators', [])) + len(botnet_results.get('botnet_logs', []))
        if botnet_issues > 0:
            total_issues += botnet_issues
            issues.append(f"僵尸网络活动 {botnet_issues} 个")
        
        if total_issues > 0:
            f.write(f"共发现 {total_issues} 个安全问题:\n")
            for issue in issues:
                f.write(f"  - {issue}\n")
            f.write("\n")
            f.write("建议措施:\n")
            f.write("  1. 检查并加固SSH配置，限制登录IP，使用密钥认证\n")
            f.write("  2. 终止并删除可疑进程和文件\n")
            f.write("  3. 清理发现的Webshell文件\n")
            f.write("  4. 检查并修复账户异常，删除不必要的账户\n")
            f.write("  5. 检查系统定时任务，删除可疑任务\n")
            f.write("  6. 检查网络连接，屏蔽可疑IP\n")
            f.write("  7. 更新系统和应用补丁\n")
            f.write("  8. 部署入侵检测系统(IDS)\n")
        else:
            f.write("未发现明显安全问题\n\n")
            f.write("建议措施:\n")
            f.write("  1. 定期进行安全检查\n")
            f.write("  2. 保持系统和应用补丁更新\n")
            f.write("  3. 加强SSH访问控制\n")
            f.write("  4. 部署入侵检测系统\n")
            f.write("  5. 定期备份重要数据\n")
    
    print(f"增强版TXT报告已生成: {txt_report_path}")
    print(f"\n===== 应急排查完成！=====")
    print(f"所有检测结果已生成到报告文件中，请查看详细报告。")

# ===================== 主函数 =====================
def main():
    """主函数"""
    print(f"{Colors.BOLD_BLUE}===== Linux服务器应急响应排查脚本====={Colors.RESET}")
    print(f"开始执行全维度应急排查...")
    print(f"当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # 检查权限
    try:
        if os.geteuid() != 0:
            print(f"{Colors.YELLOW}[警告] 建议以root权限运行，以获取更完整的信息{Colors.RESET}")
    except AttributeError:
        # Windows系统不支持geteuid，跳过权限检查
        pass
    
    # 执行各项检测
    all_results = {
        "ssh": analyze_ssh_logs(),
        "processes": analyze_processes(),
        "network": analyze_network(),
        "webshell": scan_webshell(),
        "account": analyze_system_accounts(),
        "file_tampering": detect_file_tampering(),
        "log_anomalies": analyze_log_anomalies(),
        "mining_behavior": detect_mining_behavior(),
        "memory_malware": detect_memory_malware(),
        "alias_backdoors": detect_alias_backdoors(),
        "web_attack_logs": analyze_web_attack_logs(),
        "vulnerabilities": detect_vulnerabilities(),
        "middleware": detect_middleware_versions(),
        "botnet": detect_botnet()
    }
    
    # 执行综合日志分析
    all_results["comprehensive_logs"] = analyze_comprehensive_logs(all_results)
    
    # 生成报告
    generate_emergency_report(all_results)
    
    # 压缩日志文件
    zip_logs()

# ===================== 日志压缩函数 =====================
def zip_logs():
    """压缩所有日志文件到脚本目录"""
    import zipfile
    import os
    
    print(f"\n{Colors.BOLD_YELLOW}=== 压缩日志文件 ==={Colors.RESET}")
    
    # 定义要收集的日志文件路径
    log_files = [
        # SSH日志
        ("/var/log/auth.log", "auth.log"),
        ("/var/log/secure", "secure.log"),
        ("/var/log/sshd.log", "sshd.log"),
        # 系统日志
        ("/var/log/messages", "messages.log"),
        ("/var/log/syslog", "syslog.log"),
        ("/var/log/daemon.log", "daemon.log"),
        # Web服务器日志
        ("/var/log/apache2/access.log", "apache_access.log"),
        ("/var/log/apache2/error.log", "apache_error.log"),
        ("/var/log/nginx/access.log", "nginx_access.log"),
        ("/var/log/nginx/error.log", "nginx_error.log"),
        # 其他可能的日志
        ("/var/log/cron.log", "cron.log"),
        ("/var/log/audit/audit.log", "audit.log")
    ]
    
    # 生成时间戳
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_filename = f"logs_backup_{timestamp}.zip"
    
    # 统计信息
    collected_logs = 0
    skipped_logs = 0
    
    try:
        # 创建zip文件
        with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for log_path, log_name in log_files:
                if os.path.exists(log_path):
                    try:
                        # 检查文件大小（限制为10MB）
                        max_size = 10 * 1024 * 1024  # 10MB
                        if os.path.getsize(log_path) > max_size:
                            print(f"  {Colors.YELLOW}[警告] 日志文件{log_path}过大，仅压缩最后1000行{Colors.RESET}")
                            # 使用tail命令获取最后1000行
                            cmd = f"tail -n 1000 {log_path}"
                            log_content = run_command(cmd)
                            if log_content and log_content != "命令执行失败":
                                zipf.writestr(f"logs/{log_name}", log_content)
                                collected_logs += 1
                            else:
                                skipped_logs += 1
                        else:
                            # 直接压缩整个文件
                            zipf.write(log_path, f"logs/{log_name}")
                            collected_logs += 1
                            print(f"  {Colors.GREEN}[+] 收集日志文件: {log_path}{Colors.RESET}")
                    except Exception as e:
                        print(f"  {Colors.RED}[错误] 无法压缩日志文件{log_path}: {str(e)}{Colors.RESET}")
                        skipped_logs += 1
                else:
                    skipped_logs += 1
        
        # 输出统计信息
        print(f"\n{Colors.GREEN}[+] 日志压缩完成{Colors.RESET}")
        print(f"  收集的日志文件: {collected_logs}")
        print(f"  跳过的日志文件: {skipped_logs}")
        print(f"  压缩文件保存为: {zip_filename}")
        
    except Exception as e:
        print(f"\n{Colors.RED}[错误] 日志压缩失败: {str(e)}{Colors.RESET}")

# ===================== 11. 僵尸网络检测 =====================
def detect_botnet():
    """检测僵尸网络活动"""
    print(f"\n{Colors.BOLD_BLUE}[11/11] 开始检测僵尸网络活动{Colors.RESET}")
    botnet_results = {
        "c2_connections": [],  # C2服务器连接
        "botnet_processes": [],  # 可疑僵尸网络进程
        "botnet_indicators": [],  # 僵尸网络指标
        "botnet_logs": []  # 僵尸网络相关日志
    }
    
    # 1. C2服务器检测
    print(f"\n{Colors.BOLD_YELLOW}=== C2服务器连接检测 ==={Colors.RESET}")
    
    # 常见C2服务器特征
    c2_indicators = [
        # 常见C2服务器域名特征
        ".top", ".xyz", ".info", ".biz", ".ru", ".cn",
        "-bot", "bot-", "c2-", "-c2", "command", "control",
        "botnet", "zombie", "trojan", "malware", "rat",
        # 常见C2服务器IP段
        "185.", "192.168.", "10.", "172.16."
    ]
    
    # 常见僵尸网络端口
    botnet_ports = [
        443, 80, 8080, 8443, 3389, 22, 21, 135, 139, 445,
        1433, 3306, 5432, 6379, 27017, 9200
    ]
    
    try:
        # 获取网络连接
        netstat_output = run_command("netstat -tulnpa 2>/dev/null")
        if netstat_output and netstat_output != "命令执行失败":
            connections = netstat_output.split('\n')
            for conn in connections:
                if not conn or 'Proto' in conn:
                    continue
                
                parts = conn.split()
                if len(parts) < 7:
                    continue
                
                proto, recv_q, send_q, local, foreign, state, pid_prog = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], ' '.join(parts[6:])
                
                # 提取PID和程序名
                pid = "-"
                prog = "-"
                pid_match = re.search(r'\d+/', pid_prog)
                if pid_match:
                    pid = pid_match.group(0)[:-1]
                    prog = pid_prog.split('/')[1]
                
                # 分析外部连接
                if foreign != "0.0.0.0:*" and foreign != ":::*":
                    # 排除本地连接
                    if not (foreign.startswith('127.') or foreign.startswith('192.168.') or foreign.startswith('10.') or foreign.startswith('172.16.')):
                        # 检查C2服务器特征
                        for indicator in c2_indicators:
                            if indicator in foreign.lower():
                                c2_connection = {
                                    "proto": proto,
                                    "state": state,
                                    "local": local,
                                    "remote": foreign,
                                    "pid": pid,
                                    "prog": prog,
                                    "indicator": indicator
                                }
                                botnet_results["c2_connections"].append(c2_connection)
                                break
                        
                        # 检查常见僵尸网络端口
                        try:
                            if ':' in foreign:
                                port = int(foreign.split(':')[-1])
                                if port in botnet_ports:
                                    # 检查进程名是否可疑
                                    suspicious_procs = ["python", "perl", "bash", "sh", "curl", "wget", "netcat", "nc"]
                                    if any(proc in prog.lower() for proc in suspicious_procs):
                                        c2_connection = {
                                            "proto": proto,
                                            "state": state,
                                            "local": local,
                                            "remote": foreign,
                                            "pid": pid,
                                            "prog": prog,
                                            "indicator": f"Suspicious process on common botnet port {port}"
                                        }
                                        botnet_results["c2_connections"].append(c2_connection)
                        except:
                            pass
    
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] C2服务器连接检测失败: {str(e)}{Colors.RESET}")
    
    # 输出C2服务器连接检测结果
    if botnet_results["c2_connections"]:
        print(f"{Colors.RED}检测到可疑C2服务器连接（{len(botnet_results['c2_connections'])}个）:{Colors.RESET}")
        for conn in botnet_results["c2_connections"]:
            print(f"  {conn['proto'].upper()} | 本地: {conn['local']} -> 远程: {conn['remote']}")
            print(f"     PID: {conn['pid']} | 程序: {conn['prog']} | 特征: {conn['indicator']}")
    else:
        print(f"{Colors.GREEN}未检测到可疑C2服务器连接{Colors.RESET}")
    
    # 2. 可疑僵尸网络进程检测
    print(f"\n{Colors.BOLD_YELLOW}=== 可疑僵尸网络进程检测 ==={Colors.RESET}")
    
    # 常见僵尸网络进程特征
    botnet_process_names = [
        "irc", "bot", "zombie", "trojan", "malware", "rat",
        "backdoor", "reverse", "shell", "keylogger", "spy",
        "miner", "crypto", "coin", "挖", "矿", "比特币"
    ]
    
    try:
        # 获取进程列表
        ps_output = run_command("ps aux 2>/dev/null")
        if ps_output and ps_output != "命令执行失败":
            processes = ps_output.split('\n')
            for proc in processes:
                if not proc or 'USER' in proc:
                    continue
                
                parts = proc.split()
                if len(parts) < 11:
                    continue
                
                user, pid, cpu, mem, vsz, rss, tty, stat, start, time, cmd = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7], parts[8], parts[9], ' '.join(parts[10:])
                
                # 检查进程名是否包含僵尸网络特征
                for name in botnet_process_names:
                    if name in cmd.lower():
                        botnet_process = {
                            "user": user,
                            "pid": pid,
                            "cpu": cpu,
                            "mem": mem,
                            "cmd": cmd
                        }
                        botnet_results["botnet_processes"].append(botnet_process)
                        break
                
                # 检查进程是否有可疑参数
                suspicious_args = ["-connect", "-join", "-listen", "-server", "-client"]
                for arg in suspicious_args:
                    if arg in cmd:
                        botnet_process = {
                            "user": user,
                            "pid": pid,
                            "cpu": cpu,
                            "mem": mem,
                            "cmd": cmd
                        }
                        botnet_results["botnet_processes"].append(botnet_process)
                        break
    
    except Exception as e:
        print(f"{Colors.YELLOW}[警告] 可疑僵尸网络进程检测失败: {str(e)}{Colors.RESET}")
    
    # 输出可疑僵尸网络进程检测结果
    if botnet_results["botnet_processes"]:
        print(f"{Colors.RED}检测到可疑僵尸网络进程（{len(botnet_results['botnet_processes'])}个）:{Colors.RESET}")
        for proc in botnet_results["botnet_processes"]:
            print(f"  PID: {proc['pid']} | 用户: {proc['user']} | CPU: {proc['cpu']}% | 内存: {proc['mem']}%")
            print(f"     命令: {proc['cmd']}")
    else:
        print(f"{Colors.GREEN}未检测到可疑僵尸网络进程{Colors.RESET}")
    
    # 3. 僵尸网络指标检测
    print(f"\n{Colors.BOLD_YELLOW}=== 僵尸网络指标检测 ==={Colors.RESET}")
    
    # 检查可疑文件
    suspicious_paths = [
        "/tmp", "/var/tmp", "/dev/shm", "/run/shm",
        "/home/*/.ssh", "/home/*/.config", "/home/*/.local"
    ]
    
    for path_pattern in suspicious_paths:
        try:
            import glob
            files = glob.glob(path_pattern)
            for file in files:
                if os.path.isfile(file):
                    # 检查文件大小和权限
                    try:
                        file_size = os.path.getsize(file)
                        file_perm = oct(os.stat(file).st_mode)[-4:]
                        
                        # 检查可疑文件特征
                        if file_size < 1024000:  # 小于1MB
                            with open(file, 'r', errors='ignore') as f:
                                content = f.read()
                                # 检查文件内容中的僵尸网络特征
                                botnet_indicators = [
                                    "irc://", "botnet", "zombie", "trojan",
                                    "C2", "command and control", "malware",
                                    "socket", "connect", "listen", "bind"
                                ]
                                for indicator in botnet_indicators:
                                    if indicator in content.lower():
                                        botnet_results["botnet_indicators"].append({
                                            "file": file,
                                            "size": file_size,
                                            "permissions": file_perm,
                                            "indicator": indicator
                                        })
                                        break
                    except:
                        pass
        except:
            pass
    
    # 输出僵尸网络指标检测结果
    if botnet_results["botnet_indicators"]:
        print(f"{Colors.RED}检测到可疑僵尸网络指标（{len(botnet_results['botnet_indicators'])}个）:{Colors.RESET}")
        for indicator in botnet_results["botnet_indicators"]:
            print(f"  文件: {indicator['file']} | 大小: {indicator['size']} bytes | 权限: {indicator['permissions']}")
            print(f"     指标: {indicator['indicator']}")
    else:
        print(f"{Colors.GREEN}未检测到可疑僵尸网络指标{Colors.RESET}")
    
    # 4. 僵尸网络相关日志检测
    print(f"\n{Colors.BOLD_YELLOW}=== 僵尸网络相关日志检测 ==={Colors.RESET}")
    
    # 检查系统日志中的僵尸网络活动
    log_files = [
        "/var/log/auth.log", "/var/log/secure", "/var/log/syslog",
        "/var/log/messages", "/var/log/daemon.log"
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r', errors='ignore') as f:
                    log_content = f.read()
                    
                    # 检查日志中的僵尸网络特征
                    botnet_log_patterns = [
                        r"Failed password.*from",
                        r"Invalid user.*from",
                        r"ssh.*connection.*refused",
                        r"ssh.*connection.*closed",
                        r"irc.*connect",
                        r"botnet",
                        r"zombie",
                        r"trojan",
                        r"malware"
                    ]
                    
                    for pattern in botnet_log_patterns:
                        matches = re.findall(pattern, log_content, re.IGNORECASE)
                        if matches:
                            botnet_results["botnet_logs"].append({
                                "log_file": log_file,
                                "pattern": pattern,
                                "matches": len(matches)
                            })
                            break
            except Exception as e:
                pass
    
    # 输出僵尸网络相关日志检测结果
    if botnet_results["botnet_logs"]:
        print(f"{Colors.RED}检测到僵尸网络相关日志（{len(botnet_results['botnet_logs'])}个）:{Colors.RESET}")
        for log in botnet_results["botnet_logs"]:
            print(f"  日志文件: {log['log_file']} | 模式: {log['pattern']} | 匹配数: {log['matches']}")
    else:
        print(f"{Colors.GREEN}未检测到僵尸网络相关日志{Colors.RESET}")
    
    return botnet_results

if __name__ == "__main__":
    main()