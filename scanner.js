#!/usr/bin/env node

/**
 * ========================================================================
 * NETSCAN developed by MR.X [OFFICIAL]
 * Advanced Terminal Network, Port Scanner, OS & Device Reconnaissance Engine
 * Built with Node.js standard libraries (zero external dependencies).
 * ========================================================================
 */

const net = require('net');
const tls = require('tls');
const os = require('os');
const dns = require('dns').promises;
const fs = require('fs').promises;
const { execSync } = require('child_process');
const readline = require('readline');

// Common service mappings for 50+ ports
const COMMON_SERVICES = {
  20: 'FTP-Data',
  21: 'FTP-Control',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP-Server',
  68: 'DHCP-Client',
  69: 'TFTP',
  80: 'HTTP',
  88: 'Kerberos',
  110: 'POP3',
  111: 'RPCBind',
  119: 'NNTP',
  123: 'NTP',
  135: 'MS-RPC',
  137: 'NetBIOS-NS',
  138: 'NetBIOS-DGM',
  139: 'NetBIOS-SSN',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB / MS-DS',
  465: 'SMTPS',
  514: 'Syslog',
  515: 'LPD-Printer',
  548: 'AFP (Apple)',
  554: 'RTSP (Camera Stream)',
  587: 'SMTP-Submission',
  631: 'IPP (Printer)',
  636: 'LDAPS',
  873: 'Rsync',
  993: 'IMAPS',
  995: 'POP3S',
  1080: 'SOCKS-Proxy',
  1433: 'MS-SQL',
  1521: 'Oracle-DB',
  2049: 'NFS',
  2375: 'Docker-REST',
  2376: 'Docker-TLS',
  3000: 'Dev-Web (Node/React)',
  3306: 'MySQL',
  3389: 'RDP (Remote Desktop)',
  5000: 'Dev-Web (Flask/Express)',
  5432: 'PostgreSQL',
  5555: 'ADB (Android Debug Bridge)',
  5672: 'RabbitMQ',
  5900: 'VNC',
  6379: 'Redis',
  8000: 'HTTP-Alt / Django',
  8008: 'Google-Cast (Media)',
  8080: 'HTTP-Proxy / Tomcat',
  8443: 'HTTPS-Alt',
  8888: 'Jupyter / Web-Alt',
  9000: 'SonarQube / MinIO',
  9092: 'Apache Kafka',
  9100: 'RAW-Print (JetDirect)',
  9200: 'Elasticsearch',
  11211: 'Memcached',
  27017: 'MongoDB'
};

// Security advisories for exposed ports
const RISK_ADVISORIES = {
  21: { level: 'MEDIUM', tip: 'FTP transmits credentials in plaintext. Prefer SFTP (SSH).' },
  23: { level: 'HIGH', tip: 'Telnet is unencrypted and vulnerable to eavesdropping. Replace with SSH.' },
  69: { level: 'MEDIUM', tip: 'TFTP has no native authentication mechanism.' },
  135: { level: 'MEDIUM', tip: 'MS-RPC port exposed; verify firewall filtering on public interfaces.' },
  139: { level: 'MEDIUM', tip: 'NetBIOS exposed to network traffic.' },
  445: { level: 'HIGH', tip: 'SMB port exposed. Ensure SMB signing is enforced and public access blocked.' },
  5555: { level: 'HIGH', tip: 'Android Debug Bridge (ADB) exposed without network isolation.' },
  3389: { level: 'MEDIUM', tip: 'RDP exposed; verify Network Level Authentication (NLA) is required.' },
  6379: { level: 'HIGH', tip: 'Redis database exposed; ensure strong password authentication is set.' },
  9200: { level: 'HIGH', tip: 'Elasticsearch cluster port exposed. Ensure authentication is enabled.' },
  27017: { level: 'HIGH', tip: 'MongoDB exposed; ensure auth is enforced and access is IP-whitelisted.' }
};

// OUI Vendor Database for Hardware MAC lookup
const VENDOR_OUIS = {
  'b8:27:eb': 'Raspberry Pi Foundation',
  'dc:a6:32': 'Raspberry Pi Foundation',
  'e4:5f:01': 'Raspberry Pi Foundation',
  '28:cd:c1': 'Raspberry Pi Foundation',
  '00:1a:2b': 'Cisco Systems',
  '00:0c:29': 'VMware Inc.',
  '00:50:56': 'VMware Inc.',
  '08:00:27': 'Oracle VirtualBox',
  '52:54:00': 'QEMU / KVM Virtual Machine',
  '00:15:5d': 'Microsoft Hyper-V',
  'f0:18:98': 'Apple Inc.',
  '3c:22:fb': 'Apple Inc.',
  'ac:bc:32': 'Apple Inc.',
  'a4:83:e7': 'Apple Inc.',
  '14:7d:da': 'Apple Inc.',
  'c0:35:32': 'Intel Corporation',
  '00:1b:21': 'Intel Corporation',
  '30:07:4d': 'Samsung Electronics',
  '94:65:2d': 'Samsung Electronics',
  'ec:1f:72': 'Samsung Electronics',
  '50:c7:bf': 'TP-Link Technologies',
  'e8:48:b8': 'TP-Link Technologies',
  '60:32:b1': 'TP-Link Technologies',
  '00:14:d1': 'Trendnet',
  '00:18:e7': 'Cameo Communications (D-Link)',
  '18:68:cb': 'Hikvision Digital Technology',
  'c4:2f:90': 'Dahua Technology',
  '24:0a:c4': 'Espressif Inc. (ESP32 IoT)',
  '30:ae:a4': 'Espressif Inc. (ESP32 IoT)',
  '84:0d:8e': 'Espressif Inc. (ESP32 IoT)',
  'a4:cf:12': 'Espressif Inc. (ESP8266 IoT)',
  'a4:4c:c8': 'Dell Inc.',
  '00:26:b9': 'Dell Inc.',
  'b0:83:fe': 'HP Inc.',
  '70:85:c2': 'ASUSTek Computer',
  '00:04:4b': 'NVIDIA Corporation',
  '00:1e:06': 'Wistron InfoComm'
};

const DEFAULT_TOP_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 554, 587, 631, 993, 995,
  1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432, 5555, 5900, 6379, 8000, 8080, 8443, 9100, 9200, 27017
];

const FAST_TOP_100_PORTS = [
  7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
  119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
  515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
  1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
  2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
  5101, 5190, 5357, 5432, 5555, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
  8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 9999, 10000,
  27017, 32768, 49152, 49153, 49154
];

const SWEEP_PORTS = [80, 443, 22, 445, 135, 8080];

// Timing templates (Nmap style -T1 to -T5)
const TIMING_PROFILES = {
  1: { concurrency: 1, timeout: 3000, name: 'Paranoid' },
  2: { concurrency: 10, timeout: 2000, name: 'Sneaky' },
  3: { concurrency: 50, timeout: 1200, name: 'Normal' },
  4: { concurrency: 100, timeout: 800, name: 'Aggressive' },
  5: { concurrency: 150, timeout: 500, name: 'Insane' }
};

// ANSI Color Palette
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  gray: '\x1b[90m'
};

function printBanner() {
  console.log(`
${C.cyan}${C.bold}========================================================================${C.reset}
${C.cyan}${C.bold}  _   _ _____ _____ ____   ____    _    _   _ 
 | \\ | | ____|_   _/ ___| / ___|  / \\  | \\ | |
 |  \\| |  _|   | | \\___ \\| |     / _ \\ |  \\| |
 | |\  | |___  | |  ___) | |___ / ___ \\| |\\  |
 |_| \\_|_____| |_| |____/ \\____/_/   \\_\\_| \\_|${C.reset}

  ${C.yellow}${C.bold}[*] NETSCAN developed by MR.X [OFFICIAL]${C.reset}
  ${C.gray}High-Speed Async Network Reconnaissance & OS/Device Audit Engine${C.reset}
${C.cyan}${C.bold}========================================================================${C.reset}
`);
}

/**
 * Terminal Progress Bar
 */
function renderProgressBar(current, total, openCount) {
  if (!process.stdout.isTTY) return;
  const width = 20;
  const ratio = Math.min(1, current / total);
  const pct = Math.floor(ratio * 100);
  const filled = Math.min(width, Math.floor(ratio * width));
  const empty = Math.max(0, width - filled);
  const bar = `${'█'.repeat(filled)}${'░'.repeat(empty)}`;
  process.stdout.write(`\r  ${C.cyan}[${bar}]${C.reset} ${pct}% (${current}/${total}) | Open: ${C.green}${openCount}${C.reset}  `);
}

function clearProgressBar() {
  if (process.stdout.isTTY) {
    process.stdout.write('\r\x1b[2K');
  }
}

/**
 * Read and parse local system ARP table
 */
function getArpTable() {
  const table = new Map();
  try {
    const stdout = execSync('arp -a', { stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf-8', timeout: 1500 });
    const lines = stdout.split(/\r?\n/);
    for (const line of lines) {
      const match = line.trim().match(/(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F[:-]{17}|[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2}-[0-9a-fA-F]{2})/);
      if (match) {
        const ip = match[1];
        const mac = match[2].replace(/-/g, ':').toLowerCase();
        table.set(ip, mac);
      }
    }
  } catch {}
  return table;
}

/**
 * Lookup hardware vendor from MAC address
 */
function getVendorFromMAC(mac) {
  if (!mac || mac.includes('Not')) return 'Remote / Unknown Host';
  const prefix = mac.toLowerCase().split(':').slice(0, 3).join(':');
  return VENDOR_OUIS[prefix] || 'Generic Network Hardware';
}

/**
 * Detect local machine context where NetScan is executing
 */
function getLocalHostInfo() {
  const localIPs = new Set(['127.0.0.1', '::1', 'localhost', '0.0.0.0']);
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const a of addrs) {
      if (a.address) {
        localIPs.add(a.address.toLowerCase());
      }
    }
  }

  const platform = os.platform();
  const release = os.release();
  const version = typeof os.version === 'function' ? os.version() : '';
  const arch = os.arch();
  const hostname = os.hostname();

  let osFull = '';
  if (platform === 'win32') {
    osFull = version || `Windows (Release ${release})`;
  } else if (platform === 'darwin') {
    osFull = `Apple macOS (${release})`;
  } else if (platform === 'linux') {
    osFull = `Linux Kernel ${release}`;
  } else {
    osFull = `${os.type()} ${release}`;
  }

  return {
    localIPs,
    hostname,
    osGuess: `${osFull} [${arch}]`,
    arch,
    platform
  };
}

/**
 * Probe Ping TTL to identify operating system network stack
 */
function probePingTTL(ip) {
  try {
    const isWin = process.platform === 'win32';
    const cmd = isWin ? `ping -n 1 -w 500 ${ip}` : `ping -c 1 -W 1 ${ip}`;
    const out = execSync(cmd, { stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf-8', timeout: 700 });
    const match = out.match(/TTL=(\d+)/i);
    if (match) {
      return parseInt(match[1], 10);
    }
  } catch {}
  return null;
}

/**
 * OS & Device Fingerprinting Engine with Local Host Awareness & Stack Analysis
 */
function analyzeDevice(ip, hostname, mac, openPorts) {
  const localInfo = getLocalHostInfo();

  // 1. Precise Localhost Check (where NetScan is currently running)
  if (localInfo.localIPs.has(ip.toLowerCase()) || ip === '127.0.0.1' || ip === 'localhost') {
    return {
      deviceType: `Local Host Machine (${localInfo.hostname})`,
      osGuess: localInfo.osGuess,
      confidence: 100,
      vendor: `Local System (${os.type()})`,
      mac: 'Loopback / Local Host Adapter',
      reasons: `Verified host system where NetScan is currently executing (${localInfo.hostname})`,
      isLocalHost: true
    };
  }

  let deviceType = 'Generic Host / Network Device';
  let osGuess = 'Unknown Operating System';
  let confidence = 50;
  const reasons = [];

  const portsSet = new Set(openPorts.map((p) => p.port));
  const allBanners = openPorts.map((p) => (p.banner || '').toLowerCase()).join(' ');
  const hostLower = (hostname || '').toLowerCase();

  // Check TTL (Time to Live) signature
  const pingTTL = probePingTTL(ip);
  let stackOS = '';
  if (pingTTL !== null) {
    if (pingTTL >= 100 && pingTTL <= 130) {
      stackOS = 'Windows';
      reasons.push(`TCP/IP stack TTL=${pingTTL} (Microsoft Windows signature)`);
    } else if (pingTTL >= 50 && pingTTL <= 70) {
      stackOS = 'Unix/Linux';
      reasons.push(`TCP/IP stack TTL=${pingTTL} (Linux / Unix / Embedded signature)`);
    } else if (pingTTL >= 240 && pingTTL <= 255) {
      stackOS = 'Cisco/Switch';
      reasons.push(`TCP/IP stack TTL=${pingTTL} (Cisco / Network Appliance signature)`);
    }
  }

  // Check if target is Default Gateway on local subnet
  const localSubnets = getLocalSubnets();
  const isDefaultGateway = localSubnets.some((s) => {
    const parts = s.ip.split('.');
    return ip === `${parts[0]}.${parts[1]}.${parts[2]}.1` || ip === `${parts[0]}.${parts[1]}.${parts[2]}.254`;
  });

  // 2. Router / Gateway Detection
  if (
    isDefaultGateway ||
    (ip.endsWith('.1') && (portsSet.has(80) || portsSet.has(443) || portsSet.has(53))) ||
    allBanners.includes('router') ||
    allBanners.includes('openwrt') ||
    allBanners.includes('uhttpd') ||
    allBanners.includes('micro_httpd') ||
    allBanners.includes('asus') ||
    allBanners.includes('tp-link') ||
    allBanners.includes('netgear') ||
    allBanners.includes('d-link') ||
    allBanners.includes('dropbear') ||
    hostLower.includes('router') ||
    hostLower.includes('gateway')
  ) {
    deviceType = isDefaultGateway ? 'Local Wi-Fi Router / Network Gateway' : 'Router / Network Gateway';
    if (allBanners.includes('openwrt') || allBanners.includes('dropbear')) {
      osGuess = 'Embedded Linux (OpenWrt / BusyBox)';
      confidence = 95;
    } else {
      osGuess = 'Embedded Linux / Router OS';
      confidence = 90;
    }
    reasons.push('Default gateway address or router web daemon detected');
  }
  // 3. Windows PC / Server Detection
  else if (
    portsSet.has(135) ||
    portsSet.has(445) ||
    portsSet.has(3389) ||
    allBanners.includes('microsoft-iis') ||
    allBanners.includes('microsoft-httpapi') ||
    allBanners.includes('win64') ||
    allBanners.includes('win32') ||
    stackOS === 'Windows'
  ) {
    deviceType = 'Windows PC / Workstation / Server';
    if (allBanners.includes('iis/10.0')) {
      osGuess = 'Microsoft Windows 10/11 or Windows Server 2016-2022';
      confidence = 96;
    } else if (allBanners.includes('iis/8.5')) {
      osGuess = 'Microsoft Windows 8.1 or Windows Server 2012 R2';
      confidence = 92;
    } else if (portsSet.has(3389) && portsSet.has(445)) {
      osGuess = 'Microsoft Windows (Active Directory Member / Workstation)';
      confidence = 94;
    } else if (stackOS === 'Windows') {
      osGuess = 'Microsoft Windows OS (Confirmed by TCP/IP Stack TTL=128)';
      confidence = 88;
    } else {
      osGuess = 'Microsoft Windows OS';
      confidence = 85;
    }
    reasons.push('Active SMB (445), RPC (135), RDP (3389) or Windows network stack');
  }
  // 4. Linux Server / Cloud Host Detection
  else if (
    portsSet.has(22) ||
    allBanners.includes('ubuntu') ||
    allBanners.includes('debian') ||
    allBanners.includes('centos') ||
    allBanners.includes('rhel') ||
    allBanners.includes('linux') ||
    (stackOS === 'Unix/Linux' && !isDefaultGateway)
  ) {
    deviceType = 'Linux Server / Unix Host';
    if (allBanners.includes('ubuntu')) {
      osGuess = 'Linux (Ubuntu Linux)';
      confidence = 96;
    } else if (allBanners.includes('debian')) {
      osGuess = 'Linux (Debian Linux)';
      confidence = 96;
    } else if (allBanners.includes('centos')) {
      osGuess = 'Linux (CentOS / Red Hat Enterprise Linux)';
      confidence = 94;
    } else if (allBanners.includes('freebsd')) {
      osGuess = 'FreeBSD / BSD Unix';
      confidence = 94;
    } else if (stackOS === 'Unix/Linux') {
      osGuess = 'Linux Kernel 4.x - 6.x (Unix)';
      confidence = 88;
    } else {
      osGuess = 'Linux Kernel 4.x - 6.x (Unix)';
      confidence = 85;
    }
    reasons.push('OpenSSH server banners or Linux web server signature');
  }
  // 5. Network Printer Detection
  else if (portsSet.has(9100) || portsSet.has(515) || (portsSet.has(631) && !portsSet.has(22))) {
    deviceType = 'Network Printer / Print Server';
    osGuess = 'Embedded Printer OS / Firmware';
    confidence = 94;
    reasons.push('Active RAW JetDirect (9100) or IPP (631) print service');
  }
  // 6. IP Camera / Security CCTV Detection
  else if (
    portsSet.has(554) ||
    allBanners.includes('hikvision') ||
    allBanners.includes('dahua') ||
    allBanners.includes('ipcamera')
  ) {
    deviceType = 'IP Security Camera / DVR / NVR';
    osGuess = 'Embedded Linux (Security Camera Firmware)';
    confidence = 94;
    reasons.push('RTSP stream (554) or surveillance web banners');
  }
  // 7. Android Mobile / Smart TV
  else if (portsSet.has(5555) || hostLower.includes('android')) {
    deviceType = 'Android Device (Phone / Tablet / TV)';
    osGuess = 'Google Android OS';
    confidence = 95;
    reasons.push('Android Debug Bridge (ADB port 5555) open or hostname');
  }
  // 8. Apple macOS / iOS
  else if (
    portsSet.has(548) ||
    (portsSet.has(5900) && allBanners.includes('apple')) ||
    hostLower.includes('iphone') ||
    hostLower.includes('macbook') ||
    hostLower.includes('ipad')
  ) {
    deviceType = hostLower.includes('iphone') || hostLower.includes('ipad') ? 'Apple iOS Mobile' : 'Apple Mac Workstation';
    osGuess = hostLower.includes('iphone') || hostLower.includes('ipad') ? 'Apple iOS' : 'Apple macOS';
    confidence = 92;
    reasons.push('Apple Filing Protocol (AFP 548), Apple VNC or hostname match');
  }

  // Adjust with Hardware Vendor from MAC
  const vendor = getVendorFromMAC(mac);
  if (vendor.includes('Apple') && deviceType === 'Generic Host / Network Device') {
    deviceType = 'Apple Device (iPhone / iPad / Mac)';
    osGuess = 'Apple iOS / macOS';
    confidence = 82;
    reasons.push('Apple OUI Hardware Address');
  } else if (vendor.includes('Raspberry Pi')) {
    deviceType = 'Raspberry Pi Single-Board Computer';
    osGuess = 'Linux (Raspberry Pi OS / Raspbian)';
    confidence = 95;
    reasons.push('Raspberry Pi Foundation Hardware OUI');
  } else if (vendor.includes('TP-Link') || vendor.includes('Cisco') || vendor.includes('D-Link')) {
    if (deviceType === 'Generic Host / Network Device') {
      deviceType = `Network Appliance (${vendor})`;
      osGuess = 'Embedded Hardware Firmware';
      confidence = 85;
      reasons.push(`Known networking hardware vendor (${vendor})`);
    }
  }

  return {
    deviceType,
    osGuess,
    confidence,
    vendor,
    mac: mac || 'Not in local ARP cache (routed host)',
    reasons: reasons.join('; ') || 'Standard TCP stack fingerprint'
  };
}

/**
 * Deep Probe: TLS Certificate Inspection
 */
function probeTLS(host, port, timeout = 1000) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = tls.connect(
      {
        host,
        port,
        rejectUnauthorized: false,
        timeout
      },
      () => {
        if (resolved) return;
        resolved = true;
        try {
          const cert = socket.getPeerCertificate();
          let details = 'TLS Active';
          if (cert && cert.subject) {
            const cn = cert.subject.CN || '';
            const org = cert.subject.O || '';
            const expiry = cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : '';
            details = `TLS: ${cn || 'Self-Signed'}${org ? ` (${org})` : ''}${expiry ? ` [Exp: ${expiry}]` : ''}`;
          }
          socket.destroy();
          resolve(details);
        } catch {
          socket.destroy();
          resolve('TLS Active');
        }
      }
    );

    const cleanup = () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve('');
    };

    socket.on('error', cleanup);
    socket.on('timeout', cleanup);
  });
}

/**
 * Deep Probe: HTTP Headers, Server & Title extraction
 */
function probeHTTP(host, port, timeout = 1000) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = new net.Socket();
    let responseData = '';
    socket.setTimeout(timeout);

    const finish = () => {
      if (resolved) return;
      resolved = true;
      socket.removeAllListeners();
      socket.destroy();
      if (!responseData) return resolve('');

      const serverMatch = responseData.match(/Server:\s*([^\r\n]+)/i);
      const titleMatch = responseData.match(/<title[^>]*>([^<]+)<\/title>/i);
      const poweredMatch = responseData.match(/X-Powered-By:\s*([^\r\n]+)/i);
      const statusLine = responseData.split('\r\n')[0] || '';

      const parts = [];
      if (serverMatch) parts.push(`Server: ${serverMatch[1].trim()}`);
      if (titleMatch) parts.push(`Title: "${titleMatch[1].trim()}"`);
      if (poweredMatch) parts.push(`Tech: ${poweredMatch[1].trim()}`);
      if (parts.length === 0 && statusLine.startsWith('HTTP/')) {
        parts.push(statusLine);
      }
      resolve(parts.join(' | '));
    };

    socket.connect(port, host, () => {
      socket.write(
        `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: NetScan/MR.X\r\nAccept: */*\r\nConnection: close\r\n\r\n`
      );
    });

    socket.on('data', (chunk) => {
      responseData += chunk.toString('utf-8');
      if (responseData.length > 3000 || responseData.includes('</title>') || responseData.includes('\r\n\r\n')) {
        finish();
      }
    });

    socket.on('timeout', finish);
    socket.on('error', finish);
    socket.on('close', finish);
  });
}

/**
 * Deep Probe: Redis protocol ping
 */
function probeRedis(host, port, timeout = 800) {
  return new Promise((resolve) => {
    let resolved = false;
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    const finish = (val = '') => {
      if (resolved) return;
      resolved = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(val);
    };

    socket.connect(port, host, () => {
      socket.write('*1\r\n$4\r\nPING\r\n');
    });

    socket.on('data', (chunk) => {
      const resp = chunk.toString();
      if (resp.includes('PONG')) finish('Redis (Open Auth)');
      else if (resp.includes('NOAUTH')) finish('Redis (Password Protected)');
      else finish('Redis Service');
    });

    socket.on('timeout', () => finish(''));
    socket.on('error', () => finish(''));
  });
}

/**
 * Scan a single port with deep multi-protocol probes
 */
function scanPort(host, port, timeout = 1200, grabBanner = true) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = '';
    let isFinished = false;
    let bannerTimer = null;
    let rttMs = null;
    const connectStart = Date.now();

    socket.setTimeout(timeout);

    const finish = async (status, errorMsg = '') => {
      if (isFinished) return;
      isFinished = true;
      if (bannerTimer) clearTimeout(bannerTimer);
      socket.removeAllListeners();
      socket.destroy();

      let deepBanner = banner.trim();

      if (status === 'open' && grabBanner) {
        if ([443, 8443, 9443].includes(port)) {
          const tlsInfo = await probeTLS(host, port, Math.min(timeout, 1200));
          if (tlsInfo) deepBanner = tlsInfo;
        } else if ([80, 8080, 3000, 5000, 8000, 8888, 9000].includes(port) && !deepBanner) {
          const httpInfo = await probeHTTP(host, port, Math.min(timeout, 1200));
          if (httpInfo) deepBanner = httpInfo;
        } else if (port === 6379) {
          const redisInfo = await probeRedis(host, port, Math.min(timeout, 1000));
          if (redisInfo) deepBanner = redisInfo;
        }
      }

      const advisory = RISK_ADVISORIES[port] || null;

      resolve({
        port,
        status, // 'open', 'closed', 'filtered'
        service: COMMON_SERVICES[port] || 'unknown',
        banner: deepBanner,
        rtt: rttMs !== null ? `${rttMs}ms` : undefined,
        rttMs,
        advisory,
        error: errorMsg
      });
    };

    socket.on('connect', () => {
      rttMs = Date.now() - connectStart;
      if (!grabBanner) {
        finish('open');
        return;
      }

      bannerTimer = setTimeout(() => {
        finish('open');
      }, 350);

      socket.on('data', (data) => {
        if (bannerTimer) clearTimeout(bannerTimer);
        const cleanStr = data.toString('utf-8').replace(/[^\x20-\x7E\r\n]/g, '').trim();
        banner = cleanStr.split(/[\r\n]+/)[0] || '';
        finish('open');
      });
    });

    socket.on('timeout', () => {
      finish('filtered', 'Timeout');
    });

    socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') {
        finish('closed', 'Connection Refused');
      } else if (err.code === 'EHOSTUNREACH' || err.code === 'ENETUNREACH' || err.code === 'ETIMEDOUT') {
        finish('filtered', err.code);
      } else if (err.code === 'EACCES') {
        finish('filtered', 'Firewall / Restricted');
      } else {
        finish('closed', err.code || 'Error');
      }
    });

    socket.connect(port, host);
  });
}

/**
 * Concurrency worker pool
 */
async function scanWorkerPool(host, ports, concurrency = 50, timeout = 1200, grabBanner = true, onResult) {
  const results = [];
  let currentIndex = 0;

  async function worker() {
    while (currentIndex < ports.length) {
      const idx = currentIndex++;
      const port = ports[idx];
      const result = await scanPort(host, port, timeout, grabBanner);
      results.push(result);
      if (onResult) {
        onResult(result, results.length, ports.length);
      }
    }
  }

  const workerCount = Math.min(concurrency, ports.length);
  const workers = Array.from({ length: workerCount }, () => worker());
  await Promise.all(workers);
  return results;
}

/**
 * Reverse DNS Lookup with timeout
 */
async function getReverseDNS(ip) {
  try {
    const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 600));
    const lookup = dns.reverse(ip);
    const hostnames = await Promise.race([lookup, timeout]);
    return hostnames && hostnames.length > 0 ? hostnames[0] : '';
  } catch {
    return '';
  }
}

/**
 * Local Network Interface Subnet Auto-Detection
 */
function getLocalSubnets() {
  const interfaces = os.networkInterfaces();
  const subnets = [];

  for (const [name, addrs] of Object.entries(interfaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        const parts = addr.address.split('.').map(Number);
        const baseSubnet = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
        subnets.push({
          interface: name,
          ip: addr.address,
          netmask: addr.netmask,
          subnet: baseSubnet
        });
      }
    }
  }
  return subnets;
}

function parsePorts(portArg) {
  if (!portArg || portArg.toLowerCase() === 'top') {
    return DEFAULT_TOP_PORTS;
  }
  if (portArg.toLowerCase() === 'fast' || portArg.toLowerCase() === 'f') {
    return FAST_TOP_100_PORTS;
  }

  const ports = new Set();
  const parts = portArg.split(',');

  for (const part of parts) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    if (trimmed.includes('-')) {
      const [startStr, endStr] = trimmed.split('-');
      const start = parseInt(startStr, 10);
      const end = parseInt(endStr, 10);
      if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
        throw new Error(`Invalid port range: "${trimmed}". Must be 1-65535.`);
      }
      for (let p = start; p <= end; p++) {
        ports.add(p);
      }
    } else {
      const p = parseInt(trimmed, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        throw new Error(`Invalid port number: "${trimmed}". Must be 1-65535.`);
      }
      ports.add(p);
    }
  }

  return Array.from(ports).sort((a, b) => a - b);
}

function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0);
}

function intToIP(intVal) {
  return [
    (intVal >>> 24) & 255,
    (intVal >>> 16) & 255,
    (intVal >>> 8) & 255,
    intVal & 255
  ].join('.');
}

function parseTargets(targetArg) {
  const targets = [];

  if (targetArg.includes('/')) {
    const [baseIP, maskStr] = targetArg.split('/');
    const mask = parseInt(maskStr, 10);
    const ipInt = ipToInt(baseIP);
    if (ipInt !== null && mask >= 16 && mask <= 32) {
      const totalHosts = Math.pow(2, 32 - mask);
      const network = (ipInt & (~((1 << (32 - mask)) - 1))) >>> 0;
      const start = mask <= 30 ? network + 1 : network;
      const end = mask <= 30 ? network + totalHosts - 2 : network + totalHosts - 1;

      if (end - start > 512) {
        throw new Error(`CIDR block /${mask} contains ${totalHosts} hosts. Limit scans to /24 (256 hosts) or smaller.`);
      }

      for (let i = start; i <= end; i++) {
        targets.push(intToIP(i));
      }
      return targets;
    }
  }

  if (targetArg.includes('-') && !targetArg.startsWith('-')) {
    const [startStr, endStr] = targetArg.split('-');
    const startInt = ipToInt(startStr);
    let endInt;
    if (endStr.includes('.')) {
      endInt = ipToInt(endStr);
    } else {
      const base = startStr.substring(0, startStr.lastIndexOf('.') + 1);
      endInt = ipToInt(base + endStr);
    }

    if (startInt !== null && endInt !== null && startInt <= endInt) {
      if (endInt - startInt > 256) {
        throw new Error('Range exceeds maximum 256 hosts.');
      }
      for (let i = startInt; i <= endInt; i++) {
        targets.push(intToIP(i));
      }
      return targets;
    }
  }

  targets.push(targetArg);
  return targets;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Generate CSV Report
 */
function generateCSVReport(reportData) {
  const lines = [
    'Target,IP,Hostname,Device_Type,Operating_System,Confidence,MAC_Address,Hardware_Vendor,Port,Protocol,State,Service,Risk_Level,Banner'
  ];
  for (const res of reportData.results) {
    const dev = res.deviceInfo || {};
    for (const p of res.openPorts) {
      const risk = p.advisory ? p.advisory.level : 'LOW';
      const cleanBanner = (p.banner || '').replace(/"/g, '""');
      lines.push(
        `"${res.target}","${res.ip}","${res.hostname || ''}","${dev.deviceType || ''}","${dev.osGuess || ''}","${dev.confidence || 0}%","${dev.mac || ''}","${dev.vendor || ''}",${p.port},"tcp","${p.status}","${p.service}","${risk}","${cleanBanner}"`
      );
    }
  }
  return lines.join('\r\n');
}

/**
 * Generate Modern Dark Dashboard HTML Report with Device & OS Profile Cards
 */
function generateHTMLReport(reportData) {
  const openRows = [];
  const deviceCards = [];
  let riskAlertsCount = 0;

  for (const res of reportData.results) {
    const dev = res.deviceInfo || {};
    const openPortsStr = res.openPorts.map((p) => `${p.port}/${p.service}`).join(', ') || 'No open ports';

    deviceCards.push(`
      <div class="device-card">
        <div class="device-header">
          <div>
            <div class="device-type-badge">${escapeHTML(dev.deviceType || 'Network Device')}</div>
            <div class="device-title">${escapeHTML(res.ip)}${res.hostname ? ` (${escapeHTML(res.hostname)})` : ''}</div>
          </div>
          <div class="confidence-badge">${dev.confidence || 50}% CONFIDENCE</div>
        </div>
        <div class="device-body">
          <div class="device-meta-row">
            <span class="label">Operating System:</span>
            <span class="val os-text">${escapeHTML(dev.osGuess || 'Unknown')}</span>
          </div>
          <div class="device-meta-row">
            <span class="label">Hardware MAC:</span>
            <span class="val mac-code">${escapeHTML(dev.mac || 'N/A')}</span>
          </div>
          <div class="device-meta-row">
            <span class="label">Hardware Vendor:</span>
            <span class="val">${escapeHTML(dev.vendor || 'Unknown')}</span>
          </div>
          <div class="device-meta-row">
            <span class="label">Discovered Ports:</span>
            <span class="val ports-highlight">${escapeHTML(openPortsStr)}</span>
          </div>
          <div class="device-meta-row">
            <span class="label">Detection Clues:</span>
            <span class="val clues-text">${escapeHTML(dev.reasons || 'Standard probe')}</span>
          </div>
        </div>
      </div>
    `);

    for (const p of res.openPorts) {
      if (p.advisory) riskAlertsCount++;
      const riskBadge = p.advisory
        ? `<span class="badge ${p.advisory.level.toLowerCase()}">${p.advisory.level} RISK</span>`
        : `<span class="badge low">INFO</span>`;

      openRows.push(`
        <tr>
          <td><span class="badge ip">${res.ip}${res.hostname ? ` (${res.hostname})` : ''}</span></td>
          <td><span class="badge port">${p.port}/tcp</span></td>
          <td><span class="badge open">OPEN</span></td>
          <td><strong>${p.service}</strong></td>
          <td>${riskBadge}</td>
          <td class="banner-cell"><code>${p.banner ? escapeHTML(p.banner) : '<em>No banner response</em>'}</code></td>
        </tr>
      `);
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NETSCAN Device & OS Audit Report - MR.X [OFFICIAL]</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #121824;
      --border: #212c40;
      --text: #cbd5e1;
      --heading: #f8fafc;
      --accent: #38bdf8;
      --green: #22c55e;
      --yellow: #f59e0b;
      --red: #ef4444;
      --purple: #a855f7;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 30px 20px;
      line-height: 1.5;
    }
    .container { max-width: 1250px; margin: 0 auto; }
    .header {
      background: linear-gradient(135deg, #162032 0%, #101623 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 24px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    .tagline {
      color: var(--accent);
      font-weight: 700;
      font-size: 13px;
      letter-spacing: 1px;
      text-transform: uppercase;
      margin-bottom: 8px;
    }
    h1 { margin: 0 0 16px; color: var(--heading); font-size: 28px; }
    h2 { font-size: 20px; color: var(--heading); margin: 32px 0 16px; display: flex; align-items: center; gap: 8px; }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-top: 18px;
    }
    .meta-card {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .meta-label { font-size: 12px; color: #64748b; text-transform: uppercase; margin-bottom: 6px; }
    .meta-val { font-size: 26px; font-weight: bold; color: var(--heading); }
    .meta-val.green { color: var(--green); }
    .meta-val.yellow { color: var(--yellow); }
    .meta-val.purple { color: var(--purple); }

    /* Device Cards Grid */
    .device-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 18px;
      margin-bottom: 30px;
    }
    .device-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 20px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }
    .device-header {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 14px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 12px;
    }
    .device-type-badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--accent);
      background: #0284c722;
      padding: 2px 8px;
      border-radius: 4px;
      margin-bottom: 6px;
    }
    .device-title { font-size: 18px; font-weight: bold; color: var(--heading); }
    .confidence-badge {
      font-size: 11px;
      background: #22c55e22;
      color: var(--green);
      border: 1px solid #22c55e66;
      padding: 3px 6px;
      border-radius: 4px;
      font-weight: bold;
    }
    .device-meta-row {
      display: flex;
      font-size: 13px;
      margin-bottom: 8px;
      gap: 8px;
    }
    .device-meta-row .label { color: #64748b; min-width: 130px; }
    .device-meta-row .val { color: var(--text); font-weight: 500; }
    .os-text { color: #38bdf8 !important; font-weight: bold; }
    .mac-code { font-family: monospace; background: #090d16; padding: 2px 6px; border-radius: 4px; }
    .ports-highlight { color: #34d399 !important; }
    .clues-text { color: #94a3b8 !important; font-size: 12px; }

    .search-box {
      margin-bottom: 16px;
      display: flex;
      gap: 12px;
    }
    .search-box input {
      flex: 1;
      padding: 12px 16px;
      border-radius: 8px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      color: var(--heading);
      font-size: 14px;
      outline: none;
    }
    .search-box input:focus { border-color: var(--accent); }
    .table-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow-x: auto;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th {
      background: #192233;
      color: #94a3b8;
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
    }
    td { padding: 14px 18px; border-bottom: 1px solid var(--border); font-size: 14px; }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      font-family: monospace;
    }
    .badge.port { background: #0284c722; color: #38bdf8; border: 1px solid #0284c766; }
    .badge.ip { background: #1e293b; color: #f8fafc; }
    .badge.open { background: #22c55e22; color: #22c55e; border: 1px solid #22c55e66; }
    .badge.high { background: #ef444422; color: #f87171; border: 1px solid #ef444466; }
    .badge.medium { background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b66; }
    .badge.low { background: #64748b22; color: #94a3b8; }
    .banner-cell code {
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px;
      background: #090d16;
      padding: 4px 8px;
      border-radius: 4px;
      border: 1px solid #1e293b;
      display: inline-block;
      max-width: 440px;
      overflow-x: auto;
      white-space: nowrap;
    }
    .footer { text-align: center; margin-top: 36px; font-size: 13px; color: #64748b; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="tagline">NETSCAN developed by MR.X [OFFICIAL]</div>
      <h1>Network Device Inventory & OS Security Audit Report</h1>
      <div class="meta-grid">
        <div class="meta-card">
          <div class="meta-label">Total Targets</div>
          <div class="meta-val">${reportData.targetsCount}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Open Ports Found</div>
          <div class="meta-val green">${reportData.totalOpen}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">OS Fingerprints</div>
          <div class="meta-val purple">${reportData.results.length}</div>
        </div>
        <div class="meta-card">
          <div class="meta-label">Risk Advisories</div>
          <div class="meta-val yellow">${riskAlertsCount}</div>
        </div>
      </div>
    </div>

    <h2>Network Devices & OS Profile Matrix</h2>
    <div class="device-grid">
      ${deviceCards.join('')}
    </div>

    <h2>Detailed Port & Fingerprint Analysis</h2>
    <div class="search-box">
      <input type="text" id="filterInput" placeholder="Filter ports, services, OS or IP addresses..." onkeyup="filterTable()">
    </div>

    <div class="table-card">
      <table id="portsTable">
        <thead>
          <tr>
            <th>Host / IP</th>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Exposure Level</th>
            <th>Fingerprint / Banner</th>
          </tr>
        </thead>
        <tbody>
          ${openRows.length > 0 ? openRows.join('') : '<tr><td colspan="6" style="text-align:center; padding: 30px; color:#64748b;">No open ports discovered in the selected range.</td></tr>'}
        </tbody>
      </table>
    </div>

    <div class="footer">
      Generated by <strong>NETSCAN</strong> | Developed by MR.X [OFFICIAL] | ${new Date(reportData.timestamp).toLocaleString()}
    </div>
  </div>

  <script>
    function filterTable() {
      const q = document.getElementById('filterInput').value.toLowerCase();
      const rows = document.querySelectorAll('#portsTable tbody tr');
      rows.forEach(r => {
        r.style.display = r.innerText.toLowerCase().includes(q) ? '' : 'none';
      });
    }
  </script>
</body>
</html>`;
}

function printHelp() {
  printBanner();
  console.log(`Usage:
  netscan [target] [options]
  node scanner.js [target] [options]

Arguments:
  target                  Target IP, hostname, CIDR, or range:
                          - Single host:   127.0.0.1, localhost, scanme.nmap.org
                          - CIDR subnet:   192.168.1.0/24
                          - IP Range:      192.168.1.1-192.168.1.25

Reconnaissance & OS Options:
  -O, --os                Enable deep OS & device type detection (Enabled by default)
  -l, --local             Auto-detect and scan local LAN interface subnet
  -s, --sweep             Host discovery sweep mode (quick active host mapping)

Port Scope Options:
  -p, --ports <specs>     Port(s) to scan:
                          - "top"           Scan common 35+ service ports (default)
                          - "fast" / "-F"   Scan top 100 high-frequency ports
                          - "80,443,8080"   Scan comma-separated list
                          - "1-1024"        Scan continuous port range

Performance & Timing Options:
  -T <1-5>                Timing profile template (Nmap style):
                          -T1: Paranoid (serial) | -T3: Normal (default) | -T5: Insane (high speed)
  -t, --timeout <ms>      Socket timeout in milliseconds (default: 1200)
  -c, --concurrency <n>   Concurrent connections count (default: 50)

Output & Reporting Options:
  -o, --output <file>     Export results to HTML (.html), JSON (.json), or CSV (.csv)
  --html <file>           Export an interactive HTML dashboard report
  -v, --verbose           Show closed and filtered ports in terminal output
  --no-banner             Skip service banner grabbing for faster scan
  -h, --help              Show this help guide

Examples:
  netscan 127.0.0.1
  netscan --local --sweep
  netscan 192.168.1.0/24 -F -O --html network_audit.html
  netscan scanme.nmap.org -p 22,80,443 -o audit.csv
  netscan 192.168.1.1 -p 1-1000 -c 100
`);
}

/**
 * Interactive Setup Wizard
 */
async function promptInteractive() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  const ask = (query) => new Promise((resolve) => rl.question(query, resolve));

  printBanner();
  console.log(`${C.yellow}No target specified. Starting Interactive Setup Wizard:${C.reset}\n`);

  const localSubnets = getLocalSubnets();
  if (localSubnets.length > 0) {
    console.log(`${C.cyan}Detected Local Network Interfaces:${C.reset}`);
    localSubnets.forEach((s, idx) => {
      console.log(`  [${idx + 1}] ${C.bold}${s.interface}${C.reset}: ${s.ip} (Subnet: ${C.green}${s.subnet}${C.reset})`);
    });
    console.log();
  }

  let target = (await ask(`${C.bold}Target Host / IP / Subnet${C.reset} (default: 127.0.0.1): `)).trim();
  if (!target) target = '127.0.0.1';

  let portsInput = (await ask(`${C.bold}Ports to Scan${C.reset} ['top', 'fast', '1-1024', or '22,80,443'] (default: top): `)).trim();
  if (!portsInput) portsInput = 'top';

  rl.close();
  return { target, portsInput };
}

/**
 * Main Entry Point
 */
async function main() {
  const args = process.argv.slice(2);

  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    return;
  }

  let targetArg = '';
  let portsArg = 'top';
  let timeout = 1200;
  let concurrency = 50;
  let grabBanner = true;
  let verbose = false;
  let sweepMode = false;
  let outputFile = null;
  let timingProfile = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-p' || arg === '--ports') {
      portsArg = args[++i];
    } else if (arg === '-F' || arg === '--fast') {
      portsArg = 'fast';
    } else if (arg === '-T' && args[i + 1]) {
      timingProfile = parseInt(args[++i], 10);
    } else if (arg.startsWith('-T') && arg.length === 3) {
      timingProfile = parseInt(arg[2], 10);
    } else if (arg === '-t' || arg === '--timeout') {
      timeout = parseInt(args[++i], 10);
    } else if (arg === '-c' || arg === '--concurrency') {
      concurrency = parseInt(args[++i], 10);
    } else if (arg === '-o' || arg === '--output') {
      outputFile = args[++i];
    } else if (arg === '--html') {
      outputFile = args[++i];
    } else if (arg === '-s' || arg === '--sweep') {
      sweepMode = true;
    } else if (arg === '-l' || arg === '--local') {
      const locals = getLocalSubnets();
      if (locals.length > 0) {
        targetArg = locals[0].subnet;
      }
    } else if (arg === '--no-banner') {
      grabBanner = false;
    } else if (arg === '-v' || arg === '--verbose') {
      verbose = true;
    } else if (!arg.startsWith('-') && !targetArg) {
      targetArg = arg;
    }
  }

  if (timingProfile && TIMING_PROFILES[timingProfile]) {
    const prof = TIMING_PROFILES[timingProfile];
    concurrency = prof.concurrency;
    timeout = prof.timeout;
  }

  if (!targetArg) {
    const answers = await promptInteractive();
    targetArg = answers.target;
    portsArg = answers.portsInput;
  } else {
    printBanner();
  }

  let targets;
  try {
    targets = parseTargets(targetArg);
  } catch (err) {
    console.error(`\n${C.red}[!] Target Parse Error:${C.reset} ${err.message}\n`);
    process.exit(1);
  }

  let ports;
  try {
    ports = sweepMode ? SWEEP_PORTS : parsePorts(portsArg);
  } catch (err) {
    console.error(`\n${C.red}[!] Port Parse Error:${C.reset} ${err.message}\n`);
    process.exit(1);
  }

  // Load ARP table for local MAC mapping
  const arpTable = getArpTable();

  console.log(`${C.cyan}Targets Count:${C.reset}  ${targets.length} host(s) [${targetArg}]`);
  console.log(`${C.cyan}Ports Scope:${C.reset}    ${ports.length} ports [${sweepMode ? 'Sweep Discovery' : portsArg}]`);
  console.log(`${C.cyan}Engine Timing:${C.reset}  Concurrency: ${concurrency} workers | Timeout: ${timeout}ms${timingProfile ? ` (Profile -T${timingProfile})` : ''}`);
  console.log(`${C.cyan}OS & Device:${C.reset}   Deep Device Classification & Stack Heuristics Active`);
  console.log(`${C.cyan}Scan Started:${C.reset}   ${new Date().toLocaleString()}`);
  console.log(`${C.gray}${'―'.repeat(74)}${C.reset}`);

  const overallResults = [];
  const globalStart = Date.now();

  for (let t = 0; t < targets.length; t++) {
    const currentTarget = targets[t];
    let resolvedIP = currentTarget;

    try {
      const lookup = await dns.lookup(currentTarget);
      resolvedIP = lookup.address;
    } catch (err) {
      if (!sweepMode) {
        console.error(`${C.red}[!] Could not resolve host:${C.reset} ${currentTarget} (${err.message})`);
      }
      continue;
    }

    const reverseHostname = await getReverseDNS(resolvedIP);
    const targetMac = arpTable.get(resolvedIP) || '';

    if (targets.length > 1) {
      console.log(`\n${C.bold}Scanning Target [${t + 1}/${targets.length}]: ${currentTarget}${C.reset} (${resolvedIP}${reverseHostname ? ` - ${reverseHostname}` : ''})`);
    }

    console.log(`${C.bold}${'PORT'.padEnd(12)} ${'STATE'.padEnd(12)} ${'SERVICE'.padEnd(18)} BANNER / FINGERPRINT${C.reset}`);
    console.log(`${C.gray}${'―'.repeat(74)}${C.reset}`);

    const targetOpen = [];
    let closedCount = 0;
    let filteredCount = 0;

    await scanWorkerPool(
      resolvedIP,
      ports,
      concurrency,
      timeout,
      grabBanner,
      (result, scannedCount, totalCount) => {
        if (result.status === 'open') {
          targetOpen.push(result);
          clearProgressBar();
          const portStr = `${result.port}/tcp`.padEnd(12);
          const stateStr = `${C.green}open${C.reset}`.padEnd(21);
          const serviceStr = result.service.padEnd(18);
          const rttStr = result.rtt ? `${C.cyan}[${result.rtt}]${C.reset} ` : '';
          const bannerStr = result.banner ? `${C.white}${result.banner}${C.reset}` : '';
          console.log(`${portStr} ${stateStr} ${serviceStr} ${rttStr}${bannerStr}`);

          if (result.advisory) {
            console.log(`  ${C.yellow}↳ [${result.advisory.level} RISK]${C.reset} ${C.dim}${result.advisory.tip}${C.reset}`);
          }
        } else if (result.status === 'filtered') {
          filteredCount++;
          if (verbose) {
            clearProgressBar();
            const portStr = `${result.port}/tcp`.padEnd(12);
            const stateStr = `${C.yellow}filtered${C.reset}`.padEnd(21);
            const serviceStr = result.service.padEnd(18);
            console.log(`${portStr} ${stateStr} ${serviceStr} ${C.dim}(${result.error})${C.reset}`);
          }
        } else {
          closedCount++;
          if (verbose) {
            clearProgressBar();
            const portStr = `${result.port}/tcp`.padEnd(12);
            const stateStr = `${C.red}closed${C.reset}`.padEnd(21);
            const serviceStr = result.service.padEnd(18);
            console.log(`${portStr} ${stateStr} ${serviceStr}`);
          }
        }

        renderProgressBar(scannedCount, totalCount, targetOpen.length);
      }
    );

    clearProgressBar();

    // Perform Device & OS Fingerprint
    const deviceInfo = analyzeDevice(resolvedIP, reverseHostname, targetMac, targetOpen);

    // Print Device & OS Reconnaissance card
    console.log(`${C.dim}${'―'.repeat(74)}${C.reset}`);
    console.log(`${C.bold}${C.cyan}[+] DEVICE & OS RECONNAISSANCE:${C.reset}`);
    console.log(`  Device Type:       ${C.bold}${deviceInfo.deviceType}${C.reset}`);
    console.log(`  Operating System:  ${C.green}${C.bold}${deviceInfo.osGuess}${C.reset} (${deviceInfo.confidence}% confidence)`);
    if (targetMac) {
      console.log(`  Hardware MAC:      ${C.yellow}${targetMac.toUpperCase()}${C.reset} (${deviceInfo.vendor})`);
    }
    if (reverseHostname) {
      console.log(`  Host FQDN:         ${reverseHostname}`);
    }
    console.log(`  Classification:    ${C.dim}${deviceInfo.reasons}${C.reset}`);

    if (targetOpen.length === 0 && !verbose) {
      console.log(`  ${C.dim}(No open TCP ports detected on this host)${C.reset}`);
    }

    overallResults.push({
      target: currentTarget,
      ip: resolvedIP,
      hostname: reverseHostname,
      deviceInfo,
      openCount: targetOpen.length,
      closedCount,
      filteredCount,
      openPorts: targetOpen
    });
  }

  const durationSec = ((Date.now() - globalStart) / 1000).toFixed(2);
  const totalOpen = overallResults.reduce((acc, r) => acc + r.openCount, 0);

  console.log(`\n${C.gray}${'―'.repeat(74)}${C.reset}`);
  console.log(`${C.bold}Scan Complete!${C.reset} Elapsed: ${durationSec}s`);
  console.log(`Total Targets Scanned: ${targets.length}`);
  console.log(`Total Open Ports:      ${totalOpen > 0 ? C.green : C.gray}${totalOpen}${C.reset}`);

  // Export File (HTML, JSON, or CSV)
  if (outputFile) {
    const reportData = {
      tool: 'NETSCAN developed by MR.X [OFFICIAL]',
      timestamp: new Date().toISOString(),
      durationSeconds: parseFloat(durationSec),
      targetInput: targetArg,
      targetsCount: targets.length,
      totalOpen,
      results: overallResults
    };

    try {
      const lowerOut = outputFile.toLowerCase();
      if (lowerOut.endsWith('.html')) {
        const htmlContent = generateHTMLReport(reportData);
        await fs.writeFile(outputFile, htmlContent, 'utf-8');
        console.log(`${C.green}[✓] Interactive HTML Report exported:${C.reset} ${outputFile}`);
      } else if (lowerOut.endsWith('.csv')) {
        const csvContent = generateCSVReport(reportData);
        await fs.writeFile(outputFile, csvContent, 'utf-8');
        console.log(`${C.green}[✓] CSV Device & Port Audit exported:${C.reset} ${outputFile}`);
      } else {
        await fs.writeFile(outputFile, JSON.stringify(reportData, null, 2), 'utf-8');
        console.log(`${C.green}[✓] JSON Audit Report exported:${C.reset} ${outputFile}`);
      }
    } catch (err) {
      console.error(`${C.red}[!] Failed to write export file:${C.reset} ${err.message}`);
    }
  }

  console.log();
}

main().catch((err) => {
  console.error(`\n${C.red}[!] Fatal Error:${C.reset}`, err);
  process.exit(1);
});
