import { Packet, Protocol } from '../types';

const COMMON_IPS = [
  '192.168.1.1',
  '192.168.1.45',
  '10.0.0.5',
  '172.16.0.10',
  '8.8.8.8',
  '1.1.1.1',
  '162.159.200.12',
  '157.240.22.35',
  '44.22.45.122'
];

const MAC_ADDRESSES = [
  '00:0a:95:9d:68:16',
  '00:14:22:01:23:45',
  'b4:2e:99:a1:b2:c3',
  '8c:85:90:3a:4b:5c'
];

function getRandomItem<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function generateMac() {
  return MAC_ADDRESSES[Math.floor(Math.random() * MAC_ADDRESSES.length)];
}

function generateIp() {
  return COMMON_IPS[Math.floor(Math.random() * COMMON_IPS.length)];
}

export function generateRandomPacket(): Packet {
  const protocol: Protocol = ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS'][Math.floor(Math.random() * 6)] as Protocol;
  const srcIp = generateIp();
  let dstIp = generateIp();
  while (dstIp === srcIp) dstIp = generateIp();

  const srcPort = Math.floor(Math.random() * 65535);
  const dstPort = [80, 443, 53, 22, 21, 3306, 8080][Math.floor(Math.random() * 7)];
  
  const id = Math.random().toString(36).substring(2, 11);
  const timestamp = Date.now();
  
  let info = '';
  let payload = '';
  let isSuspicious = false;
  let threatLevel: 'Low' | 'Medium' | 'High' = 'Low';

  switch (protocol) {
    case 'TCP':
      const flags = ['SYN', 'ACK', 'PUSH', 'FIN'];
      const activeFlags = [flags[Math.floor(Math.random() * flags.length)]];
      if (Math.random() > 0.8) activeFlags.push('ACK');
      info = `${srcPort} → ${dstPort} [${activeFlags.join(', ')}] Seq=${Math.floor(Math.random() * 10000)} Win=${Math.floor(Math.random() * 65535)}`;
      payload = '47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a';
      if (activeFlags.includes('SYN') && Math.random() > 0.9) {
        isSuspicious = true;
        threatLevel = 'Medium';
        info += ' [Potential Port Scan]';
      }
      break;
    case 'UDP':
      info = `${srcPort} → ${dstPort} Len=${Math.floor(Math.random() * 1400)}`;
      payload = 'a1 b2 c3 d4 e5 f6 07 08 09 10 11 12 13 14 15';
      break;
    case 'ICMP':
      const types = ['Echo (ping) request', 'Echo (ping) reply', 'Destination unreachable'];
      const type = types[Math.floor(Math.random() * types.length)];
      info = `${type} id=0x${Math.floor(Math.random() * 65535).toString(16)}, seq=${Math.floor(Math.random() * 100)}`;
      payload = '08 00 4d 5a 00 01 00 01 61 62 63 64 65 66 67 68';
      break;
    case 'DNS':
      const domains = ['google.com', 'github.com', 'apple.com', 'evil-malware.cc', 'internal.corp'];
      const domain = domains[Math.floor(Math.random() * domains.length)];
      info = `Standard query 0x${Math.floor(Math.random() * 65535).toString(16)} A ${domain}`;
      if (domain.includes('evil')) {
        isSuspicious = true;
        threatLevel = 'High';
        info += ' [Known Malicious Domain]';
      }
      break;
    case 'HTTP':
      const methods = ['GET', 'POST', 'PUT'];
      const paths = ['/', '/login', '/api/data', '/admin/setup'];
      const path = paths[Math.floor(Math.random() * paths.length)];
      info = `${methods[Math.floor(Math.random() * methods.length)]} ${path} HTTP/1.1`;
      if (path.includes('admin') && Math.random() > 0.5) {
        isSuspicious = true;
        threatLevel = 'High';
        info += ' [Unauthorized Admin Access Attempt]';
      }
      break;
    case 'TLS':
      info = 'Client Hello, TLS 1.3';
      break;
  }

  return {
    id,
    timestamp,
    source: srcIp,
    destination: dstIp,
    protocol,
    length: Math.floor(Math.random() * 1500) + 64,
    info,
    payload,
    isSuspicious,
    threatLevel,
    headers: {
      ethernet: {
        src: generateMac(),
        dst: generateMac(),
        type: 'IPv4 (0x0800)'
      },
      ip: {
        version: 4,
        src: srcIp,
        dst: dstIp,
        ttl: 64,
        protocol: protocol === 'ICMP' ? 'ICMP (1)' : protocol === 'UDP' || protocol === 'DNS' ? 'UDP (17)' : 'TCP (6)'
      },
      transport: {
        srcPort: protocol !== 'ICMP' ? srcPort : undefined,
        dstPort: protocol !== 'ICMP' ? dstPort : undefined,
        flags: protocol === 'TCP' ? ['ACK'] : undefined,
        type: protocol === 'ICMP' ? 'Echo Request' : undefined
      }
    }
  };
}
