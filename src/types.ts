export type Protocol = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'HTTP' | 'TLS';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface Alert {
  id: string;
  timestamp: number;
  type: string;
  severity: Severity;
  sourceIp: string;
  details: string;
}

export interface DetectionRules {
  portScan: boolean;
  synFlood: boolean;
  icmpFlood: boolean;
  bruteForce: boolean;
  arpSpoofing: boolean;
}

export interface PacketHeaders {
  ethernet: {
    src: string;
    dst: string;
    type: string;
  };
  ip: {
    version: number;
    src: string;
    dst: string;
    ttl: number;
    protocol: string;
  };
  transport: {
    srcPort?: number;
    dstPort?: number;
    flags?: string[];
    sequenceNumber?: number;
    acknowledgmentNumber?: number;
    type?: string;
  };
}

export interface Packet {
  id: string;
  timestamp: number;
  source: string;
  destination: string;
  protocol: Protocol;
  length: number;
  info: string;
  payload: string;
  headers: PacketHeaders;
  isSuspicious?: boolean;
}
