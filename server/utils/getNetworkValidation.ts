import { promises as dns } from 'dns';
import net from 'net';
/**
 * "Self-Hosted Friendly" Blocklist.
 * * 1. BLOCKS: Loopback (Localhost) - Prevents accessing the server itself.
 * 2. BLOCKS: Link-Local (Cloud Metadata) - Prevents accessing AWS/Azure secrets.
 * 3. ALLOWS: Private LAN (10.x, 192.168.x) - Allows connecting to your local NAS/Server.
 */
const dangerousIPRanges = [
  /^127\./,        // Loopback (127.0.0.0/8) - CRITICAL TO BLOCK
  /^169\.254\./,   // Link-Local (169.254.0.0/16) - CRITICAL TO BLOCK (AWS/Cloud)
  /^0\./,          // Invalid (0.0.0.0/8)
  /^(22[4-9]|23[0-9])\./, // Multicast
];

/**
 * Checks if a hostname or IP address is considered an internal,
 * loopback, or private network address.
 * * @param host The hostname or IP address to check.
 * @returns true if the host is a private address, false otherwise.
 */
export function isPrivateNetwork(host: string): boolean {
  // Check against the dangerous IP list
  if (dangerousIPRanges.some(regex => regex.test(host))) {
    return true;
  }

  // Block specific dangerous hostnames
  const blockedNames = ['localhost', 'host.docker.internal'];
  if (blockedNames.includes(host.toLowerCase())) {
      return true;
  }
  // ALLOWS: 192.168.x.x, 10.x.x.x, and subdomains like jellyfin.local
  return false;
}

/**
 * Resolves a hostname to an IP and throws an error if it resolves
 * to a Loopback (127.x) or Link-Local (169.254.x) address.
 */
export async function validateHostStrict(hostname: string): Promise<void> {
  // Check the hostname directly if it is an IP
  if (net.isIP(hostname)) {
    if (isDangerousIP(hostname)) {
      throw new Error(`Blocked dangerous IP address: ${hostname}`);
    }
    return;
  }

  // If the hostname is a domain/subdomain, resolve it to an IP first (Prevents DNS Rebinding)
  try {
    const { address } = await dns.lookup(hostname);

    // 3. Check the resolved IP
    if (isDangerousIP(address)) {
      throw new Error(`Hostname ${hostname} resolves to blocked IP: ${address}`);
    }
  } catch (err) {
    // If we can't resolve it, it might be invalid or internal DNS that failed.
    // You can choose to throw or allow based on strictness.
    throw new Error(`Could not validate hostname: ${err.message}`);
  }
}

/**
 * Checks if an IP is Loopback or Link-Local (Metadata).
 * Allows standard Private LANs (10.x, 192.168.x) for self-hosting.
 */
function isDangerousIP(ip: string): boolean {
  // IPv4 Checks
  if (net.isIPv4(ip)) {
    // Block 127.0.0.0/8 (Loopback)
    if (ip.startsWith('127.')) return true;
    // Block 169.254.0.0/16 (Link-Local / Cloud Metadata)
    if (ip.startsWith('169.254.')) return true;
    // Block 0.0.0.0/8
    if (ip.startsWith('0.')) return true;
  }

  // IPv6 Checks
  if (net.isIPv6(ip)) {
    // Block ::1 (Loopback)
    if (ip === '::1') return true;
    // Block ::ffff:127.x.x.x (IPv4-mapped Loopback)
    if (ip.toLowerCase().startsWith('::ffff:127.')) return true;
  }

  return false;
}
