import dns from 'dns/promises';
import net from 'net';
/**
 * "Self-Hosted Friendly" Blocklist.
 * * 1. BLOCKS: Loopback (Localhost) - Prevents accessing the server itself.
 * 2. BLOCKS: Link-Local (Cloud Metadata) - Prevents accessing AWS/Azure secrets.
 * 3. ALLOWS: Private LAN (10.x, 192.168.x) - Allows connecting to your local NAS/Server.
 */
const dangerousIpRanges = [
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
  if (dangerousIpRanges.some(regex => regex.test(host))) {
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
