// devnet-browser.mjs: a Chromium for atproto-devnet's https devnet. Under scripts/https-run, Node
// trusts the devnet's CA through NODE_EXTRA_CA_CERTS, but Chromium does not read it, and the hosts
// file https-run makes lists each handle by name, so a handle made after it was written does not
// resolve. Chromium gets two launch args instead:
//
//   --host-resolver-rules              the devnet's names resolve to the address its nginx answers on
//                                      (SG_BIND, 127.0.0.1 unless the devnet was given another):
//                                      every name under SG_DOMAIN, plc.directory, and apps under
//                                      .devnet.internal
//   --ignore-certificate-errors-spki-list
//                                      trust exactly the key of the devnet's leaf certificate, and
//                                      no other certificate error
//
// The leaf is SG_LEAF_FILE, or else leaf.crt beside SG_CA_FILE (lib.mjs sets that to the
// devnet's data/https/ca.crt). A pattern with a leading * matches names of any depth.
import { X509Certificate, createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'

// The base64 SHA-256 of the certificate's DER SubjectPublicKeyInfo, the form Chromium's
// --ignore-certificate-errors-spki-list takes.
export function leafSpki(certPath) {
  const cert = new X509Certificate(readFileSync(certPath))
  return createHash('sha256')
    .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64')
}

function leafFile() {
  if (process.env.SG_LEAF_FILE) return process.env.SG_LEAF_FILE
  if (process.env.SG_CA_FILE) return path.join(path.dirname(process.env.SG_CA_FILE), 'leaf.crt')
  throw new Error('SG_LEAF_FILE is required')
}

export async function launchBrowser(chromium) {
  const domain = process.env.SG_DOMAIN || 'devnet.test'
  const bind = process.env.SG_BIND || '127.0.0.1'
  const names = [`*.${domain}`, 'plc.directory', '*.devnet.internal']
  const args = [
    `--host-resolver-rules=${names.map((n) => `MAP ${n} ${bind}`).join(', ')}`,
    `--ignore-certificate-errors-spki-list=${leafSpki(leafFile())}`,
  ]
  // A container that runs as root cannot use Chromium's sandbox (CHROMIUM_NO_SANDBOX=1 there).
  if (process.env.CHROMIUM_NO_SANDBOX) args.push('--no-sandbox')
  return chromium.launch({ args })
}
