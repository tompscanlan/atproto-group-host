// Like atproto-devnet's https/app-names.cjs, but also sends every name under the devnet's domain
// (DEVNET_DOMAIN, devnet.test by default: the PDSes and their handles) to nginx, since Docker's
// DNS knows only the three PDS aliases.
'use strict';
const dns = require('dns');
const domain = (process.env.DEVNET_DOMAIN || 'devnet.test').toLowerCase();
const isOurs = (n) => {
  if (typeof n !== 'string') return false;
  const h = n.toLowerCase().replace(/\.$/, '');
  return h.endsWith('.devnet.internal') || h.endsWith(`.${domain}`);
};
const lookup = dns.lookup;
dns.lookup = function (h, ...rest) { return lookup.call(this, isOurs(h) ? 'nginx' : h, ...rest); };
const lp = dns.promises.lookup;
dns.promises.lookup = function (h, ...rest) { return lp.call(this, isOurs(h) ? 'nginx' : h, ...rest); };
