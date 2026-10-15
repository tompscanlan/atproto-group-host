// Like atproto-devnet's https/app-names.cjs, but also sends *.devnet.test (handles) to nginx,
// since Docker's DNS knows only the three PDS aliases.
'use strict';
const dns = require('dns');
const isOurs = (n) => typeof n === 'string' && /\.devnet\.(internal|test)\.?$/i.test(n);
const lookup = dns.lookup;
dns.lookup = function (h, ...rest) { return lookup.call(this, isOurs(h) ? 'nginx' : h, ...rest); };
const lp = dns.promises.lookup;
dns.promises.lookup = function (h, ...rest) { return lp.call(this, isOurs(h) ? 'nginx' : h, ...rest); };
