/**
 * The one import site for @peculiar/x509. Since 2.x it resolves its parsers
 * through tsyringe, which needs the Reflect metadata polyfill loaded first;
 * importing it from here guarantees the order everywhere.
 */

import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

x509.cryptoProvider.set(crypto);

export { x509 };
