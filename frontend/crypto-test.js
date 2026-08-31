const crypto = require('crypto');

const hash = crypto.createHash('md5');
hash.update('test data');

const encrypted = crypto.createCipheriv(
  'aes-256-cbc',
  Buffer.alloc(32),
  Buffer.alloc(16)
);