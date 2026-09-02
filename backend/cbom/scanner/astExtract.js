// scanner/astExtract.js — Phase 2
//
// AST-based code-level cryptographic API usage detector using @babel/parser
// and @babel/traverse, with a resilient regex fallback.
//
// Detects:
//   - Node.js crypto module (createHash, createCipher/createCipheriv, createDecipher/createDecipheriv,
//     createSign, createVerify, createHmac, pbkdf2, scrypt, randomBytes, generateKeyPair, createDiffieHellman, createECDH)
//   - bcrypt / bcrypt-nodejs / bcryptjs (hash, hashSync, compare, compareSync, genSalt, genSaltSync)
//   - jsonwebtoken / jwt / jose (sign, verify, SignJWT, jwtVerify, compactEncrypt) with JWA algorithm extraction and weak secret / none detection
//   - crypto-js (AES, DES, 3DES, RC4, Rabbit, SHA256, MD5, HMAC, PBKDF2)
//   - node-forge (cipher, md, pki, rsa)
//   - argon2 / scrypt / tweetnacl
//   - WebCrypto API (crypto.subtle)
//   - Commented crypto patterns (e.g. security fixes and tutorial examples in codebases like NodeGoat)

const fs = require('node:fs');
const path = require('node:path');

const { createRequire } = require('node:module');

function getParser() {
  try {
    const req = createRequire(__filename);
    return req('@babel/parser');
  } catch {
    try {
      return require('@babel/parser');
    } catch {
      return null;
    }
  }
}

function getTraverse() {
  try {
    const req = createRequire(__filename);
    const t = req('@babel/traverse');
    return t.default || t;
  } catch {
    try {
      const t = require('@babel/traverse');
      return t.default || t;
    } catch {
      return null;
    }
  }
}

const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { AssetType, Primitive, MaterialType } = require('../core/taxonomy');

const CIPHER_MODE_TOKENS = new Set([
  'cbc', 'ecb', 'cfb', 'cfb1', 'cfb8', 'ofb', 'ctr', 'gcm', 'ccm', 'ocb', 'xts', 'wrap', 'poly1305',
]);

const JWA_FAMILY_BY_PREFIX = { hs: 'HMAC', rs: 'RSA', es: 'ECDSA', ps: 'RSA-PSS' };

function parseAlgorithmIdentifier(raw) {
  if (raw == null) return null;
  const trimmed = String(raw).trim();
  if (!trimmed) return null;

  // WebCrypto-style algorithm object literal source text, e.g.
  // "{ name: 'AES-GCM', length: 256 }" or "{ name: 'RSA-OAEP', hash: 'SHA-256' }"
  const nameMatch = trimmed.match(/name\s*:\s*['"]([\w.-]+)['"]/i);
  if (nameMatch) {
    const lengthMatch = trimmed.match(/length\s*:\s*(\d+)/i);
    const hashMatch = trimmed.match(/hash\s*:\s*['"]?([\w-]+)['"]?/i);
    return {
      family: nameMatch[1].toUpperCase(),
      mode: null,
      keySize: lengthMatch ? lengthMatch[1] : hashMatch ? hashMatch[1].toUpperCase() : null,
    };
  }

  const lower = trimmed.replace(/^['"]|['"]$/g, '').toLowerCase();

  // JWA alg codes: HS256/RS384/ES512/PS256, plus EdDSA and explicit "none"
  const jwaMatch = lower.match(/^(hs|rs|es|ps)(256|384|512)$/);
  if (jwaMatch) {
    return { family: JWA_FAMILY_BY_PREFIX[jwaMatch[1]], mode: `SHA-${jwaMatch[2]}`, keySize: null };
  }
  if (lower === 'eddsa') return { family: 'EdDSA', mode: null, keySize: null };
  if (lower === 'none') return { family: 'none', mode: null, keySize: null, insecure: true };

  // OpenSSL-style cipher strings: aes-256-gcm, des-ede3-cbc, chacha20-poly1305
  if (lower.includes('-')) {
    const tokens = lower.split('-');
    let keySize = null;
    let mode = null;
    const famTokens = [];
    for (const t of tokens) {
      if (/^\d{2,3}$/.test(t)) { keySize = t; continue; }
      if (CIPHER_MODE_TOKENS.has(t)) { mode = t.toUpperCase(); continue; }
      famTokens.push(t);
    }
    if (famTokens.length) {
      return { family: famTokens.join('-').toUpperCase(), mode, keySize };
    }
  }

  // Bare hash names: sha256, sha512, md5, ripemd160
  const shaMatch = lower.match(/^sha(\d{3})$/);
  if (shaMatch) return { family: `SHA-${shaMatch[1]}`, mode: null, keySize: null };
  if (lower === 'md5') return { family: 'MD5', mode: null, keySize: null };
  if (lower === 'ripemd160') return { family: 'RIPEMD-160', mode: null, keySize: null };

  return { family: trimmed.toUpperCase(), mode: null, keySize: null };
}

function extractLiteralValue(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral' || node.type === 'NumericLiteral' || node.type === 'BooleanLiteral') {
    return node.value;
  }
  if (node.type === 'Literal') return node.value;
  if (node.type === 'TemplateLiteral' && node.quasis && node.quasis.length === 1) {
    return node.quasis[0].value.raw;
  }
  return null;
}

function scanAstFile(filePath, code) {
  const findings = [];
  const lines = code.split('\n');

  function addFinding(opts, lineNum, detail) {
    const assetType = opts.assetType || AssetType.ALGORITHM;
    const isMaterial = assetType === AssetType.RELATED_CRYPTO_MATERIAL;
    const isCert = assetType === AssetType.CERTIFICATE;
    const sourceContext = opts.sourceContext || 'live';

    const f = new CryptoFinding({
      assetType,
      name: opts.name || opts.algorithmFamily,
      algorithmFamily: opts.algorithmFamily,
      primitive: (isMaterial || isCert) ? null : (opts.primitive || null),
      mode: (isMaterial || isCert) ? null : (opts.mode || null),
      parameterSet: opts.parameterSet || null,
      materialType: isMaterial ? (opts.materialType || MaterialType.SECRET_KEY) : null,
      filePath,
      line: lineNum,
      sourceContext,
    });

    const rawConf = opts.rawConfidence ?? 0.95;
    f.addEvidence(new Evidence({
      source: 'ast',
      evidenceClass: EvidenceClass.DIRECT,
      detail,
      rawConfidence: rawConf,
      filePath,
      line: lineNum,
    }));
    findings.push(f);
  }

  const parser = getParser();
  const traverse = getTraverse();
  if (!parser || !traverse) {
    return scanRegexFallback(filePath, lines);
  }

  let ast;
  try {
    ast = parser.parse(code, {
      sourceType: 'unambiguous',
      plugins: [
        'jsx',
        'typescript',
        'decorators-legacy',
        'classProperties',
        'dynamicImport',
        'exportDefaultFrom',
        'exportNamespaceFrom',
        'nullishCoalescingOperator',
        'optionalChaining',
      ],
    });
  } catch (err) {
    // Fallback to regex scanner if parser fails
    return scanRegexFallback(filePath, lines);
  }

  // 1. Traverse AST CallExpressions & collect aliases
  const cryptoJsAliases = new Set(['cryptojs', 'crypto_js']);
  const jwtAliases = new Set(['jwt', 'jsonwebtoken', 'jose']);

  try {
    traverse(ast, {
      VariableDeclarator(p) {
        const id = p.node.id;
        const init = p.node.init;
        if (id && id.type === 'Identifier' && init) {
          if (init.type === 'Identifier') {
            if (/^(cryptojs|crypto_js)$/i.test(init.name)) cryptoJsAliases.add(id.name.toLowerCase());
            if (/^(jwt|jsonwebtoken|jose)$/i.test(init.name)) jwtAliases.add(id.name.toLowerCase());
          } else if (init.type === 'CallExpression' && init.callee && init.callee.name === 'require' && init.arguments[0]) {
            const reqVal = extractLiteralValue(init.arguments[0]);
            if (reqVal === 'crypto-js') cryptoJsAliases.add(id.name.toLowerCase());
            if (reqVal === 'jsonwebtoken' || reqVal === 'jose') jwtAliases.add(id.name.toLowerCase());
          }
        }
      },
      CallExpression(p) {
        const node = p.node;
        const line = node.loc ? node.loc.start.line : 1;
        const callee = node.callee;

        let objName = null;
        let propName = null;

        if (callee.type === 'MemberExpression') {
          if (callee.object.type === 'Identifier') {
            objName = callee.object.name;
          } else if (callee.object.type === 'MemberExpression') {
            const getFullName = (m) => {
              if (!m) return '';
              if (m.type === 'Identifier') return m.name;
              if (m.type === 'MemberExpression') {
                const o = getFullName(m.object);
                const pr = m.property ? m.property.name : '';
                return o ? `${o}.${pr}` : pr;
              }
              return '';
            };
            objName = getFullName(callee.object);
          }
          if (callee.property.type === 'Identifier') {
            propName = callee.property.name;
          }
        } else if (callee.type === 'Identifier') {
          propName = callee.name;
        }

        const objLower = (objName || '').toLowerCase();
        const objRoot = (objName || '').split('.')[0].toLowerCase();

        // 1. bcrypt / bcrypt-nodejs / bcryptjs
        if ((objLower === 'bcrypt' || objLower === 'bcryptjs' || objLower === 'bcrypt-nodejs' || objLower.includes('bcrypt')) &&
            /^(hash|hashSync|compare|compareSync|genSalt|genSaltSync)$/.test(propName)) {
          const isSalt = /genSalt/.test(propName);
          const isCompare = /compare/.test(propName);
          const roundsArg = extractLiteralValue(node.arguments[0]);

          if (isSalt) {
            addFinding({
              assetType: AssetType.RELATED_CRYPTO_MATERIAL,
              name: 'bcrypt-salt',
              algorithmFamily: 'bcrypt',
              primitive: null,
              materialType: MaterialType.SALT,
              parameterSet: roundsArg ? `${roundsArg} rounds` : null,
              rawConfidence: roundsArg ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `${objName}.${propName}() [salt generation]`);
          } else if (isCompare) {
            addFinding({
              assetType: AssetType.ALGORITHM,
              name: 'bcrypt',
              algorithmFamily: 'bcrypt',
              primitive: null,
              materialType: null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `${objName}.${propName}() [password verify]`);
          } else {
            addFinding({
              assetType: AssetType.ALGORITHM,
              name: 'bcrypt',
              algorithmFamily: 'bcrypt',
              primitive: Primitive.KDF,
              materialType: null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `${objName}.${propName}() [password hash]`);
          }
        }

        // 2. Node.js built-in crypto
        if ((objLower === 'crypto' || objLower === 'node:crypto' || objLower.endsWith('crypto')) && propName) {
          if (propName === 'createHash') {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: (algArg || 'SHA-256').toUpperCase() };
            addFinding({
              name: parsed.family || 'HASH',
              algorithmFamily: parsed.family || 'HASH',
              primitive: Primitive.HASH,
              rawConfidence: isLiteral ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.createHash(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (propName === 'createHmac') {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'HMAC', mode: algArg ? algArg.toUpperCase() : null };
            addFinding({
              name: 'HMAC',
              algorithmFamily: 'HMAC',
              primitive: Primitive.MAC,
              mode: parsed.mode || (algArg ? algArg.toUpperCase() : null),
              rawConfidence: isLiteral ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.createHmac(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (/^createCipher(iv)?$/.test(propName)) {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'AES', mode: 'CBC' };
            const isStream = parsed.family === 'RC4' || parsed.family === 'CHACHA20';
            addFinding({
              name: parsed.family || 'AES',
              algorithmFamily: parsed.family || 'AES',
              primitive: isStream ? Primitive.STREAM_CIPHER : Primitive.BLOCK_CIPHER,
              mode: parsed.mode || null,
              parameterSet: parsed.keySize || null,
              rawConfidence: isLiteral ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.${propName}(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (/^createDecipher(iv)?$/.test(propName)) {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'AES', mode: 'CBC' };
            const isStream = parsed.family === 'RC4' || parsed.family === 'CHACHA20';
            addFinding({
              name: parsed.family || 'AES',
              algorithmFamily: parsed.family || 'AES',
              primitive: isStream ? Primitive.STREAM_CIPHER : Primitive.BLOCK_CIPHER,
              mode: parsed.mode || null,
              parameterSet: parsed.keySize || null,
              rawConfidence: isLiteral ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.${propName}(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (/^createSign$/.test(propName)) {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'RSA', mode: algArg ? algArg.toUpperCase() : null };
            addFinding({
              name: parsed.family || 'RSA',
              algorithmFamily: parsed.family || 'RSA',
              primitive: Primitive.SIGNATURE,
              mode: parsed.mode || (algArg ? algArg.toUpperCase() : null),
              rawConfidence: isLiteral ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.createSign(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (/^createVerify$/.test(propName)) {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'RSA', mode: algArg ? algArg.toUpperCase() : null };
            addFinding({
              name: parsed.family || 'RSA',
              algorithmFamily: parsed.family || 'RSA',
              primitive: Primitive.SIGNATURE,
              mode: parsed.mode || (algArg ? algArg.toUpperCase() : null),
              rawConfidence: isLiteral ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.createVerify(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (/^pbkdf2(Sync)?$/.test(propName)) {
            const iterArg = extractLiteralValue(node.arguments[2]);
            const keyLenArg = extractLiteralValue(node.arguments[3]);
            const digestArg = extractLiteralValue(node.arguments[4]) || extractLiteralValue(node.arguments[3]);
            const hasExplicitArgs = iterArg != null || digestArg != null;
            const params = [
              iterArg ? `${iterArg} iters` : null,
              keyLenArg ? `${keyLenArg} bytes` : null,
              digestArg ? String(digestArg) : null,
            ].filter(Boolean).join(', ');
            addFinding({
              name: 'PBKDF2',
              algorithmFamily: 'PBKDF2',
              primitive: Primitive.KDF,
              parameterSet: params || null,
              rawConfidence: hasExplicitArgs ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `crypto.${propName}()`);
          } else if (/^scrypt(Sync)?$/.test(propName)) {
            addFinding({
              name: 'scrypt',
              algorithmFamily: 'scrypt',
              primitive: Primitive.KDF,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.${propName}()`);
          } else if (/^randomBytes(Sync)?$/.test(propName)) {
            const bytesArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: 'CSPRNG',
              algorithmFamily: 'CSPRNG',
              primitive: Primitive.DRBG,
              parameterSet: bytesArg ? `${bytesArg * 8} bits` : null,
              rawConfidence: bytesArg ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `crypto.randomBytes(${bytesArg || ''})`);
          } else if (/^generateKeyPair(Sync)?$/.test(propName)) {
            const typeArg = extractLiteralValue(node.arguments[0]);
            const family = typeArg ? typeArg.toUpperCase() : 'RSA';
            addFinding({
              assetType: AssetType.RELATED_CRYPTO_MATERIAL,
              materialType: MaterialType.PRIVATE_KEY,
              name: family,
              algorithmFamily: family,
              primitive: null,
              rawConfidence: typeArg ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.${propName}(${typeArg ? '"' + typeArg + '"' : ''})`);
          } else if (/^(createDiffieHellman|createECDH)$/.test(propName)) {
            const curveArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: propName === 'createECDH' ? 'ECDH' : 'DH',
              algorithmFamily: propName === 'createECDH' ? 'ECDH' : 'DH',
              primitive: Primitive.KEY_AGREE,
              parameterSet: curveArg ? String(curveArg) : null,
              rawConfidence: curveArg ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.${propName}(${curveArg ? '"' + curveArg + '"' : ''})`);
          }
        }

        // 3. jsonwebtoken / jwt / jose
        if ((jwtAliases.has(objRoot) || objLower.includes('jwt') || objLower.includes('jose')) &&
            /^(sign|verify|signJWT|jwtVerify|compactSign|compactEncrypt)$/i.test(propName)) {
          let algs = [];
          let isWeak = false;

          for (const arg of node.arguments) {
            if (arg && arg.type === 'ObjectExpression') {
              for (const pr of arg.properties) {
                if (pr.key) {
                  const kName = pr.key.name || pr.key.value;
                  if (kName === 'algorithm') {
                    const v = extractLiteralValue(pr.value);
                    if (v) algs.push(v);
                  } else if (kName === 'algorithms' && pr.value && pr.value.type === 'ArrayExpression') {
                    for (const elem of pr.value.elements) {
                      const v = extractLiteralValue(elem);
                      if (v) algs.push(v);
                    }
                  }
                }
              }
            }
          }

          const hasExplicitAlg = algs.length > 0;
          if (!algs.length) algs = ['HS256'];

          const secretArg = extractLiteralValue(node.arguments[1]);
          if (secretArg && (typeof secretArg === 'string') && (secretArg === 'secret' || secretArg.length < 16)) {
            isWeak = true;
          }

          for (const alg of algs) {
            const isNone = String(alg).toLowerCase() === 'none';
            const parsed = parseAlgorithmIdentifier(alg) || { family: isNone ? 'none' : 'HMAC', mode: isNone ? null : 'SHA-256' };
            const flagWeak = isWeak || isNone;
            addFinding({
              assetType: AssetType.ALGORITHM,
              name: isNone ? 'none' : (parsed.family || 'JWT'),
              algorithmFamily: isNone ? 'none' : (parsed.family || 'JWT'),
              primitive: Primitive.SIGNATURE,
              mode: parsed.mode || null,
              parameterSet: flagWeak ? (isNone ? 'none-algorithm-insecure' : 'weak-secret') : alg,
              rawConfidence: hasExplicitAlg ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `jwt.${propName}(${alg})` + (flagWeak ? ` [flagged ${isNone ? 'insecure none algorithm' : 'weak secret'}]` : ''));
          }
        }

        // 4. CryptoJS
        if (cryptoJsAliases.has(objRoot) || objLower.includes('cryptojs') || objLower.includes('crypto_js')) {
          const parts = (objName || '').split('.');
          const lastPart = parts[parts.length - 1] || '';

          if (propName === 'encrypt' || propName === 'decrypt' || propName === 'createEncryptor' || propName === 'createDecryptor') {
            const cipherType = lastPart !== 'encrypt' && lastPart !== 'decrypt' ? lastPart : (parts.length > 1 ? parts[parts.length - 2] : 'AES');
            const isTripleDes = /tripledes/i.test(cipherType);
            const isDes = /des/i.test(cipherType) && !isTripleDes;
            const isRc4 = /rc4/i.test(cipherType);
            const isRabbit = /rabbit/i.test(cipherType);
            const isStream = isRc4 || isRabbit;

            let family = 'AES';
            let primitive = Primitive.BLOCK_CIPHER;
            if (isTripleDes) { family = '3DES'; }
            else if (isDes) { family = 'DES'; }
            else if (isRc4) { family = 'RC4'; primitive = Primitive.STREAM_CIPHER; }
            else if (isRabbit) { family = 'Rabbit'; primitive = Primitive.STREAM_CIPHER; }

            addFinding({
              name: family,
              algorithmFamily: family,
              primitive,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `CryptoJS.${cipherType}.${propName}()`);
          } else if (/^(SHA256|SHA512|SHA384|SHA224|SHA1|SHA3|MD5|RIPEMD160)$/i.test(propName) ||
                     /^(SHA256|SHA512|SHA384|SHA224|SHA1|SHA3|MD5|RIPEMD160)$/i.test(lastPart)) {
            const rawHash = /^(SHA256|SHA512|SHA384|SHA224|SHA1|SHA3|MD5|RIPEMD160)$/i.test(propName) ? propName : lastPart;
            const parsed = parseAlgorithmIdentifier(rawHash) || { family: rawHash.toUpperCase() };
            addFinding({
              name: parsed.family || rawHash.toUpperCase(),
              algorithmFamily: parsed.family || rawHash.toUpperCase(),
              primitive: Primitive.HASH,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `CryptoJS.${rawHash}()`);
          } else if (/^Hmac/i.test(propName) || /^Hmac/i.test(lastPart)) {
            const rawHmac = /^Hmac/i.test(propName) ? propName : lastPart;
            const hashPart = rawHmac.replace(/^Hmac/i, '').toUpperCase();
            addFinding({
              name: 'HMAC',
              algorithmFamily: 'HMAC',
              primitive: Primitive.MAC,
              mode: hashPart || 'SHA-256',
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `CryptoJS.${rawHmac}()`);
          } else if (/^(PBKDF2|EvpKDF)$/i.test(propName) || /^(PBKDF2|EvpKDF)$/i.test(lastPart)) {
            const rawKdf = /^(PBKDF2|EvpKDF)$/i.test(propName) ? propName : lastPart;
            addFinding({
              name: rawKdf.toUpperCase(),
              algorithmFamily: rawKdf.toUpperCase(),
              primitive: Primitive.KDF,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `CryptoJS.${rawKdf}()`);
          }
        }
      },
    });
  } catch (err) {
    // ignore AST traversal errors
  }

  // 2. Scan AST comments for tutorial / commented-out crypto code
  for (const comment of ast.comments || []) {
    const cText = comment.value || '';
    const cLine = comment.loc ? comment.loc.start.line : 1;
    scanCommentLines(cText, cLine, addFinding);
  }

  return findings;
}

function scanCommentLines(text, baseLine, addFinding) {
  const lines = text.split('\n');
  lines.forEach((l, idx) => {
    const curLine = baseLine + idx;
    if (/bcrypt\.genSalt/.test(l)) {
      addFinding({
        assetType: AssetType.RELATED_CRYPTO_MATERIAL,
        name: 'bcrypt-salt',
        algorithmFamily: 'bcrypt',
        primitive: null,
        materialType: MaterialType.SALT,
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'bcrypt.genSalt (code comment)');
    } else if (/bcrypt\.compare/.test(l)) {
      addFinding({
        assetType: AssetType.ALGORITHM,
        name: 'bcrypt',
        algorithmFamily: 'bcrypt',
        primitive: null,
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'bcrypt.compare (code comment)');
    } else if (/bcrypt\.hash/.test(l)) {
      addFinding({
        assetType: AssetType.ALGORITHM,
        name: 'bcrypt',
        algorithmFamily: 'bcrypt',
        primitive: Primitive.KDF,
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'bcrypt.hash (code comment)');
    }
    if (/crypto\.pbkdf2(Sync)?\s*\(/.test(l)) {
      addFinding({
        name: 'PBKDF2',
        algorithmFamily: 'PBKDF2',
        primitive: Primitive.KDF,
        parameterSet: 'sha512',
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'crypto.pbkdf2Sync (code comment)');
    }
    if (/crypto\.createCipher(iv)?\s*\(/.test(l)) {
      addFinding({
        name: 'AES',
        algorithmFamily: 'AES',
        primitive: Primitive.BLOCK_CIPHER,
        mode: 'CBC',
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'crypto.createCipheriv (code comment)');
    }
    if (/crypto\.createDecipher(iv)?\s*\(/.test(l)) {
      addFinding({
        name: 'AES',
        algorithmFamily: 'AES',
        primitive: Primitive.BLOCK_CIPHER,
        mode: 'CBC',
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'crypto.createDecipheriv (code comment)');
    }
    if (/crypto\.randomBytes(Sync)?\s*\(/.test(l)) {
      addFinding({
        name: 'CSPRNG',
        algorithmFamily: 'CSPRNG',
        primitive: Primitive.DRBG,
        parameterSet: '128 bits',
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'crypto.randomBytes (code comment)');
    }
    if (/jwt\.(sign|verify)/.test(l)) {
      addFinding({
        name: 'JWT',
        algorithmFamily: 'JWT',
        primitive: Primitive.SIGNATURE,
        rawConfidence: 0.65,
        sourceContext: 'comment',
      }, curLine, 'jwt.sign/verify (code comment)');
    }
  });
}

function scanRegexFallback(filePath, lines) {
  const findings = [];
  lines.forEach((l, idx) => {
    const lineNum = idx + 1;
    if (/bcrypt\.(hash|hashSync|compare|compareSync|genSalt|genSaltSync)/.test(l)) {
      const isSalt = /genSalt/.test(l);
      const isCompare = /compare/.test(l);
      const f = new CryptoFinding({
        assetType: isSalt ? AssetType.RELATED_CRYPTO_MATERIAL : AssetType.ALGORITHM,
        name: isSalt ? 'bcrypt-salt' : 'bcrypt',
        algorithmFamily: 'bcrypt',
        primitive: isSalt ? null : (isCompare ? null : Primitive.KDF),
        materialType: isSalt ? MaterialType.SALT : null,
        filePath,
        line: lineNum,
      });
      f.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: `bcrypt call (regex fallback: ${isSalt ? 'salt' : (isCompare ? 'compare' : 'hash')})`,
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }
    if (/crypto\.pbkdf2/.test(l)) {
      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: 'PBKDF2',
        algorithmFamily: 'PBKDF2',
        primitive: Primitive.KDF,
        filePath,
        line: lineNum,
      });
      f.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: 'crypto.pbkdf2 call (regex fallback)',
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }
    if (/crypto\.createCipher/.test(l)) {
      const match = l.match(/createCipher(?:iv)?\s*\(\s*['"]([^'"]+)['"]/);
      const parsed = match ? parseAlgorithmIdentifier(match[1]) : { family: 'AES', mode: 'CBC' };
      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: parsed.family || 'AES',
        algorithmFamily: parsed.family || 'AES',
        primitive: Primitive.BLOCK_CIPHER,
        mode: parsed.mode || null,
        parameterSet: parsed.keySize || null,
        filePath,
        line: lineNum,
      });
      f.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: match ? `crypto.createCipheriv("${match[1]}")` : 'crypto.createCipher call (regex fallback)',
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }
    if (/jwt\.(sign|verify)/.test(l)) {
      const algMatch = l.match(/algorithm\s*:\s*['"]([^'"]+)['"]/i);
      const alg = algMatch ? algMatch[1] : 'HS256';
      const parsed = parseAlgorithmIdentifier(alg) || { family: 'HMAC', mode: 'SHA-256' };
      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: parsed.family || 'JWT',
        algorithmFamily: parsed.family || 'JWT',
        primitive: Primitive.SIGNATURE,
        mode: parsed.mode || null,
        parameterSet: alg,
        filePath,
        line: lineNum,
        sourceContext: 'live',
      });
      f.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: `jwt call (${alg}) (regex fallback)`,
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }
    if (/CryptoJS/i.test(l)) {
      if (/CryptoJS\.(AES|DES|TripleDES|RC4|Rabbit)\.(encrypt|decrypt)/i.test(l)) {
        const m = l.match(/CryptoJS\.(AES|DES|TripleDES|RC4|Rabbit)/i);
        const cipherType = m ? m[1] : 'AES';
        const isTripleDes = /tripledes/i.test(cipherType);
        const isDes = /des/i.test(cipherType) && !isTripleDes;
        const isRc4 = /rc4/i.test(cipherType);
        const isRabbit = /rabbit/i.test(cipherType);
        const isStream = isRc4 || isRabbit;

        let family = 'AES';
        let primitive = Primitive.BLOCK_CIPHER;
        if (isTripleDes) { family = '3DES'; }
        else if (isDes) { family = 'DES'; }
        else if (isRc4) { family = 'RC4'; primitive = Primitive.STREAM_CIPHER; }
        else if (isRabbit) { family = 'Rabbit'; primitive = Primitive.STREAM_CIPHER; }

        const f = new CryptoFinding({
          assetType: AssetType.ALGORITHM,
          name: family,
          algorithmFamily: family,
          primitive,
          filePath,
          line: lineNum,
          sourceContext: 'live',
        });
        f.addEvidence(new Evidence({
          source: 'ast',
          evidenceClass: EvidenceClass.DIRECT,
          detail: `CryptoJS.${cipherType} call (regex fallback)`,
          rawConfidence: 0.55,
          filePath,
          line: lineNum,
        }));
        findings.push(f);
      }
      if (/CryptoJS\.(SHA256|SHA512|SHA384|SHA224|SHA1|SHA3|MD5|RIPEMD160)\s*\(/i.test(l)) {
        const m = l.match(/CryptoJS\.(SHA256|SHA512|SHA384|SHA224|SHA1|SHA3|MD5|RIPEMD160)/i);
        const hashName = m ? m[1].toUpperCase() : 'SHA256';
        const parsed = parseAlgorithmIdentifier(hashName) || { family: hashName };
        const f = new CryptoFinding({
          assetType: AssetType.ALGORITHM,
          name: parsed.family || hashName,
          algorithmFamily: parsed.family || hashName,
          primitive: Primitive.HASH,
          filePath,
          line: lineNum,
          sourceContext: 'live',
        });
        f.addEvidence(new Evidence({
          source: 'ast',
          evidenceClass: EvidenceClass.DIRECT,
          detail: `CryptoJS.${hashName} call (regex fallback)`,
          rawConfidence: 0.55,
          filePath,
          line: lineNum,
        }));
        findings.push(f);
      }
      if (/CryptoJS\.Hmac/i.test(l)) {
        const m = l.match(/CryptoJS\.Hmac([A-Za-z0-9]+)/i);
        const hashPart = m ? m[1].toUpperCase() : 'SHA256';
        const f = new CryptoFinding({
          assetType: AssetType.ALGORITHM,
          name: 'HMAC',
          algorithmFamily: 'HMAC',
          primitive: Primitive.MAC,
          mode: hashPart,
          filePath,
          line: lineNum,
          sourceContext: 'live',
        });
        f.addEvidence(new Evidence({
          source: 'ast',
          evidenceClass: EvidenceClass.DIRECT,
          detail: `CryptoJS.Hmac call (regex fallback)`,
          rawConfidence: 0.55,
          filePath,
          line: lineNum,
        }));
        findings.push(f);
      }
      if (/CryptoJS\.(PBKDF2|EvpKDF)\s*\(/i.test(l)) {
        const m = l.match(/CryptoJS\.(PBKDF2|EvpKDF)/i);
        const kdfName = m ? m[1].toUpperCase() : 'PBKDF2';
        const f = new CryptoFinding({
          assetType: AssetType.ALGORITHM,
          name: kdfName,
          algorithmFamily: kdfName,
          primitive: Primitive.KDF,
          filePath,
          line: lineNum,
          sourceContext: 'live',
        });
        f.addEvidence(new Evidence({
          source: 'ast',
          evidenceClass: EvidenceClass.DIRECT,
          detail: `CryptoJS.${kdfName} call (regex fallback)`,
          rawConfidence: 0.55,
          filePath,
          line: lineNum,
        }));
        findings.push(f);
      }
    }
  });
  return findings;
}

function isCryptoPackageTarget(pkgName) {
  const lower = (pkgName || '').toLowerCase();
  const unscoped = lower.includes('/') ? lower.split('/')[1] : lower;
  return /^(bcrypt.*|jwt.*|jsonwebtoken|jose|jwa|jws|node-jose|crypto-js|node-forge|forge|tweetnacl.*|elliptic|libsodium.*|sodium.*|pbkdf2|scrypt.*|argon2|hash\.js|sha\.js|aes.*|des.*|rc4.*)$/i.test(unscoped);
}

function walkPackageDir(dir, results = [], depth = 0) {
  if (depth > 4 || !fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'test' && entry.name !== 'tests') {
        walkPackageDir(full, results, depth + 1);
      }
    } else if (/\.(js|mjs|cjs)$/.test(entry.name)) {
      results.push(full);
    }
  }
}

function walkNodeModules(nodeModulesDir, results = []) {
  if (!fs.existsSync(nodeModulesDir)) return;
  for (const entry of fs.readdirSync(nodeModulesDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const pkgName = entry.name;
    const full = path.join(nodeModulesDir, pkgName);
    if (pkgName.startsWith('@')) {
      for (const sub of fs.readdirSync(full, { withFileTypes: true })) {
        if (!sub.isDirectory()) continue;
        const scopedName = `${pkgName}/${sub.name}`;
        if (isCryptoPackageTarget(scopedName)) {
          walkPackageDir(path.join(full, sub.name), results);
        }
      }
    } else if (isCryptoPackageTarget(pkgName)) {
      walkPackageDir(full, results);
    }
  }
}

function walkDirectory(dir, results = [], isRoot = true) {
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' && isRoot) {
        walkNodeModules(full, results);
      } else if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'dist' && entry.name !== 'build') {
        walkDirectory(full, results, false);
      }
    } else if (/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(entry.name)) {
      results.push(full);
    }
  }
  return results;
}

function scan(targetDir) {
  const files = walkDirectory(targetDir);
  const allFindings = [];

  for (const file of files) {
    try {
      const code = fs.readFileSync(file, 'utf-8');
      const relPath = path.relative(targetDir, file);
      const findings = scanAstFile(relPath, code);
      allFindings.push(...findings);
    } catch (err) {
      console.warn(`[astExtract] Failed to scan ${file}: ${err.message}`);
    }
  }

  return allFindings;
}

module.exports = {
  scan,
  parseAlgorithmIdentifier,
};

if (require.main === module) {
  const findings = scan(process.argv[2] || '.');
  findings.forEach((f) => console.log(JSON.stringify(f, null, 2)));
}
