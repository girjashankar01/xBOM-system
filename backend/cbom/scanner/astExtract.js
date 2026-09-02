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
    const babelCore = require('@babel/core');
    if (babelCore && typeof babelCore.parseSync === 'function') {
      return {
        parse: (code, opts) => babelCore.parseSync(code, {
          configFile: false,
          babelrc: false,
          ast: true,
          sourceType: opts?.sourceType || 'unambiguous',
          plugins: [
            '@babel/plugin-syntax-jsx',
            '@babel/plugin-syntax-typescript',
          ],
        }),
      };
    }
  } catch {}

  try {
    return require('@babel/parser');
  } catch {
    try {
      const req = createRequire(__filename);
      return req('@babel/parser');
    } catch {
      return null;
    }
  }
}

function getTraverse() {
  try {
    const babelCore = require('@babel/core');
    if (babelCore && typeof babelCore.traverse === 'function') {
      return babelCore.traverse;
    }
  } catch {}

  try {
    const t = require('@babel/traverse');
    return t.default?.default || t.default || t;
  } catch {
    try {
      const req = createRequire(__filename);
      const t = req('@babel/traverse');
      return t.default?.default || t.default || t;
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

const COSE_ALGORITHMS = {
  [-7]: { name: 'ECDSA', algorithmFamily: 'ECDSA', primitive: Primitive.SIGNATURE, parameterSet: 'P-256 / ES256', label: 'ES256 (-7)' },
  [-257]: { name: 'RSA', algorithmFamily: 'RSA', primitive: Primitive.SIGNATURE, parameterSet: 'RS256', label: 'RS256 (-257)' },
  [-8]: { name: 'EdDSA', algorithmFamily: 'EdDSA', primitive: Primitive.SIGNATURE, parameterSet: 'EdDSA', label: 'EdDSA (-8)' },
  [-37]: { name: 'RSA-PSS', algorithmFamily: 'RSA-PSS', primitive: Primitive.SIGNATURE, parameterSet: 'PS256', label: 'PS256 (-37)' },
  [-35]: { name: 'ECDSA', algorithmFamily: 'ECDSA', primitive: Primitive.SIGNATURE, parameterSet: 'P-384 / ES384', label: 'ES384 (-35)' },
  [-36]: { name: 'ECDSA', algorithmFamily: 'ECDSA', primitive: Primitive.SIGNATURE, parameterSet: 'P-521 / ES512', label: 'ES512 (-36)' },
  [-47]: { name: 'ECDSA', algorithmFamily: 'ECDSA', primitive: Primitive.SIGNATURE, parameterSet: 'secp256k1 / ES256K', label: 'ES256K (-47)' },
  [-258]: { name: 'RSA', algorithmFamily: 'RSA', primitive: Primitive.SIGNATURE, parameterSet: 'RS384', label: 'RS384 (-258)' },
  [-259]: { name: 'RSA', algorithmFamily: 'RSA', primitive: Primitive.SIGNATURE, parameterSet: 'RS512', label: 'RS512 (-259)' },
};

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

function extractNumericValue(node) {
  if (!node) return null;
  if (node.type === 'NumericLiteral') return node.value;
  if (node.type === 'Literal' && typeof node.value === 'number') return node.value;
  if (node.type === 'UnaryExpression' && node.operator === '-' && node.argument) {
    const inner = extractNumericValue(node.argument);
    return inner != null ? -inner : null;
  }
  return null;
}

function extractWebCryptoAlgorithm(node) {
  if (!node) return null;
  if (node.type === 'StringLiteral' || (node.type === 'Literal' && typeof node.value === 'string')) {
    const val = node.value;
    const parsed = parseAlgorithmIdentifier(val);
    return {
      name: parsed?.family || val.toUpperCase(),
      family: parsed?.family || val.toUpperCase(),
      mode: parsed?.mode || null,
      parameterSet: parsed?.keySize || null,
      rawDetail: val,
    };
  }
  if (node.type === 'ObjectExpression') {
    let nameVal = null;
    let namedCurveVal = null;
    let hashVal = null;
    let lengthVal = null;
    let modulusLengthVal = null;

    for (const prop of node.properties) {
      if (!prop.key) continue;
      const k = prop.key.name || prop.key.value;
      if (k === 'name') {
        nameVal = extractLiteralValue(prop.value);
      } else if (k === 'namedCurve') {
        namedCurveVal = extractLiteralValue(prop.value);
      } else if (k === 'hash') {
        if (prop.value && prop.value.type === 'ObjectExpression') {
          for (const subProp of prop.value.properties) {
            const subK = subProp.key?.name || subProp.key?.value;
            if (subK === 'name') hashVal = extractLiteralValue(subProp.value);
          }
        } else {
          hashVal = extractLiteralValue(prop.value);
        }
      } else if (k === 'length') {
        lengthVal = extractLiteralValue(prop.value);
      } else if (k === 'modulusLength') {
        modulusLengthVal = extractLiteralValue(prop.value);
      }
    }

    const rawName = nameVal || 'UNKNOWN';
    let family = rawName.toUpperCase();
    if (/^RSASSA-PKCS1/i.test(rawName) || /^RSA-OAEP/i.test(rawName)) family = 'RSA';
    else if (/^RSA-PSS/i.test(rawName)) family = 'RSA-PSS';
    else if (/^ECDSA/i.test(rawName)) family = 'ECDSA';
    else if (/^ECDH/i.test(rawName)) family = 'ECDH';
    else if (/^AES/i.test(rawName)) family = 'AES';
    else if (/^HMAC/i.test(rawName)) family = 'HMAC';
    else if (/^PBKDF2/i.test(rawName)) family = 'PBKDF2';
    else if (/^HKDF/i.test(rawName)) family = 'HKDF';
    else if (/^ED25519/i.test(rawName)) family = 'EdDSA';

    const paramParts = [
      namedCurveVal,
      hashVal ? (typeof hashVal === 'string' ? hashVal.toUpperCase() : null) : null,
      lengthVal ? `${lengthVal} bits` : null,
      modulusLengthVal ? `${modulusLengthVal} bits` : null,
    ].filter(Boolean);

    return {
      name: family,
      family,
      namedCurve: namedCurveVal,
      hash: hashVal,
      parameterSet: paramParts.length ? paramParts.join(' / ') : null,
      rawDetail: JSON.stringify({ name: nameVal, namedCurve: namedCurveVal, hash: hashVal, length: lengthVal || modulusLengthVal || undefined }),
    };
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
    return scanRegexFallback(filePath, lines);
  }

  // 1. Traverse AST CallExpressions & collect aliases
  const cryptoAliases = new Set(['crypto', 'node:crypto']);
  const subtleAliases = new Set(['subtle']);
  const destructuredCryptoFns = new Map();
  const cryptoJsAliases = new Set(['cryptojs', 'crypto_js']);
  const jwtAliases = new Set(['jwt', 'jsonwebtoken', 'jose']);
  const seenCoseLocations = new Set();

  try {
    traverse(ast, {
      ImportDeclaration(p) {
        const sourceVal = p.node.source ? p.node.source.value : '';
        if (sourceVal === 'crypto' || sourceVal === 'node:crypto') {
          for (const spec of p.node.specifiers) {
            if (spec.type === 'ImportDefaultSpecifier' || spec.type === 'ImportNamespaceSpecifier') {
              cryptoAliases.add(spec.local.name.toLowerCase());
            } else if (spec.type === 'ImportSpecifier') {
              const importedName = spec.imported ? (spec.imported.name || spec.imported.value) : spec.local.name;
              destructuredCryptoFns.set(spec.local.name.toLowerCase(), importedName);
              if (importedName === 'subtle') subtleAliases.add(spec.local.name.toLowerCase());
            }
          }
        } else if (sourceVal === 'crypto-js') {
          for (const spec of p.node.specifiers) {
            cryptoJsAliases.add(spec.local.name.toLowerCase());
          }
        } else if (sourceVal === 'jsonwebtoken' || sourceVal === 'jose') {
          for (const spec of p.node.specifiers) {
            jwtAliases.add(spec.local.name.toLowerCase());
          }
        }
      },
      VariableDeclarator(p) {
        const id = p.node.id;
        const init = p.node.init;

        if (id && init) {
          if (id.type === 'Identifier') {
            const idLower = id.name.toLowerCase();
            if (init.type === 'Identifier') {
              const initLower = init.name.toLowerCase();
              if (cryptoAliases.has(initLower)) cryptoAliases.add(idLower);
              if (/^(cryptojs|crypto_js)$/i.test(init.name)) cryptoJsAliases.add(idLower);
              if (/^(jwt|jsonwebtoken|jose)$/i.test(init.name)) jwtAliases.add(idLower);
            } else if (init.type === 'MemberExpression') {
              const objName = init.object?.name?.toLowerCase();
              const propName = init.property?.name || init.property?.value;
              if (cryptoAliases.has(objName) && propName === 'subtle') {
                subtleAliases.add(idLower);
              }
            } else if (init.type === 'CallExpression' && init.callee && init.callee.name === 'require' && init.arguments[0]) {
              const reqVal = extractLiteralValue(init.arguments[0]);
              if (reqVal === 'crypto' || reqVal === 'node:crypto') cryptoAliases.add(idLower);
              if (reqVal === 'crypto-js') cryptoJsAliases.add(idLower);
              if (reqVal === 'jsonwebtoken' || reqVal === 'jose') jwtAliases.add(idLower);
            }

            // COSE variable match (e.g. const coseAlg = -7)
            if (/^(alg|algorithm|coseAlg|coseAlgorithm|preferredAlgorithm)$/i.test(id.name)) {
              const numVal = extractNumericValue(init);
              if (numVal !== null && COSE_ALGORITHMS[numVal]) {
                const line = id.loc ? id.loc.start.line : 1;
                const locKey = `${line}:${numVal}`;
                if (!seenCoseLocations.has(locKey)) {
                  seenCoseLocations.add(locKey);
                  const cose = COSE_ALGORITHMS[numVal];
                  addFinding({
                    name: cose.name,
                    algorithmFamily: cose.algorithmFamily,
                    primitive: cose.primitive,
                    parameterSet: cose.parameterSet,
                    rawConfidence: 0.95,
                    sourceContext: 'live',
                  }, line, `COSE algorithm identifier ${cose.label}`);
                }
              }
            }
          } else if (id.type === 'ObjectPattern' && init.type === 'CallExpression' && init.callee && init.callee.name === 'require' && init.arguments[0]) {
            const reqVal = extractLiteralValue(init.arguments[0]);
            if (reqVal === 'crypto' || reqVal === 'node:crypto') {
              for (const prop of id.properties) {
                if (prop.type === 'ObjectProperty' && prop.key && prop.value) {
                  const orig = prop.key.name || prop.key.value;
                  const local = prop.value.name || orig;
                  destructuredCryptoFns.set(local.toLowerCase(), orig);
                  if (orig === 'subtle') subtleAliases.add(local.toLowerCase());
                }
              }
            }
          } else if (id.type === 'ObjectPattern' && init.type === 'Identifier') {
            const initLower = init.name.toLowerCase();
            if (cryptoAliases.has(initLower)) {
              for (const prop of id.properties) {
                if (prop.type === 'ObjectProperty' && prop.key && prop.value) {
                  const orig = prop.key.name || prop.key.value;
                  const local = prop.value.name || orig;
                  destructuredCryptoFns.set(local.toLowerCase(), orig);
                  if (orig === 'subtle') subtleAliases.add(local.toLowerCase());
                }
              }
            }
          }
        }
      },
      ObjectProperty(p) {
        const prop = p.node;
        if (!prop.key) return;
        const kName = prop.key.name || prop.key.value;
        const line = prop.loc ? prop.loc.start.line : 1;

        // 1. Single COSE algorithm property, e.g. { alg: -7 } or { algorithm: -257 }
        if (/^(alg|algorithm|coseAlg|coseAlgorithm)$/i.test(kName)) {
          const numVal = extractNumericValue(prop.value);
          if (numVal !== null && COSE_ALGORITHMS[numVal]) {
            const locKey = `${line}:${numVal}`;
            if (!seenCoseLocations.has(locKey)) {
              seenCoseLocations.add(locKey);
              const cose = COSE_ALGORITHMS[numVal];
              addFinding({
                name: cose.name,
                algorithmFamily: cose.algorithmFamily,
                primitive: cose.primitive,
                parameterSet: cose.parameterSet,
                rawConfidence: 0.95,
                sourceContext: 'live',
              }, line, `COSE algorithm identifier ${cose.label}`);
            }
          }
        }

        // 2. pubKeyCredParams array, e.g. pubKeyCredParams: [{ type: 'public-key', alg: -7 }]
        if (/^(pubKeyCredParams|supportedAlgorithmIDs|authenticatorSelection)$/i.test(kName) && prop.value && prop.value.type === 'ArrayExpression') {
          for (const elem of prop.value.elements) {
            if (!elem) continue;
            let algVal = null;
            let elemLine = elem.loc ? elem.loc.start.line : line;

            if (elem.type === 'ObjectExpression') {
              for (const sub of elem.properties) {
                const subK = sub.key ? (sub.key.name || sub.key.value) : '';
                if (/^(alg|algorithm)$/i.test(subK)) {
                  algVal = extractNumericValue(sub.value);
                  if (sub.loc) elemLine = sub.loc.start.line;
                }
              }
            } else {
              algVal = extractNumericValue(elem);
            }

            if (algVal !== null && COSE_ALGORITHMS[algVal]) {
              const locKey = `${elemLine}:${algVal}`;
              if (!seenCoseLocations.has(locKey)) {
                seenCoseLocations.add(locKey);
                const cose = COSE_ALGORITHMS[algVal];
                addFinding({
                  name: cose.name,
                  algorithmFamily: cose.algorithmFamily,
                  primitive: cose.primitive,
                  parameterSet: cose.parameterSet,
                  rawConfidence: 0.95,
                  sourceContext: 'live',
                }, elemLine, `WebAuthn pubKeyCredParams COSE algorithm ${cose.label}`);
              }
            }
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
                const pr = m.property ? (m.property.name || m.property.value) : '';
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
        const objParts = objLower.split('.');
        const isSubtleCall =
          subtleAliases.has(objLower) ||
          (objParts.length >= 2 && objParts[objParts.length - 1] === 'subtle' && (cryptoAliases.has(objParts[0]) || objParts[0] === 'window'));

        // 1. WebCrypto API (crypto.subtle.*)
        if (isSubtleCall && propName) {
          if (propName === 'verify' || propName === 'sign') {
            const algInfo = extractWebCryptoAlgorithm(node.arguments[0]) || { family: 'ECDSA', parameterSet: 'P-256' };
            const isHmac = algInfo.family === 'HMAC';
            addFinding({
              name: algInfo.family || 'ECDSA',
              algorithmFamily: algInfo.family || 'ECDSA',
              primitive: isHmac ? Primitive.MAC : Primitive.SIGNATURE,
              parameterSet: algInfo.parameterSet || null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.subtle.${propName}(${algInfo.rawDetail || algInfo.family})`);
          } else if (propName === 'digest') {
            const algInfo = extractWebCryptoAlgorithm(node.arguments[0]) || { family: 'SHA-256' };
            addFinding({
              name: algInfo.family || 'SHA-256',
              algorithmFamily: algInfo.family || 'SHA-256',
              primitive: Primitive.HASH,
              parameterSet: algInfo.parameterSet || null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.subtle.digest(${algInfo.rawDetail || algInfo.family})`);
          } else if (propName === 'importKey') {
            const formatArg = extractLiteralValue(node.arguments[0]);
            const algInfo = extractWebCryptoAlgorithm(node.arguments[2]) || { family: 'ECDSA', parameterSet: 'P-256' };
            const isAsymmetric = /^(ECDSA|ECDH|RSA|RSA-PSS|EDDSA)$/i.test(algInfo.family);
            const isPub = formatArg === 'spki';
            const isPriv = formatArg === 'pkcs8';

            addFinding({
              assetType: isAsymmetric ? AssetType.RELATED_CRYPTO_MATERIAL : AssetType.ALGORITHM,
              materialType: isAsymmetric ? (isPriv ? MaterialType.PRIVATE_KEY : MaterialType.PUBLIC_KEY) : null,
              name: algInfo.family || 'ECDSA',
              algorithmFamily: algInfo.family || 'ECDSA',
              primitive: isAsymmetric ? null : Primitive.BLOCK_CIPHER,
              parameterSet: algInfo.parameterSet || null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.subtle.importKey(${formatArg || ''}, ${algInfo.rawDetail || algInfo.family})`);
          } else if (propName === 'generateKey') {
            const algInfo = extractWebCryptoAlgorithm(node.arguments[0]) || { family: 'ECDSA', parameterSet: 'P-256' };
            addFinding({
              name: algInfo.family || 'ECDSA',
              algorithmFamily: algInfo.family || 'ECDSA',
              primitive: Primitive.SIGNATURE,
              parameterSet: algInfo.parameterSet || null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.subtle.generateKey(${algInfo.rawDetail || algInfo.family})`);
          } else if (propName === 'deriveKey' || propName === 'deriveBits') {
            const algInfo = extractWebCryptoAlgorithm(node.arguments[0]) || { family: 'HKDF' };
            const isEcdh = algInfo.family === 'ECDH';
            addFinding({
              name: algInfo.family || 'HKDF',
              algorithmFamily: algInfo.family || 'HKDF',
              primitive: isEcdh ? Primitive.KEY_AGREE : Primitive.KDF,
              parameterSet: algInfo.parameterSet || null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.subtle.${propName}(${algInfo.rawDetail || algInfo.family})`);
          }
          return;
        }

        // Resolve Node crypto direct calls vs destructured calls
        let isNodeCrypto = cryptoAliases.has(objLower);
        let resolvedMethod = propName;

        if (!isNodeCrypto && !objName && propName && destructuredCryptoFns.has(propName.toLowerCase())) {
          isNodeCrypto = true;
          resolvedMethod = destructuredCryptoFns.get(propName.toLowerCase());
        }

        // 2. Node.js built-in crypto
        if (isNodeCrypto && resolvedMethod) {
          if (resolvedMethod === 'verify') {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'RSA' };
            addFinding({
              name: parsed.family || 'RSA',
              algorithmFamily: parsed.family || 'RSA',
              primitive: Primitive.SIGNATURE,
              parameterSet: parsed.mode || (algArg ? String(algArg) : null),
              rawConfidence: isLiteral ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `crypto.verify(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (resolvedMethod === 'sign') {
            const algArg = extractLiteralValue(node.arguments[0]);
            const isLiteral = algArg != null;
            const parsed = parseAlgorithmIdentifier(algArg) || { family: 'RSA' };
            addFinding({
              name: parsed.family || 'RSA',
              algorithmFamily: parsed.family || 'RSA',
              primitive: Primitive.SIGNATURE,
              parameterSet: parsed.mode || (algArg ? String(algArg) : null),
              rawConfidence: isLiteral ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `crypto.sign(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (resolvedMethod === 'createPublicKey') {
            addFinding({
              assetType: AssetType.RELATED_CRYPTO_MATERIAL,
              materialType: MaterialType.PUBLIC_KEY,
              name: 'public-key',
              algorithmFamily: 'RSA',
              primitive: null,
              rawConfidence: 0.90,
              sourceContext: 'live',
            }, line, 'crypto.createPublicKey()');
          } else if (resolvedMethod === 'createPrivateKey') {
            addFinding({
              assetType: AssetType.RELATED_CRYPTO_MATERIAL,
              materialType: MaterialType.PRIVATE_KEY,
              name: 'private-key',
              algorithmFamily: 'RSA',
              primitive: null,
              rawConfidence: 0.90,
              sourceContext: 'live',
            }, line, 'crypto.createPrivateKey()');
          } else if (resolvedMethod === 'timingSafeEqual') {
            addFinding({
              assetType: AssetType.ALGORITHM,
              name: 'timingSafeEqual',
              algorithmFamily: 'timingSafeEqual',
              primitive: null,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, 'crypto.timingSafeEqual() [constant-time comparison]');
          } else if (/^hkdf(Sync)?$/.test(resolvedMethod)) {
            const digestArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: 'HKDF',
              algorithmFamily: 'HKDF',
              primitive: Primitive.KDF,
              parameterSet: digestArg ? String(digestArg) : 'sha256',
              rawConfidence: digestArg ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `crypto.${resolvedMethod}(${digestArg ? '"' + digestArg + '"' : ''})`);
          } else if (resolvedMethod === 'createHash') {
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
          } else if (resolvedMethod === 'createHmac') {
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
          } else if (/^createCipher(iv)?$/.test(resolvedMethod)) {
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
            }, line, `crypto.${resolvedMethod}(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (/^createDecipher(iv)?$/.test(resolvedMethod)) {
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
            }, line, `crypto.${resolvedMethod}(${algArg ? '"' + algArg + '"' : ''})`);
          } else if (resolvedMethod === 'createSign') {
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
          } else if (resolvedMethod === 'createVerify') {
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
          } else if (/^pbkdf2(Sync)?$/.test(resolvedMethod)) {
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
            }, line, `crypto.${resolvedMethod}()`);
          } else if (/^scrypt(Sync)?$/.test(resolvedMethod)) {
            addFinding({
              name: 'scrypt',
              algorithmFamily: 'scrypt',
              primitive: Primitive.KDF,
              rawConfidence: 0.95,
              sourceContext: 'live',
            }, line, `crypto.${resolvedMethod}()`);
          } else if (/^randomBytes(Sync)?$/.test(resolvedMethod)) {
            const bytesArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: 'CSPRNG',
              algorithmFamily: 'CSPRNG',
              primitive: Primitive.DRBG,
              parameterSet: bytesArg ? `${bytesArg * 8} bits` : null,
              rawConfidence: bytesArg ? 0.95 : 0.85,
              sourceContext: 'live',
            }, line, `crypto.${resolvedMethod}(${bytesArg || ''})`);
          } else if (/^generateKeyPair(Sync)?$/.test(resolvedMethod)) {
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
            }, line, `crypto.${resolvedMethod}(${typeArg ? '"' + typeArg + '"' : ''})`);
          } else if (/^(createDiffieHellman|createECDH)$/.test(resolvedMethod)) {
            const curveArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: resolvedMethod === 'createECDH' ? 'ECDH' : 'DH',
              algorithmFamily: resolvedMethod === 'createECDH' ? 'ECDH' : 'DH',
              primitive: Primitive.KEY_AGREE,
              parameterSet: curveArg ? String(curveArg) : null,
              rawConfidence: curveArg ? 0.95 : 0.80,
              sourceContext: 'live',
            }, line, `crypto.${resolvedMethod}(${curveArg ? '"' + curveArg + '"' : ''})`);
          }
        }

        // 3. bcrypt / bcrypt-nodejs / bcryptjs
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

        // 4. jsonwebtoken / jwt / jose
        if ((jwtAliases.has(objLower) || objLower.includes('jwt') || objLower.includes('jose')) &&
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

        // 5. CryptoJS
        if (cryptoJsAliases.has(objLower) || objLower.includes('cryptojs') || objLower.includes('crypto_js')) {
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

    // COSE algorithms in regex fallback
    const coseMatch = l.match(/\b(?:alg|coseAlg|algorithm)\s*:\s*(-7|-257|-8|-37|-35|-36|-47|-258|-259)\b/i);
    if (coseMatch) {
      const algNum = parseInt(coseMatch[1], 10);
      const cose = COSE_ALGORITHMS[algNum];
      if (cose) {
        const f = new CryptoFinding({
          assetType: AssetType.ALGORITHM,
          name: cose.name,
          algorithmFamily: cose.algorithmFamily,
          primitive: cose.primitive,
          parameterSet: cose.parameterSet,
          filePath,
          line: lineNum,
          sourceContext: 'live',
        });
        f.addEvidence(new Evidence({
          source: 'ast',
          evidenceClass: EvidenceClass.DIRECT,
          detail: `COSE algorithm ${cose.label} (regex fallback)`,
          rawConfidence: 0.60,
          filePath,
          line: lineNum,
        }));
        findings.push(f);
      }
    }

    // WebCrypto calls in regex fallback
    if (/crypto\.subtle\.(verify|sign|digest|importKey|generateKey|deriveKey|deriveBits)/.test(l)) {
      const m = l.match(/crypto\.subtle\.(verify|sign|digest|importKey|generateKey|deriveKey|deriveBits)/);
      const method = m ? m[1] : 'verify';
      let family = 'ECDSA';
      let primitive = Primitive.SIGNATURE;
      if (method === 'digest') { family = 'SHA-256'; primitive = Primitive.HASH; }
      else if (method === 'deriveKey' || method === 'deriveBits') { family = 'HKDF'; primitive = Primitive.KDF; }

      if (/P-256|ECDSA/i.test(l)) { family = 'ECDSA'; }
      else if (/RSA/i.test(l)) { family = 'RSA'; }
      else if (/AES/i.test(l)) { family = 'AES'; primitive = Primitive.BLOCK_CIPHER; }

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
        detail: `crypto.subtle.${method}() (regex fallback)`,
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }

    // Node crypto.verify / crypto.sign / crypto.hkdf
    if (/crypto\.(verify|sign)\s*\(/.test(l)) {
      const m = l.match(/crypto\.(verify|sign)\s*\(\s*['"]?([A-Za-z0-9-]+)?/);
      const alg = m && m[2] ? m[2] : 'RSA';
      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: 'RSA',
        algorithmFamily: 'RSA',
        primitive: Primitive.SIGNATURE,
        parameterSet: alg,
        filePath,
        line: lineNum,
        sourceContext: 'live',
      });
      f.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: `crypto.${m ? m[1] : 'verify'}(${alg}) (regex fallback)`,
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }

    if (/crypto\.(hkdf|hkdfSync)\s*\(/.test(l)) {
      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: 'HKDF',
        algorithmFamily: 'HKDF',
        primitive: Primitive.KDF,
        parameterSet: 'sha256',
        filePath,
        line: lineNum,
        sourceContext: 'live',
      });
      f.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: 'crypto.hkdf call (regex fallback)',
        rawConfidence: 0.55,
        filePath,
        line: lineNum,
      }));
      findings.push(f);
    }

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

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
  '__tests__', '__mocks__', 'test', 'tests', 'fixtures',
]);

function isTestPath(filename, relPath = '') {
  if (/[._-](test|spec)\.[a-zA-Z0-9]+$/i.test(filename)) return true;
  const normalized = relPath.replace(/\\/g, '/');
  if (/(?:^|\/)(?:__tests__|__mocks__|test|tests)\//i.test(normalized)) return true;
  return false;
}

function walkDirectory(dir, targetDir = dir, results = [], isRoot = true) {
  if (!fs.existsSync(dir)) return results;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const relPath = path.relative(targetDir, full).replace(/\\/g, '/');
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' && isRoot) {
        walkNodeModules(full, results);
      } else if (!SKIP_DIRS.has(entry.name)) {
        walkDirectory(full, targetDir, results, false);
      }
    } else if (/\.(js|jsx|ts|tsx|mjs|cjs)$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
      if (!isTestPath(entry.name, relPath)) {
        results.push(full);
      }
    }
  }
  return results;
}

function scan(targetDir) {
  const files = walkDirectory(targetDir, targetDir);
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
