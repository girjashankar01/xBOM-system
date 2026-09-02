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

  // 1. Traverse AST CallExpressions
  try {
    traverse(ast, {
      CallExpression(p) {
        const node = p.node;
        const line = node.loc ? node.loc.start.line : 1;
        const callee = node.callee;

        let objName = null;
        let propName = null;

        if (callee.type === 'MemberExpression') {
          if (callee.object.type === 'Identifier') {
            objName = callee.object.name;
          } else if (callee.object.type === 'MemberExpression' && callee.object.property) {
            const prefix = callee.object.object && callee.object.object.name ? callee.object.object.name + '.' : '';
            objName = prefix + callee.object.property.name;
          }
          if (callee.property.type === 'Identifier') {
            propName = callee.property.name;
          }
        } else if (callee.type === 'Identifier') {
          propName = callee.name;
        }

        const objLower = (objName || '').toLowerCase();

        // 1. bcrypt / bcrypt-nodejs / bcryptjs
        if ((objLower === 'bcrypt' || objLower === 'bcryptjs' || objLower === 'bcrypt-nodejs' || objLower.includes('bcrypt')) &&
            /^(hash|hashSync|compare|compareSync|genSalt|genSaltSync)$/.test(propName)) {
          const isSalt = /genSalt/.test(propName);
          const isCompare = /compare/.test(propName);
          const roundsArg = extractLiteralValue(node.arguments[0]);

          if (isSalt) {
            // Salt generation -> related-crypto-material of type salt, NO algorithm primitive
            addFinding({
              assetType: AssetType.RELATED_CRYPTO_MATERIAL,
              name: 'bcrypt-salt',
              algorithmFamily: 'bcrypt',
              primitive: null,
              materialType: MaterialType.SALT,
              parameterSet: roundsArg ? `${roundsArg} rounds` : null,
              rawConfidence: roundsArg ? 0.95 : 0.85,
            }, line, `${objName}.${propName}() [salt generation]`);
          } else if (isCompare) {
            // Password verification -> algorithm bcrypt without KDF primitive
            addFinding({
              assetType: AssetType.ALGORITHM,
              name: 'bcrypt',
              algorithmFamily: 'bcrypt',
              primitive: null,
              materialType: null,
              rawConfidence: 0.95,
            }, line, `${objName}.${propName}() [password verify]`);
          } else {
            // Password hash derivation -> algorithm bcrypt with KDF primitive
            addFinding({
              assetType: AssetType.ALGORITHM,
              name: 'bcrypt',
              algorithmFamily: 'bcrypt',
              primitive: Primitive.KDF,
              materialType: null,
              rawConfidence: 0.95,
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
            }, line, `crypto.${propName}()`);
          } else if (/^scrypt(Sync)?$/.test(propName)) {
            addFinding({
              name: 'scrypt',
              algorithmFamily: 'scrypt',
              primitive: Primitive.KDF,
              rawConfidence: 0.95,
            }, line, `crypto.${propName}()`);
          } else if (/^randomBytes(Sync)?$/.test(propName)) {
            const bytesArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: 'CSPRNG',
              algorithmFamily: 'CSPRNG',
              primitive: Primitive.DRBG,
              parameterSet: bytesArg ? `${bytesArg * 8} bits` : null,
              rawConfidence: bytesArg ? 0.95 : 0.85,
            }, line, `crypto.randomBytes(${bytesArg || ''})`);
          } else if (/^generateKeyPair(Sync)?$/.test(propName)) {
            const typeArg = extractLiteralValue(node.arguments[0]);
            const family = typeArg ? typeArg.toUpperCase() : 'RSA';
            // Keypair generation emits key material (related-crypto-material) without primitive
            addFinding({
              assetType: AssetType.RELATED_CRYPTO_MATERIAL,
              materialType: MaterialType.PRIVATE_KEY,
              name: family,
              algorithmFamily: family,
              primitive: null,
              rawConfidence: typeArg ? 0.95 : 0.80,
            }, line, `crypto.${propName}(${typeArg ? '"' + typeArg + '"' : ''})`);
          } else if (/^(createDiffieHellman|createECDH)$/.test(propName)) {
            const curveArg = extractLiteralValue(node.arguments[0]);
            addFinding({
              name: propName === 'createECDH' ? 'ECDH' : 'DH',
              algorithmFamily: propName === 'createECDH' ? 'ECDH' : 'DH',
              primitive: Primitive.KEY_AGREE,
              parameterSet: curveArg ? String(curveArg) : null,
              rawConfidence: curveArg ? 0.95 : 0.80,
            }, line, `crypto.${propName}(${curveArg ? '"' + curveArg + '"' : ''})`);
          }
        }

        // 3. jsonwebtoken / jwt / jose
        if ((objLower === 'jwt' || objLower === 'jsonwebtoken' || objLower.includes('jwt') || objLower.includes('jose')) &&
            /^(sign|verify|signJWT|jwtVerify|compactEncrypt)$/i.test(propName)) {
          let alg = null;
          let isWeak = false;

          for (const arg of node.arguments) {
            if (arg && arg.type === 'ObjectExpression') {
              for (const pr of arg.properties) {
                if (pr.key && (pr.key.name === 'algorithm' || pr.key.value === 'algorithm')) {
                  alg = extractLiteralValue(pr.value);
                }
              }
            }
          }

          const hasExplicitAlg = alg != null;
          if (!alg) alg = 'HS256';

          const secretArg = extractLiteralValue(node.arguments[1]);
          if (secretArg && (typeof secretArg === 'string') && (secretArg === 'secret' || secretArg.length < 16)) {
            isWeak = true;
          }
          if (alg && alg.toLowerCase() === 'none') {
            isWeak = true;
          }

          const parsed = parseAlgorithmIdentifier(alg) || { family: 'HMAC', mode: 'SHA-256' };
          addFinding({
            assetType: AssetType.ALGORITHM,
            name: parsed.family || 'JWT',
            algorithmFamily: parsed.family || 'JWT',
            primitive: Primitive.SIGNATURE,
            mode: parsed.mode || null,
            parameterSet: isWeak ? 'weak-secret-or-none' : alg,
            rawConfidence: hasExplicitAlg ? 0.95 : 0.80,
          }, line, `jwt.${propName}(${alg})` + (isWeak ? ' [flagged weak secret/none]' : ''));
        }

        // 4. CryptoJS
        if (objLower.includes('cryptojs') || objLower.includes('crypto_js')) {
          if (propName === 'encrypt' || propName === 'decrypt') {
            const cipherType = objName.split('.').pop() || 'AES';
            const parsed = parseAlgorithmIdentifier(cipherType) || { family: cipherType.toUpperCase() };
            const isStream = /^(RC4|Rabbit)$/i.test(cipherType);
            addFinding({
              name: parsed.family || 'AES',
              algorithmFamily: parsed.family || 'AES',
              primitive: isStream ? Primitive.STREAM_CIPHER : Primitive.BLOCK_CIPHER,
              rawConfidence: 0.95,
            }, line, `CryptoJS.${cipherType}.${propName}()`);
          } else if (/^(SHA256|SHA512|SHA384|SHA224|SHA1|MD5|RIPEMD160)$/i.test(propName)) {
            addFinding({
              name: propName.toUpperCase(),
              algorithmFamily: propName.toUpperCase(),
              primitive: Primitive.HASH,
              rawConfidence: 0.95,
            }, line, `CryptoJS.${propName}()`);
          } else if (/^Hmac/i.test(propName)) {
            addFinding({
              name: 'HMAC',
              algorithmFamily: 'HMAC',
              primitive: Primitive.MAC,
              mode: propName.replace(/^Hmac/i, '').toUpperCase(),
              rawConfidence: 0.95,
            }, line, `CryptoJS.${propName}()`);
          } else if (propName === 'PBKDF2') {
            addFinding({
              name: 'PBKDF2',
              algorithmFamily: 'PBKDF2',
              primitive: Primitive.KDF,
              rawConfidence: 0.95,
            }, line, `CryptoJS.PBKDF2()`);
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
      }, curLine, 'bcrypt.genSalt (code comment)');
    } else if (/bcrypt\.compare/.test(l)) {
      addFinding({
        assetType: AssetType.ALGORITHM,
        name: 'bcrypt',
        algorithmFamily: 'bcrypt',
        primitive: null,
        rawConfidence: 0.65,
      }, curLine, 'bcrypt.compare (code comment)');
    } else if (/bcrypt\.hash/.test(l)) {
      addFinding({
        assetType: AssetType.ALGORITHM,
        name: 'bcrypt',
        algorithmFamily: 'bcrypt',
        primitive: Primitive.KDF,
        rawConfidence: 0.65,
      }, curLine, 'bcrypt.hash (code comment)');
    }
    if (/crypto\.pbkdf2(Sync)?\s*\(/.test(l)) {
      addFinding({
        name: 'PBKDF2',
        algorithmFamily: 'PBKDF2',
        primitive: Primitive.KDF,
        parameterSet: 'sha512',
        rawConfidence: 0.65,
      }, curLine, 'crypto.pbkdf2Sync (code comment)');
    }
    if (/crypto\.createCipher(iv)?\s*\(/.test(l)) {
      addFinding({
        name: 'AES',
        algorithmFamily: 'AES',
        primitive: Primitive.BLOCK_CIPHER,
        mode: 'CBC',
        rawConfidence: 0.65,
      }, curLine, 'crypto.createCipheriv (code comment)');
    }
    if (/crypto\.createDecipher(iv)?\s*\(/.test(l)) {
      addFinding({
        name: 'AES',
        algorithmFamily: 'AES',
        primitive: Primitive.BLOCK_CIPHER,
        mode: 'CBC',
        rawConfidence: 0.65,
      }, curLine, 'crypto.createDecipheriv (code comment)');
    }
    if (/crypto\.randomBytes(Sync)?\s*\(/.test(l)) {
      addFinding({
        name: 'CSPRNG',
        algorithmFamily: 'CSPRNG',
        primitive: Primitive.DRBG,
        parameterSet: '128 bits',
        rawConfidence: 0.65,
      }, curLine, 'crypto.randomBytes (code comment)');
    }
    if (/jwt\.(sign|verify)/.test(l)) {
      addFinding({
        name: 'JWT',
        algorithmFamily: 'JWT',
        primitive: Primitive.SIGNATURE,
        rawConfidence: 0.65,
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
  });
  return findings;
}

function walkDirectory(dir, results = []) {
  if (!fs.existsSync(dir)) return results;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== 'node_modules' && entry.name !== '.git' && entry.name !== 'dist' && entry.name !== 'build') {
        walkDirectory(full, results);
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
