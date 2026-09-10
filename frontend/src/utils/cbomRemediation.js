/**
 * Cryptographic Remediation & Post-Quantum Risk Reference Utility
 * Provides tailored remediation steps, NIST PQC explanations, and checklist generation.
 */

export const QUANTUM_EXPLANATIONS = {
  0: {
    title: 'Level 0 — Broken by Quantum (Critical Risk)',
    badgeColor: 'bg-critical/15 text-critical border-critical/30',
    summary: 'Completely vulnerable to Shor’s algorithm on a Cryptographically Relevant Quantum Computer (CRQC).',
    affectedAlgorithms: 'RSA, ECDSA, ECDH, DSA, Ed25519, Diffie-Hellman',
    quantumAttack: 'Shor’s algorithm solves integer factorization and discrete logarithms in polynomial time, completely destroying public-key encryption and digital signatures.',
    recommendation: 'Migrate immediately to NIST Post-Quantum Cryptography (PQC) standards: ML-KEM (FIPS 203) for key encapsulation, and ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for digital signatures.',
  },
  1: {
    title: 'Level 1 — 128-Bit Classical Security (Grover Downgrade)',
    badgeColor: 'bg-high/15 text-high border-high/30',
    summary: 'Equivalent to AES-128 key exhaustion. Grover’s algorithm effectively halves security to ~64 bits.',
    affectedAlgorithms: 'AES-128, HMAC-SHA1, 128-bit symmetric ciphers',
    quantumAttack: 'Grover’s algorithm provides a quadratic speedup for unstructured brute-force search (O(√N)), reducing a 128-bit key space to 2^64 operations.',
    recommendation: 'Upgrade symmetric cipher keys to 256-bit (e.g. AES-256-GCM) to ensure at least 128 bits of post-quantum security margin.',
  },
  2: {
    title: 'Level 2 — SHA-256 / SHA3-256 Collision Level',
    badgeColor: 'bg-high/15 text-high border-high/30',
    summary: 'Equivalent to the collision resistance of SHA-256 (128-bit collision strength).',
    affectedAlgorithms: 'SHA-256, SHA3-256',
    quantumAttack: 'Quantum collision algorithms (Brassard-Høyer-Tapp) provide polynomial-to-subexponential attacks against hash collision resistance.',
    recommendation: 'Safe for most classical and hybrid use cases. For critical signatures or long-term secrecy, consider upgrading to SHA-384 (Level 4) or SHA-512.',
  },
  3: {
    title: 'Level 3 — 192-Bit Classical / NIST PQC Baseline (Quantum-Safe)',
    badgeColor: 'bg-safe/15 text-safe border-safe/30',
    summary: 'Equivalent to AES-192 key search. Certified NIST Quantum-Safe baseline.',
    affectedAlgorithms: 'AES-192, ML-KEM-768 (Kyber-768), ML-DSA-65 (Dilithium-3)',
    quantumAttack: 'Provides robust theoretical and practical resistance against known quantum search and collision algorithms.',
    recommendation: 'NIST’s recommended baseline standard for general commercial and enterprise post-quantum transition.',
  },
  4: {
    title: 'Level 4 — SHA-384 / SHA3-384 Collision Level',
    badgeColor: 'bg-safe/15 text-safe border-safe/30',
    summary: 'Equivalent to the collision resistance of SHA-384 (192-bit collision resistance).',
    affectedAlgorithms: 'SHA-384, SHA3-384',
    quantumAttack: 'Resistant to both classical and quantum collision search algorithms with an extensive security margin.',
    recommendation: 'Ideal for top-tier cryptographic integrity, code signing, and government applications.',
  },
  5: {
    title: 'Level 5 — 256-Bit Classical / Maximum PQC (Maximum Quantum Resistance)',
    badgeColor: 'bg-safe/15 text-safe border-safe/30',
    summary: 'Equivalent to AES-256 key exhaustion. Highest post-quantum security tier.',
    affectedAlgorithms: 'AES-256-GCM, ML-KEM-1024, ML-DSA-87, SHA-512',
    quantumAttack: 'Requires 2^128 quantum operations even under Grover’s algorithm, which is physically impossible to brute force.',
    recommendation: 'Maximum security rating. Recommended for long-term secret archival (Store Now, Decrypt Later defense).',
  },
}

/**
 * Returns tailored remediation steps for a specific CBOM asset finding.
 */
export function getRemediationAdvice(asset) {
  const qLevel = asset.quantumSecurityLevel ?? 0
  const exposure = asset.exposureRisk || 'NONE'
  const name = (asset.name || '').toUpperCase()
  const pset = (asset.algorithmProperties?.parameterSetIdentifier || '').toUpperCase()

  const actions = []
  let severity = 'info'
  let summary = ''
  let targetPqc = ''

  // 1. Exposure Risk (Plaintext secret or private key in code)
  if (exposure === 'CRITICAL' || exposure === 'HIGH') {
    severity = 'critical'
    summary = 'Exposed Private Key or Cryptographic Secret'
    actions.push(
      'Revoke and rotate this exposed cryptographic key immediately.',
      'Migrate key storage to an automated secret manager (e.g. AWS Secrets Manager, HashiCorp Vault, or KMS).',
      'Purge plaintexts from Git history and ensure sensitive files are added to .gitignore.'
    )
    return { severity, summary, actions, targetPqc: 'KMS / Vault' }
  }

  // 2. Quantum Vulnerability (Q0 - Classical Asymmetric)
  if (qLevel === 0) {
    severity = 'critical'
    if (name.includes('EC') || name.includes('ECDSA') || name.includes('CURVE')) {
      summary = 'Elliptic Curve (ECC) Shor Vulnerability'
      targetPqc = 'ML-DSA (FIPS 204) / ML-KEM (FIPS 203)'
      actions.push(
        'Elliptic Curve cryptography is broken in polynomial time by Shor’s algorithm on a quantum computer.',
        'Digital Signatures: Migrate to NIST post-quantum standard ML-DSA (Dilithium) or stateful hash signatures (SLH-DSA).',
        'Key Exchange: Adopt hybrid post-quantum key exchange (e.g. X25519 + ML-KEM-768).'
      )
    } else if (name.includes('RSA')) {
      summary = 'RSA Factorization Shor Vulnerability'
      targetPqc = 'ML-KEM (FIPS 203) / ML-DSA (FIPS 204)'
      actions.push(
        'RSA integer factorization is vulnerable to Shor’s algorithm on cryptographically relevant quantum computers.',
        'Plan migration to ML-KEM for key encapsulation and ML-DSA for digital signatures.',
        'Introduce crypto-agility to swap asymmetric algorithm suites without recompiling code.'
      )
    } else {
      summary = 'Quantum-Vulnerable Asymmetric Primitive'
      targetPqc = 'NIST PQC Suite (FIPS 203 / 204 / 205)'
      actions.push(
        'This asymmetric asset does not resist Shor’s algorithm.',
        'Transition to NIST-standardized Post-Quantum Cryptography (PQC) algorithms.'
      )
    }
    return { severity, summary, actions, targetPqc }
  }

  // 3. Legacy Weak Hashes (MD5, SHA-1)
  if (pset.includes('SHA1') || pset.includes('MD5') || name.includes('MD5') || name.includes('SHA1')) {
    severity = 'high'
    summary = 'Legacy Weak Digest (Collision Vulnerability)'
    targetPqc = 'SHA-256 / SHA-384 / SHA-3'
    actions.push(
      'SHA-1 and MD5 suffer from known practical collision attacks and should never be used for integrity checks or signatures.',
      'Upgrade hashing digest to SHA-256 (NIST Level 2) or SHA-384 (NIST Level 4).',
      'If used in HMAC tokens or authentication, invalidate and regenerate keys with HMAC-SHA256.'
    )
    return { severity, summary, actions, targetPqc }
  }

  // 4. Level 1 Symmetric (AES-128, etc.)
  if (qLevel === 1) {
    severity = 'medium'
    summary = '128-Bit Classical Key (Grover Downgrade Risk)'
    targetPqc = 'AES-256-GCM (NIST Level 5)'
    actions.push(
      'Grover’s quantum search algorithm reduces effective brute-force resistance from 128 bits to ~64 bits.',
      'Upgrade symmetric key length to AES-256-GCM to retain ≥128 bits of post-quantum security margin.',
      'Ensure authenticated encryption with associated data (AEAD) mode is enforced.'
    )
    return { severity, summary, actions, targetPqc }
  }

  // 5. Quantum-Safe (Q3 - Q5)
  if (qLevel >= 3) {
    severity = 'safe'
    summary = 'Quantum-Resistant Implementation'
    targetPqc = 'Compliant'
    actions.push(
      'This primitive meets or exceeds NIST Level 3–5 quantum resistance criteria.',
      'Maintain continuous monitoring and enforce regular key lifecycle and rotation policies.'
    )
    return { severity, summary, actions, targetPqc }
  }

  // 6. Certificate / Default
  if (asset.assetType === 'certificate') {
    severity = 'medium'
    summary = 'X.509 Certificate Lifecycle & Transition'
    targetPqc = 'Hybrid PQC Certificate'
    actions.push(
      'Verify certificate expiration and configure automated renewal (ACME / Let’s Encrypt).',
      'Plan for hybrid post-quantum certificate chains (e.g. classical RSA/ECC + ML-DSA).'
    )
    return { severity, summary, actions, targetPqc }
  }

  severity = 'low'
  summary = 'Cryptographic Good Practice'
  targetPqc = 'CSPRNG Validated'
  actions.push(
    'Verify that cryptographic nonces, IVs, and keys are generated using a cryptographically secure pseudorandom generator (crypto.randomBytes).'
  )
  return { severity, summary, actions, targetPqc }
}

/**
 * Generates an aggregated, actionable remediation checklist across all findings.
 */
export function generateRemediationChecklist(assets) {
  const tasks = []

  // 1. Critical: Exposed Secrets
  const exposed = assets.filter((a) => a.exposureRisk === 'CRITICAL' || a.exposureRisk === 'HIGH')
  if (exposed.length > 0) {
    tasks.push({
      id: 'task-exposed-secrets',
      priority: 'critical',
      title: `Revoke and isolate ${exposed.length} exposed cryptographic secret${exposed.length > 1 ? 's' : ''}`,
      description: `Detected plaintext private keys or sensitive cryptographic material in code (${exposed.map((a) => a.name).join(', ')}). Rotate immediately and migrate to an environment-backed secrets manager.`,
      affectedCount: exposed.length,
      recommendation: 'Purge from Git history & migrate to KMS/Vault',
      target: 'Immediate',
    })
  }

  // 2. Critical: Q0 Quantum-Vulnerable Assets
  const q0Assets = assets.filter((a) => a.quantumSecurityLevel === 0)
  if (q0Assets.length > 0) {
    tasks.push({
      id: 'task-q0-migration',
      priority: 'critical',
      title: `Plan Post-Quantum PQC migration for ${q0Assets.length} Q0 asymmetric asset${q0Assets.length > 1 ? 's' : ''}`,
      description: `Classical asymmetric algorithms (${Array.from(new Set(q0Assets.map((a) => a.name))).join(', ')}) will be compromised by Shor’s algorithm. Plan hybrid migration to ML-KEM (FIPS 203) and ML-DSA (FIPS 204).`,
      affectedCount: q0Assets.length,
      recommendation: 'Adopt hybrid X25519 + ML-KEM / ML-DSA',
      target: 'Post-Quantum Roadmap',
    })
  }

  // 3. High: Weak Hash Algorithms (MD5 / SHA-1)
  const weakHashes = assets.filter((a) => {
    const pset = (a.algorithmProperties?.parameterSetIdentifier || '').toUpperCase()
    const name = (a.name || '').toUpperCase()
    return pset.includes('SHA1') || pset.includes('MD5') || name.includes('MD5') || name.includes('SHA1')
  })
  if (weakHashes.length > 0) {
    tasks.push({
      id: 'task-weak-hashes',
      priority: 'high',
      title: `Replace ${weakHashes.length} legacy digest operation${weakHashes.length > 1 ? 's' : ''} (SHA-1 / MD5)`,
      description: `Weak collision resistance allows practical forgery attacks. Upgrade hashing implementations in ${Array.from(new Set(weakHashes.map((a) => a.sourceFile || a.name))).join(', ')} to SHA-256 or SHA-384.`,
      affectedCount: weakHashes.length,
      recommendation: 'Upgrade to SHA-256 (NIST Q2) or SHA-384 (NIST Q4)',
      target: 'Sprint Backlog',
    })
  }

  // 4. Medium: 128-bit Symmetric Key Strength
  const q1Assets = assets.filter((a) => a.quantumSecurityLevel === 1)
  if (q1Assets.length > 0) {
    tasks.push({
      id: 'task-q1-symmetric',
      priority: 'medium',
      title: `Upgrade ${q1Assets.length} 128-bit symmetric cipher${q1Assets.length > 1 ? 's' : ''} to 256-bit AES-GCM`,
      description: `Grover’s algorithm reduces 128-bit key strength to ~64-bit quantum security. Upgrading to AES-256-GCM guarantees ≥128-bit post-quantum security margin.`,
      affectedCount: q1Assets.length,
      recommendation: 'Migrate to AES-256-GCM (NIST Q5)',
      target: 'Medium-term',
    })
  }

  // 5. Low/Review: Low Confidence Verification
  const lowConf = assets.filter((a) => a.confidence === 'low')
  if (lowConf.length > 0) {
    tasks.push({
      id: 'task-low-confidence',
      priority: 'low',
      title: `Manually audit ${lowConf.length} low-confidence cryptographic detection${lowConf.length > 1 ? 's' : ''}`,
      description: `Heuristic or pattern match confidence was low for ${lowConf.map((a) => a.name).join(', ')}. Review call sites to confirm genuine cryptographic intent.`,
      affectedCount: lowConf.length,
      recommendation: 'Verify AST call sites & remove dead code',
      target: 'Security Review',
    })
  }

  return tasks
}

/**
 * Formats the remediation tasks as a Markdown tasklist (ready for GitHub Issue or Jira).
 */
export function formatChecklistAsMarkdown(tasks, repoUrl) {
  let md = `## Post-Quantum & Cryptography Remediation Plan\n`
  if (repoUrl) md += `*Target Repository:* ${repoUrl}\n`
  md += `*Generated by xBOM Security Platform*\n\n`

  if (tasks.length === 0) {
    md += `No critical cryptographic remediation items found.\n`
    return md
  }

  const criticalTasks = tasks.filter((t) => t.priority === 'critical')
  const highTasks = tasks.filter((t) => t.priority === 'high')
  const mediumTasks = tasks.filter((t) => t.priority === 'medium')
  const otherTasks = tasks.filter((t) => t.priority === 'low' || t.priority === 'info')

  if (criticalTasks.length > 0) {
    md += `### Immediate Action Required (Critical)\n`
    criticalTasks.forEach((t) => {
      md += `- [ ] **${t.title}**\n  - ${t.description}\n  - **Fix:** ${t.recommendation}\n`
    })
    md += `\n`
  }

  if (highTasks.length > 0) {
    md += `### High Priority\n`
    highTasks.forEach((t) => {
      md += `- [ ] **${t.title}**\n  - ${t.description}\n  - **Fix:** ${t.recommendation}\n`
    })
    md += `\n`
  }

  if (mediumTasks.length > 0) {
    md += `### Medium Priority (Post-Quantum Transition)\n`
    mediumTasks.forEach((t) => {
      md += `- [ ] **${t.title}**\n  - ${t.description}\n  - **Fix:** ${t.recommendation}\n`
    })
    md += `\n`
  }

  if (otherTasks.length > 0) {
    md += `### Security Verification & Audit\n`
    otherTasks.forEach((t) => {
      md += `- [ ] **${t.title}**\n  - ${t.description}\n  - **Fix:** ${t.recommendation}\n`
    })
    md += `\n`
  }

  return md
}

/**
 * Synthesizes a realistic code context snippet around the detected cryptographic call site.
 */
export function getSynthesizedCodeSnippet(asset) {
  const line = asset.sourceLine || 1
  const name = (asset.name || '').toUpperCase()
  const pset = (asset.algorithmProperties?.parameterSetIdentifier || '').toLowerCase()
  const mode = (asset.algorithmProperties?.mode || '').toLowerCase()

  if (name.includes('EC') || name.includes('ECDSA') || name.includes('CURVE')) {
    return [
      { line: Math.max(1, line - 1), code: `// Elliptic Curve key material initialization` },
      { line: line, code: `const ecKey = crypto.createECDH('prime256v1');`, highlight: true },
      { line: line + 1, code: `ecKey.generateKeys();` },
      { line: line + 2, code: `// [CBOM Alert]: Asymmetric EC key (NIST Q0 - Shor's algorithm vulnerable)` },
    ]
  }

  if (name.includes('HMAC')) {
    const hashAlg = pset ? pset : 'sha256'
    return [
      { line: Math.max(1, line - 1), code: `// Initialize HMAC message authentication digest` },
      { line: line, code: `const hmac = crypto.createHmac('${hashAlg}', secretKey);`, highlight: true },
      { line: line + 1, code: `hmac.update(requestPayload);` },
      { line: line + 2, code: `const digest = hmac.digest('hex');` },
    ]
  }

  if (name.includes('AES')) {
    const cipherMode = mode || 'gcm'
    return [
      { line: Math.max(1, line - 1), code: `// Symmetric cipher instantiation` },
      { line: line, code: `const cipher = crypto.createCipheriv('aes-256-${cipherMode}', encryptionKey, iv);`, highlight: true },
      { line: line + 1, code: `let encrypted = cipher.update(plaintext, 'utf8', 'hex');` },
    ]
  }

  if (name.includes('RSA')) {
    return [
      { line: Math.max(1, line - 1), code: `// Asymmetric RSA digital signature / key invocation` },
      { line: line, code: `const signer = crypto.createSign('SHA256');`, highlight: true },
      { line: line + 1, code: `signer.update(tokenData);` },
      { line: line + 2, code: `const signature = signer.sign(privateKey);` },
    ]
  }

  if (name.includes('SHA') || name.includes('MD5')) {
    const hash = name.toLowerCase()
    return [
      { line: Math.max(1, line - 1), code: `// Hash digest calculation` },
      { line: line, code: `const hash = crypto.createHash('${hash}').update(data).digest('hex');`, highlight: true },
    ]
  }

  if (asset.assetType === 'certificate') {
    return [
      { line: line, code: `-----BEGIN CERTIFICATE-----`, highlight: true },
      { line: line + 1, code: `Subject: ${asset.certificateProperties?.subjectName || 'CN=localhost'}` },
      { line: line + 2, code: `Not Valid After: ${asset.certificateProperties?.notValidAfter || '2026-12-31'}` },
      { line: line + 3, code: `-----END CERTIFICATE-----` },
    ]
  }

  if (asset.assetType === 'related-crypto-material') {
    return [
      { line: line, code: `// Key Material reference: ${asset.name}`, highlight: true },
      { line: line + 1, code: `const keyMaterial = fs.readFileSync(path.join(__dirname, 'private.pem'));` },
    ]
  }

  return [
    { line: line, code: `// Cryptographic operation: ${asset.name} (${asset.assetType})`, highlight: true },
    { line: line + 1, code: `const cryptoRef = crypto.${asset.name.toLowerCase()} || require('crypto');` },
  ]
}
