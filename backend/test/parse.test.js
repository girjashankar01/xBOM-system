const path = require('path');
const { parseLockfile } = require('../src/modules/parse/npmLockParser');

const FIXTURE = path.join(__dirname, 'fixtures', 'sample-package-lock.json');
const OLD_VERSION_FIXTURE = path.join(__dirname, 'fixtures', 'old-version-package-lock.json');

describe('npmLockParser', () => {
  test('parses transitive deps, not just top-level', () => {
    const components = parseLockfile(FIXTURE);
    const names = components.map(c => c.name);

    // direct dep
    expect(names).toContain('express');
    // transitive deps (nested two levels deep: express -> accepts -> mime-types)
    expect(names).toContain('accepts');
    expect(names).toContain('mime-types');
    expect(names).toContain('negotiator');
    expect(names).toContain('body-parser');
    expect(names).toContain('bytes');
  });

  test('every component has an exact version, not a range', () => {
    const components = parseLockfile(FIXTURE);
    for (const c of components) {
      expect(c.version).toBeDefined();
      // exact semver, not a range: no ^, ~, *, or spaces
      expect(c.version).toMatch(/^\d+\.\d+\.\d+/);
    }
  });

  test('builds correct purl format', () => {
    const components = parseLockfile(FIXTURE);
    const express = components.find(c => c.name === 'express');
    expect(express.purl).toBe('pkg:npm/express@4.18.2');
  });

  test('declaredRanges captures loose ranges where present', () => {
    const components = parseLockfile(FIXTURE);
    const looseDep = components.find(c => c.name === 'loose-dep');
    expect(looseDep.declaredRanges).toContain('*');
  });

  test('declaredRanges captures normal pinned ranges too', () => {
    const components = parseLockfile(FIXTURE);
    const accepts = components.find(c => c.name === 'accepts');
    expect(accepts.declaredRanges).toContain('~1.3.8');
  });

  test('flags dev dependency correctly', () => {
    const components = parseLockfile(FIXTURE);
    const looseDep = components.find(c => c.name === 'loose-dep');
    expect(looseDep.dev).toBe(true);
  });

  test('throws on lockfileVersion < 2', () => {
    expect(() => parseLockfile(OLD_VERSION_FIXTURE)).toThrow(
      /lockfileVersion < 2 not supported/
    );
  });

  test('skips the root package entry itself', () => {
    const components = parseLockfile(FIXTURE);
    const names = components.map(c => c.name);
    expect(names).not.toContain('');
    expect(names).not.toContain('sample-app');
  });
});
