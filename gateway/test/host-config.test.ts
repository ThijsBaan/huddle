import { describe, it, expect, vi } from 'vitest';

// socket-proxy importeert db.ts alleen voor de grant-checks; mocken houdt de
// native better-sqlite3-binding buiten deze test (die ontbreekt in een verse
// DMZ-devcontainer, zie rules.test.ts / grants.test.ts). De geteste functies
// zijn puur en raken de db niet.
vi.mock('../src/db', () => ({
  getGrant: () => null,
  isHostPortApproved: () => false,
}));

const { validateHostConfig, validateVolumeCreate } = await import('../src/socket-proxy');

// ── Boundary — socket-proxy HostConfig / volume policy ──────────────────────
// De per-container Docker-socket-proxy moet elke poging blokkeren om via een
// gespawnde container of via een volume uit de devcontainer-sandbox te breken.

describe('validateHostConfig', () => {
  it('staat een onschuldige config toe', () => {
    expect(validateHostConfig({})).toBeNull();
    expect(validateHostConfig({ Binds: ['myvol:/data'] })).toBeNull();
    expect(validateHostConfig({ Mounts: [{ Type: 'volume', Source: 'myvol', Target: '/data' }] })).toBeNull();
  });

  it('weigert de klassieke escape-vectoren', () => {
    expect(validateHostConfig({ Privileged: true })).toMatch(/privileged/i);
    expect(validateHostConfig({ PidMode: 'host' })).toMatch(/pidmode/i);
    expect(validateHostConfig({ CapAdd: ['SYS_ADMIN'] })).toMatch(/capadd/i);
    expect(validateHostConfig({ Binds: ['/:/host'] })).toMatch(/host-path bind/i);
    expect(validateHostConfig({ Mounts: [{ Type: 'bind', Source: '/', Target: '/host' }] })).toMatch(/bind-type/i);
  });

  it('weigert een volume-mount met inline driver-config (local bind escape)', () => {
    const denial = validateHostConfig({
      Mounts: [{
        Type: 'volume',
        Target: '/host',
        VolumeOptions: { DriverConfig: { Name: 'local', Options: { type: 'none', device: '/', o: 'bind' } } },
      }],
    });
    expect(denial).toMatch(/driverconfig not permitted/i);
  });
});

describe('validateHostConfig — mount permissions', () => {
  const allowAll = { bind: true, named: true, anonymous: true };
  const denyAll  = { bind: false, named: false, anonymous: false };

  it('defaults: bind denied, named + anonymous allowed', () => {
    expect(validateHostConfig({ Binds: ['/host:/data'] })).toMatch(/host-path bind/i);
    expect(validateHostConfig({ Binds: ['myvol:/data'] })).toBeNull();
    expect(validateHostConfig({ Binds: ['/data'] })).toBeNull(); // anonymous (no source)
    expect(validateHostConfig({ Mounts: [{ Type: 'volume', Target: '/x' }] })).toBeNull(); // anonymous
  });

  it('bind toggle gates host-path binds (both Binds and Mounts)', () => {
    expect(validateHostConfig({ Binds: ['/host:/data'] }, allowAll)).toBeNull();
    expect(validateHostConfig({ Mounts: [{ Type: 'bind', Source: '/', Target: '/host' }] }, allowAll)).toBeNull();
    expect(validateHostConfig({ Binds: ['/host:/data'] }, denyAll)).toMatch(/host-path bind/i);
    expect(validateHostConfig({ Mounts: [{ Type: 'bind', Source: '/', Target: '/host' }] }, denyAll)).toMatch(/bind-type/i);
  });

  it('named toggle gates named volumes', () => {
    const perms = { bind: false, named: false, anonymous: true };
    expect(validateHostConfig({ Binds: ['myvol:/data'] }, perms)).toMatch(/named volume/i);
    expect(validateHostConfig({ Mounts: [{ Type: 'volume', Source: 'myvol', Target: '/x' }] }, perms)).toMatch(/named volume/i);
  });

  it('anonymous toggle gates source-less volumes', () => {
    const perms = { bind: false, named: true, anonymous: false };
    expect(validateHostConfig({ Binds: ['/data'] }, perms)).toMatch(/anonymous volume/i);
    expect(validateHostConfig({ Mounts: [{ Type: 'volume', Target: '/x' }] }, perms)).toMatch(/anonymous volume/i);
    // named still passes
    expect(validateHostConfig({ Binds: ['myvol:/data'] }, perms)).toBeNull();
  });

  it('DriverConfig volumes are always denied, even with all mounts allowed', () => {
    expect(validateHostConfig({
      Mounts: [{ Type: 'volume', Target: '/host', VolumeOptions: { DriverConfig: { Name: 'local' } } }],
    }, allowAll)).toMatch(/driverconfig not permitted/i);
  });
});

describe('validateVolumeCreate', () => {
  it('staat een gewoon named volume toe', () => {
    expect(validateVolumeCreate({ Name: 'data' })).toBeNull();
    expect(validateVolumeCreate({ Name: 'data', Driver: 'local' })).toBeNull();
    expect(validateVolumeCreate({ Name: 'data', Driver: 'local', DriverOpts: {} })).toBeNull();
  });

  it('weigert een local bind-backed volume (host-path escape)', () => {
    expect(validateVolumeCreate({
      Name: 'hostroot', Driver: 'local',
      DriverOpts: { type: 'none', device: '/', o: 'bind' },
    })).toMatch(/bind-backed/i);
  });

  it('weigert varianten: alleen o=bind, alleen device, of type=none', () => {
    expect(validateVolumeCreate({ Driver: 'local', DriverOpts: { o: 'bind' } })).toMatch(/bind-backed/i);
    expect(validateVolumeCreate({ Driver: 'local', DriverOpts: { device: '/etc' } })).toMatch(/bind-backed/i);
    expect(validateVolumeCreate({ Driver: 'local', DriverOpts: { type: 'none' } })).toMatch(/bind-backed/i);
  });

  it('is case-insensitief op sleutels en waarden', () => {
    expect(validateVolumeCreate({ Driver: 'LOCAL', DriverOpts: { O: 'BIND' } })).toMatch(/bind-backed/i);
  });
});
