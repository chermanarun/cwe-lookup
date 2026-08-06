/**
 * Maps internal/scanner-style vulnerability IDs (e.g. from a SAST/SCA rule
 * set) to the CWE ID that best represents that finding. This lets an
 * engineer type "SQL-INJ-001" and get exactly the same result - local
 * cache, live MITRE API, or synthesized fallback - as searching "CWE-89"
 * directly. No duplicate content is maintained; this is a pure alias layer
 * in front of the existing fetchCweDetails() pipeline.
 *
 * A handful of these (see INFRA_BEST_EFFORT_IDS) are infrastructure,
 * cloud-config, or supply-chain findings rather than a single code-level
 * weakness. CWE doesn't have a clean 1:1 category for "public S3 bucket" or
 * "container running as root", so those map to the closest-fit CWE. Expect
 * the vulnerable/fixed code tabs for those to read as generic - the
 * underlying issue is a config/process problem, not a code pattern.
 */
export const vulnAliases = {
  'SQL-INJ-001': 'CWE-89',
  'XSS-001': 'CWE-79',
  'CMD-INJ-001': 'CWE-78',
  'SECRET-001': 'CWE-798',
  'PATH-TRV-001': 'CWE-22',
  'DESER-001': 'CWE-502',
  'BUF-OVF-001': 'CWE-120',
  'XXE-001': 'CWE-611',
  'CRYPTO-001': 'CWE-327',
  'AUTH-001': 'CWE-287',
  'RACE-001': 'CWE-362',
  'CSRF-001': 'CWE-352',
  'INT-OVF-001': 'CWE-190',
  'FMT-STR-001': 'CWE-134',
  'LDAP-001': 'CWE-90',
  'SSRF-001': 'CWE-918',
  'NOLOG-001': 'CWE-778',
  'PROTO-001': 'CWE-1321',
  'TEMPL-001': 'CWE-1336',
  'REDOS-001': 'CWE-1333',
  'MASSA-001': 'CWE-915',
  'CERT-001': 'CWE-295',
  'TIMING-001': 'CWE-208',
  'FILEPERM-001': 'CWE-732',
  'ARBEXEC-001': 'CWE-94',
  'DOSLARGE-001': 'CWE-400',
  'HEADINJ-001': 'CWE-113',
  'TMPFILE-001': 'CWE-377',
  'ZIPBOMB-001': 'CWE-409',
  'SSJI-001': 'CWE-94',
  'ERRDISC-001': 'CWE-209',
  'COOKIE-SEC-001': 'CWE-614',
  'CLICKJACK-001': 'CWE-1021',
  'CORS-001': 'CWE-942',
  'JWT-001': 'CWE-347',
  'DEPS-CONF-001': 'CWE-1104',
  'LOG4J-001': 'CWE-502',
  'SPRING-EL-001': 'CWE-917',
  'SESSION-FIX-001': 'CWE-384',
  'STRUTS-001': 'CWE-917',
  'S3-PUBLIC-001': 'CWE-16',
  'DOCKER-ROOT-001': 'CWE-250',
  'K8S-RBAC-001': 'CWE-284',
  'CICD-INJ-001': 'CWE-77',
  'TERRAFORM-SEC-001': 'CWE-16',
  'API-BOLA-001': 'CWE-639',
  'API-EXPOSURE-001': 'CWE-200',
  'API-RATELIM-001': 'CWE-770',
  'API-GRAPHQL-001': 'CWE-400',
  'API-JWT-EXP-001': 'CWE-613',
  'DB-STOREDPROC-001': 'CWE-89',
  'DB-BLIND-001': 'CWE-89',
  'DB-REDIS-001': 'CWE-1188',
  'MOBILE-STORAGE-001': 'CWE-922',
  'MOBILE-CERT-001': 'CWE-295',
  'MOBILE-DEEPLINK-001': 'CWE-940'
};

/**
 * IDs whose mapping is a best-effort "closest fit" rather than an exact
 * match, because the underlying finding is an infra/config/supply-chain
 * issue rather than a single CWE code weakness.
 */
export const INFRA_BEST_EFFORT_IDS = new Set([
  'DEPS-CONF-001',
  'LOG4J-001',
  'STRUTS-001',
  'S3-PUBLIC-001',
  'DOCKER-ROOT-001',
  'K8S-RBAC-001',
  'CICD-INJ-001',
  'TERRAFORM-SEC-001'
]);

export function resolveVulnAlias(input) {
  if (!input) return null;
  const key = input.trim().toUpperCase();
  return vulnAliases[key] || null;
}

export function isBestEffortAlias(input) {
  if (!input) return false;
  return INFRA_BEST_EFFORT_IDS.has(input.trim().toUpperCase());
}

export function searchVulnAliases(query) {
  if (!query || !query.trim()) return [];
  const q = query.trim().toUpperCase();
  return Object.keys(vulnAliases)
    .filter((key) => key.includes(q))
    .slice(0, 6)
    .map((key) => ({ id: key, cweId: vulnAliases[key], isBestEffort: INFRA_BEST_EFFORT_IDS.has(key) }));
}
