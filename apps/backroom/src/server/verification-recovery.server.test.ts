import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { BackroomSession } from '../lib/auth.types'
import {
  RESUME_VERIFICATION_CONFIRMATION,
  resumeArtifactVerificationInputSchema,
  verificationReadinessSchema,
} from '../lib/admin.schemas'
import { fetchVerificationReadiness, resumeArtifactVerification } from './admin.service'
import {
  BACKROOM_READ_SCOPE,
  BACKROOM_WRITE_SCOPE,
  type McpGrantProps,
  createBackroomMcpServer,
} from './mcp.server'

// Sky v2, one of the four holds #2117 names, as the exact agent under review.
const AGENT_ID = '4bd43a0c-f8d4-4298-9b84-e7e75c6a6574'
const ATTEMPT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
const QUARANTINE_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
const RECOVERY_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
const ACTOR = 'peyton@omniaura.ai'
const SHA = 'ab'.repeat(32)
const MANIFEST = 'cd'.repeat(32)
const COMMITMENT = '1f'.repeat(32)

const session: BackroomSession = {
  version: 2,
  uid: 'staff-1',
  email: ACTOR,
  name: 'Staff User',
  picture: '',
  accessLevel: 'write',
  issuedAt: Date.now(),
  expiresAt: Date.now() + 7 * 24 * 60 * 60_000,
}

async function connect(scopes: Array<string>) {
  const props: McpGrantProps = { session, scopes, clientName: 'Test client' }
  const server = createBackroomMcpServer(props)
  const client = new Client({ name: 'backroom-test', version: '1.0.0' })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return { client, server }
}

const recovery = {
  recovery_id: RECOVERY_ID,
  agent_id: AGENT_ID,
  quarantine_id: QUARANTINE_ID,
  source_attempt_id: ATTEMPT_ID,
  artifact_sha256: SHA,
  policy_version: 13,
  manifest_digest: MANIFEST,
  image_digest: null,
  state: 'queued' as const,
  outstanding_checks: ['archive_and_sha', 'health'],
  reused_evidence: [],
  challenge_commitment: COMMITMENT,
  challenge_manifest_version: 1,
  independent_worker_required: true,
  excluded_screener_hotkeys: ['5Screener'],
  claimed_by: null,
  claimed_at: null,
  dispatch_deadline: null,
  outcome: null,
  failure_domain: null,
  completed_checks: null,
  refuted_leads: null,
  reason: 'court failed without a finding; resume mandatory verification',
  actor: ACTOR,
  created_at: '2026-09-23T06:00:00Z',
  updated_at: '2026-09-23T06:00:00Z',
}

const readiness = {
  agent_id: AGENT_ID,
  agent_status: 'quarantined',
  artifact_sha256: SHA,
  policy_version: 13,
  quarantine_id: QUARANTINE_ID,
  quarantine_status: 'active',
  quarantine_reason_code: 'adjudicated-source-review-escalate',
  has_established_finding: false,
  is_non_decisive_hold: true,
  evidence_bindings: {
    artifact_sha256: SHA,
    // No screened image is pinned, and the profile and opaque manifest were
    // never recorded. All three stay explicit rather than null.
    image_digest: 'not_recorded',
    policy_digest: MANIFEST,
    opaque_manifest_digest: 'not_recorded',
    verification_profile_digest: 'not_recorded',
    challenge_manifest_digest: 'not_recorded',
  },
  mandatory_checks: [
    {
      check_id: 'archive_and_sha',
      ordinal: 1,
      lane: 'artifact' as const,
      title: 'archive and SHA verification',
      state: 'not_recorded' as const,
    },
  ],
  outstanding_mandatory_checks: ['archive_and_sha'],
  integrity_rules: [{ rule_id: 'I5', state: 'not_recorded' as const, private_tests_required: null }],
  security_rules: [{ rule_id: 'S1', state: 'not_recorded' as const, private_tests_required: null }],
  opaque_roles: [
    {
      rule_id: 'authoritative_planner',
      state: 'not_recorded' as const,
      private_tests_required: true,
    },
  ],
  private_paired_required: null,
  last_court_failure: {
    attempt_id: ATTEMPT_ID,
    reason_code: 'adjudicated-source-review-escalate',
    stage: 'response',
    diagnostic: {
      error_class: 'ValueError',
      escalation_code: 'adjudicator-failed',
      timeout_stage: 'response',
      http_status: null,
      elapsed_ms: 41_200,
      prompt_tokens: 1180,
      completion_tokens: 0,
      final_tool_call_returned: false,
      model: 'z-ai/glm-5.3-flash',
      provider: 'openrouter',
      upstream: 'sail-research',
      request_count: 0,
    },
  },
  attempts: [
    {
      attempt_id: ATTEMPT_ID,
      screener_hotkey: '5Screener',
      policy_version: 13,
      status: 'quarantined',
      reason_code: 'adjudicated-source-review-escalate',
      failure_provider: null,
      started_at: '2026-09-22T13:00:20Z',
      finished_at: '2026-09-22T13:05:35Z',
    },
  ],
  attempts_recorded: 1,
  distinct_workers: 1,
  published_retry_defaults: {
    artifact_failure_retries: 1,
    provider_failure_retries: 2,
    platform_failure_retries: 2,
    independent_worker_required_for_platform_or_provider: true,
    maximum_verification_window_hours: 24,
    provenance: 'policy-v13-published-defaults',
    enforced: false,
  },
  finalizer: {
    finalizer_state: 'not_configured' as const,
    finalizer_reason: 'no effective v13 finalizer deadline is deployed',
    verification_deadline: null,
    deadline_provenance: null,
    attempt_deadline: '2026-09-22T13:10:20Z',
    source: 'screening_verification_state' as const,
  },
  recovery: null,
  recovery_audit: [],
  evidence_sources: ['agents', 'screening_attempts'],
  generated_at: '2026-09-23T06:00:00Z',
}

const guards = {
  agentId: AGENT_ID,
  reason: 'court failed without a finding; resume mandatory verification',
  expectedSha256: SHA,
  expectedScoreCount: 0,
  expectedAttemptId: ATTEMPT_ID,
  expectedAttemptCount: 1,
  expectedQuarantineId: QUARANTINE_ID,
  expectedPolicyVersion: 13,
  expectedManifestDigest: MANIFEST,
  expectedImageDigest: null,
  confirmation: RESUME_VERIFICATION_CONFIRMATION,
}

afterEach(() => {
  vi.unstubAllGlobals()
  delete process.env.DITTO_ADMIN_API_TOKEN
})

describe('verification readiness read', () => {
  it('reads the exact-agent ledger with the operator actor recorded', async () => {
    process.env.DITTO_ADMIN_API_TOKEN = 'secret'
    const fetchMock = vi.fn().mockResolvedValue(Response.json(readiness))
    vi.stubGlobal('fetch', fetchMock)

    await expect(fetchVerificationReadiness({ agentId: AGENT_ID }, ACTOR)).resolves.toEqual(
      readiness,
    )
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(
      `https://platform-api.heyditto.ai/api/v1/admin/screening-submissions/${AGENT_ID}/verification-readiness`,
    )
    expect(init.method).toBe('GET')
    expect(init.headers).toEqual(
      expect.objectContaining({ 'X-Admin-Actor': ACTOR, Authorization: 'Bearer secret' }),
    )
  })

  it('refuses a ledger that reports unknown evidence as null', () => {
    // A null digest would let a reader treat missing evidence as inapplicable,
    // which is exactly the inference policy v13 forbids.
    const nulled = {
      ...readiness,
      evidence_bindings: { ...readiness.evidence_bindings, verification_profile_digest: null },
    }

    expect(() => verificationReadinessSchema.parse(nulled)).toThrow()
  })

  it('refuses a ledger that reports a check state outside the published set', () => {
    const invented = {
      ...readiness,
      mandatory_checks: [{ ...readiness.mandatory_checks[0], state: 'passed' }],
    }

    expect(() => verificationReadinessSchema.parse(invented)).toThrow()
  })
})

describe('bounded verification resume', () => {
  it('sends every pinned guard as the exact snake_case Platform body', async () => {
    process.env.DITTO_ADMIN_API_TOKEN = 'secret'
    const fetchMock = vi.fn().mockResolvedValue(
      Response.json({
        recovery,
        audit: [
          {
            event_id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
            event: 'authorized',
            actor: ACTOR,
            detail: { challenge_commitment: COMMITMENT },
            created_at: '2026-09-23T06:00:00Z',
          },
        ],
        idempotent: false,
        agent_status: 'quarantined',
        quarantine_status: 'active',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const result = await resumeArtifactVerification(guards, ACTOR)

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(
      `https://platform-api.heyditto.ai/api/v1/admin/screening-submissions/${AGENT_ID}/verification-recovery`,
    )
    expect(init.method).toBe('POST')
    expect(JSON.parse(String(init.body))).toEqual({
      reason: guards.reason,
      expected_sha256: SHA,
      expected_score_count: 0,
      expected_attempt_id: ATTEMPT_ID,
      expected_attempt_count: 1,
      expected_quarantine_id: QUARANTINE_ID,
      expected_policy_version: 13,
      expected_manifest_digest: MANIFEST,
      expected_image_digest: null,
      confirmation: RESUME_VERIFICATION_CONFIRMATION,
    })
    // The hold is reported unchanged, and only the commitment crosses the wire.
    expect(result.agent_status).toBe('quarantined')
    expect(result.quarantine_status).toBe('active')
    expect(result.recovery.challenge_commitment).toBe(COMMITMENT)
    expect(JSON.stringify(result)).not.toContain('challenge_seed')
  })

  it('refuses a wrong confirmation phrase, a missing guard, and an extra field', () => {
    expect(() =>
      resumeArtifactVerificationInputSchema.parse({ ...guards, confirmation: 'yes' }),
    ).toThrow()
    const { expectedManifestDigest: _omitted, ...withoutManifest } = guards
    expect(() => resumeArtifactVerificationInputSchema.parse(withoutManifest)).toThrow()
    expect(() =>
      resumeArtifactVerificationInputSchema.parse({ ...guards, forceClear: true }),
    ).toThrow()
  })

  it('requires an explicit image-digest guard rather than letting it default', () => {
    const { expectedImageDigest: _omitted, ...withoutImage } = guards

    expect(() => resumeArtifactVerificationInputSchema.parse(withoutImage)).toThrow()
  })
})

describe('verification recovery MCP surface', () => {
  it('serves the readiness ledger on a read-only grant', async () => {
    process.env.DITTO_ADMIN_API_TOKEN = 'secret'
    const fetchMock = vi.fn().mockResolvedValue(Response.json(readiness))
    vi.stubGlobal('fetch', fetchMock)
    const { client, server } = await connect([BACKROOM_READ_SCOPE])
    try {
      const response = await client.callTool({
        name: 'get_verification_readiness',
        arguments: { agentId: AGENT_ID },
      })

      expect(response.isError).not.toBe(true)
      const text = (response.content as Array<{ text: string }>)[0].text
      expect(JSON.parse(text).outstanding_mandatory_checks).toEqual(['archive_and_sha'])
      expect(text).toContain('not_recorded')
      expect(text).not.toContain('challenge_seed')
    } finally {
      await client.close()
      await server.close()
    }
  })

  it('refuses the resume on a read-only grant without reaching Platform', async () => {
    process.env.DITTO_ADMIN_API_TOKEN = 'secret'
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const { client, server } = await connect([BACKROOM_READ_SCOPE])
    try {
      const response = await client.callTool({
        name: 'resume_artifact_verification',
        arguments: guards,
      })

      expect(response.isError).toBe(true)
      expect(fetchMock).not.toHaveBeenCalled()
    } finally {
      await client.close()
      await server.close()
    }
  })

  it('authorizes the resume on a write grant and reports the hold unchanged', async () => {
    process.env.DITTO_ADMIN_API_TOKEN = 'secret'
    const fetchMock = vi.fn().mockResolvedValue(
      Response.json({
        recovery,
        audit: [],
        idempotent: false,
        agent_status: 'quarantined',
        quarantine_status: 'active',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const { client, server } = await connect([BACKROOM_READ_SCOPE, BACKROOM_WRITE_SCOPE])
    try {
      const response = await client.callTool({
        name: 'resume_artifact_verification',
        arguments: guards,
      })

      expect(response.isError).not.toBe(true)
      const body = JSON.parse((response.content as Array<{ text: string }>)[0].text)
      expect(body.recovery.state).toBe('queued')
      expect(body.agent_status).toBe('quarantined')
      expect(body.quarantine_status).toBe('active')
      expect(body.recovery.independent_worker_required).toBe(true)
    } finally {
      await client.close()
      await server.close()
    }
  })
})
