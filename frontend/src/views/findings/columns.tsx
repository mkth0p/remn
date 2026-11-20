/** The columns of the Findings page's two tables: the flat list of findings and the incidents. */
import type { Column } from '../../components/VirtualTable'
import { Badge, Sev, SevBar } from '../../components/ui'
import type { MeasureReading } from '../../data/ruleMeasures'
import { byPriority, type Priority } from '../../data/findingPriority'
import type { Finding } from '../../db/schema'
import { sevCounts, type Incident } from '../../rules/incidents'
import { fmtNum, fmtTs, timeColumnWidth, tzLabel } from '../../util/format'
import { KIND_LABEL } from './model'
import { FindingSeverity, LeadBadge, PriorityCell, StatusBadge } from './parts'

export function findingColumns({ scores, membership, readings }: { scores: Map<string, Priority>; membership: Map<number, unknown>; readings: Map<string, MeasureReading> }): Column<Finding>[] {
  return [
    { key: 'priority', label: 'priority', width: 170, render: (r) => <PriorityCell p={scores.get(r.key)} /> },
    { key: 'severity', label: 'severity', width: 104, render: (r) => <FindingSeverity finding={r} /> },
    {
      key: 'title',
      label: 'finding',
      width: 'minmax(280px, 1.6fr)',
      render: (r) => (
        <span className="sans ellipsis" title={r.description}>
          {r.title}
          {r.escalation ? <span className="muted"> · {r.escalation}</span> : null}
          {r.id != null && membership.has(r.id) && r.ruleId !== 'chain' ? (
            <>
              {' '}
              <Badge sev="outline" title="its rows are steps of an attack chain: decided with the chain on the Review page">
                chain
              </Badge>
            </>
          ) : null}
          {r.chainUnlinked ? (
            <>
              {' '}
              <Badge sev="outline" title="taken out of its attack chain: decided on its own">
                unlinked
              </Badge>
            </>
          ) : null}
          <LeadBadge reading={readings.get(r.ruleId)} />
        </span>
      ),
    },
    {
      key: 'entities',
      label: 'entities',
      width: 'minmax(220px, 1fr)',
      render: (r) =>
        Object.entries(r.entities)
          .map(([k, v]) => `${k}=${v}`)
          .join(' · '),
    },
    {
      key: 'attack',
      label: 'att&ck',
      width: 130,
      render: (r) => (
        <span className="row" style={{ gap: 4 }}>
          {r.attack.slice(0, 2).map((t) => (
            <Badge key={t} sev="outline">
              {t}
            </Badge>
          ))}
          {r.attack.length > 2 ? <span className="muted">+{r.attack.length - 2}</span> : null}
        </span>
      ),
    },
    { key: 'source', label: 'source', width: 70 },
    { key: 'count', label: 'rows', width: 64, render: (r) => fmtNum(r.count) },
    { key: 'ts', label: `first seen (${tzLabel()})`, width: timeColumnWidth(150), render: (r) => fmtTs(r.ts) },
    { key: 'status', label: 'status', width: 110, render: (r) => <StatusBadge s={r.status} /> },
  ]
}

export function incidentColumns({ scores }: { scores: Map<string, Priority> }): Column<Incident>[] {
  return [
    { key: 'priority', label: 'priority', width: 170, render: (r) => <PriorityCell p={scores.get([...r.findings].sort(byPriority(scores))[0]?.key ?? '')} /> },
    {
      key: 'severity',
      label: 'severity',
      width: 104,
      render: (r) => (
        <span title={r.kind !== 'chain' && r.findings.some((f) => f.severityOverride) ? 'Includes review severity overrides; open the incident to see the rule severities or reset.' : undefined}>
          <Sev sev={r.severity}>
            {r.severity}
            {r.kind !== 'chain' && r.findings.some((f) => f.severityOverride) ? '*' : ''}
          </Sev>
        </span>
      ),
    },
    {
      key: 'title',
      label: 'incident',
      width: 'minmax(300px, 1.8fr)',
      render: (r) => (
        <span className="sans ellipsis" title={r.subtitle}>
          <span style={{ color: 'var(--fg-1)' }}>{r.title}</span>
          <span className="muted"> · {r.subtitle}</span>
        </span>
      ),
    },
    { key: 'kind', label: 'kind', width: 74, render: (r) => KIND_LABEL[r.kind] },
    {
      key: 'findings',
      label: 'findings',
      width: 130,
      render: (r) => (
        <span className="row" style={{ gap: 6 }}>
          <span className="mono">{fmtNum(r.findings.length)}</span>
          <span style={{ width: 70 }}>
            <SevBar counts={sevCounts(r.findings)} />
          </span>
        </span>
      ),
    },
    { key: 'rules', label: 'rules', width: 56, render: (r) => fmtNum(r.rules.length) },
    { key: 'ts', label: `first seen (${tzLabel()})`, width: timeColumnWidth(150), render: (r) => fmtTs(r.ts) },
    { key: 'tsEnd', label: `last (${tzLabel()})`, width: timeColumnWidth(150), render: (r) => (r.tsEnd && r.tsEnd !== r.ts ? fmtTs(r.tsEnd) : '') },
    { key: 'status', label: 'status', width: 110, render: (r) => <StatusBadge s={r.status} /> },
  ]
}
