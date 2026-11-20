import { Sev } from '../../components/ui'
import { fmtNum } from '../../util/format'
import { attackHref } from '../../util/safe'
import type { TechniqueHits } from './useFindingsQueue'

/** The ATT&CK techniques the findings name, most found first, each with a way to its findings. */
export function AttackTab({ attack, findings, onShow }: { attack: TechniqueHits; findings: number; onShow: (technique: string) => void }) {
  return (
    <div className="view-body" style={{ paddingTop: 12 }}>
      <div className="panel">
        <div className="panel-h">
          Techniques observed{' '}
          <span className="muted">
            · {attack.hits.length} technique(s) across {fmtNum(findings)} finding(s)
          </span>
        </div>
        <table className="table">
          <thead>
            <tr>
              <th>technique</th>
              <th>worst severity</th>
              <th>findings</th>
              <th>rules that fired</th>
              <th>enabled rules mapped</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {attack.hits.map((h) => (
              <tr key={h.id}>
                <td>{h.id}</td>
                <td>
                  <Sev sev={h.worst} />
                </td>
                <td>{fmtNum(h.findings)}</td>
                <td>{h.rules.size}</td>
                <td>{attack.enabledByTechnique.get(h.id) ?? 0}</td>
                <td className="sans">
                  {attackHref(h.id) ? (
                    <a href={attackHref(h.id)} target="_blank" rel="noreferrer noopener">
                      attack.mitre.org
                    </a>
                  ) : (
                    <span className="muted">not a technique id</span>
                  )}{' '}
                  ·{' '}
                  <button className="btn link" onClick={() => onShow(h.id)}>
                    show findings
                  </button>
                </td>
              </tr>
            ))}
            {!attack.hits.length && (
              <tr>
                <td colSpan={6} className="muted sans">
                  no technique yet - run the rules
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
