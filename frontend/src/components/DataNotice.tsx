import type { Deployment } from '../data/deployment'
import { safeHref } from '../util/safe'

/**
 * What happens to a file added here, in the order it happens. Shown before the first upload to a
 * parser on another machine, and kept in Settings. Every sentence is something the server does or
 * is configured to do; docs/security.md has the detail and the limits.
 */
export function DataNotice({ dep }: { dep: Deployment }) {
  if (dep.tier === 'this-machine')
    return (
      <div className="col small" style={{ gap: 6 }}>
        <p>{dep.parsing}</p>
        <p>{dep.storage}</p>
      </div>
    )
  return (
    <div className="col small" style={{ gap: 6 }}>
      <ol className="plain-list" style={{ margin: 0, paddingLeft: 18 }}>
        <li>Your browser computes each file's SHA-256 before anything is sent.</li>
        {dep.tier === 'uploaded-not-kept' ? (
          <>
            <li>
              The file is uploaded to <b>{dep.host}</b>
              {dep.isolated ? ', which holds it in memory (a RAM-backed staging area, never its disk) while it parses it' : ', which stages it while it parses it'}, and deletes it when the parse ends.{' '}
              {dep.abandonedMinutes ? `An upload that is abandoned is removed within ${dep.abandonedMinutes} minutes.` : ''}
            </li>
            <li>
              The server keeps no copy, no rows, no case and no database, and its log holds no file names and no text from your evidence. It makes no lookups and runs no model of its own.
              {dep.isolated ? ' It has no network route off its host, so nothing can be sent to third parties.' : ''}
            </li>
          </>
        ) : (
          <li>
            The file is uploaded to <b>{dep.host}</b>, the REMN server your organisation runs, and parsed there. What that server keeps depends on how it is run; ask its operator.
          </li>
        )}
        <li>{dep.storage}</li>
        <li>
          The server runs build{' '}
          <a href={safeHref(dep.source)} target="_blank" rel="noreferrer noopener" className="mono">
            {dep.build || 'unknown'}
          </a>
          ; that link is its exact source.{dep.mismatch ? ` This page is build ${dep.pageBuild}, from a different commit.` : ''}
        </li>
      </ol>
      <div className="hint">To keep evidence off every machine but your own, run REMN locally: one command from the repository, and the same interface on 127.0.0.1.</div>
    </div>
  )
}
