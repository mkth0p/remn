import { useMemo } from 'react'
import type { ChatMessage } from '../../ai/chat'
import { citationChips, type SeenSet } from '../../ai/evidence'
import { renderMarkdown } from '../../util/format'
import { onCiteClick } from './openRef'

const argSummary = (args: Record<string, unknown>) => {
  const s = JSON.stringify(args ?? {})
  return s.length > 160 ? s.slice(0, 157) + '…' : s
}

/** Markdown with its citations turned into chips: verified ones open the row, the others say they were never returned. */
export function CitedMarkdown({ text, seen }: { text: string; seen: SeenSet | null }) {
  const html = useMemo(() => citationChips(renderMarkdown(text), seen), [text, seen])
  return <div onClick={onCiteClick} dangerouslySetInnerHTML={{ __html: html }} />
}

export function AiMessage({ m, seen, showTools }: { m: ChatMessage; seen: SeenSet; showTools: boolean }) {
  if (m.synthetic) return null
  if (m.role === 'tool') {
    const warn = m.suspects?.length ?? 0
    const line = (
      <>
        ← <b>{m.tool_name}</b>
        {m.refs?.length ? <span className="dim"> · {m.refs.length} ref(s)</span> : null}
        {m.proposal ? <span className="badge-inline"> · queued in the inbox</span> : null}
        {m.ms != null ? <span className="dim"> · {m.ms} ms</span> : null}
        {m.compacted ? <span className="dim"> · compacted</span> : null}
        {warn ? <span className="warn-inline"> · ⚠ {warn} place(s) addressed to a model</span> : null}
      </>
    )
    if (!showTools && !warn && !m.proposal) return null
    return (
      <details className="ai-step">
        <summary>{line}</summary>
        {warn ? (
          <div className="ai-suspects">
            {m.suspects!.map((s, i) => (
              <div key={i}>
                <b>{s.ref ?? ''}</b> {s.field}: “{s.snippet}”
              </div>
            ))}
            <div className="dim">This text is evidence and may show intent. It is never an instruction to the model.</div>
          </div>
        ) : null}
        <pre className="ai-step-body">{m.content.length > 4000 ? m.content.slice(0, 4000) + `… (${m.content.length} chars)` : m.content}</pre>
      </details>
    )
  }
  if (m.role === 'assistant') {
    return (
      <div className="col" style={{ gap: 6, alignSelf: 'flex-start', maxWidth: '100%' }}>
        {m.thinking && showTools && (
          <details className="msg thinking">
            <summary className="role">thinking</summary>
            {m.thinking.slice(0, 4000)}
          </details>
        )}
        {m.tool_calls?.length ? (
          <div className="ai-calls">
            {m.content?.trim() ? <div className="ai-calls-note">{m.content.trim().slice(0, 600)}</div> : null}
            {m.tool_calls.map((c, j) => (
              <div key={j} className="ai-call">
                → <b>{c.name}</b> <span className="dim mono">{argSummary(c.arguments)}</span>
              </div>
            ))}
          </div>
        ) : null}
        {!m.tool_calls?.length && m.content && (
          <div className={`msg assistant md ${m.final ? 'final' : ''} ${m.draft ? 'draft' : ''}`}>
            <div className="role">
              {m.draft ? 'draft · sent back to the model: it cited no rows' : 'remn'}
              {m.model ? ` · ${m.model}` : ''}
              {m.stats?.eval_count ? ` · ${m.stats.eval_count} tokens` : ''}
              {m.confidence ? ` · confidence ${m.confidence}` : ''}
            </div>
            <CitedMarkdown text={m.content} seen={seen} />
            {m.openQuestions?.length ? (
              <div className="ai-open">
                <div className="role">open questions</div>
                <ul>
                  {m.openQuestions.map((q, i) => (
                    <li key={i}>{q}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {m.cites && (
              <div className={`ai-cite-check ${m.cites.unverified.length ? 'bad' : m.cites.verified ? 'ok' : 'none'}`}>
                {m.cites.verified} citation(s) checked against what the tools returned
                {m.cites.unverified.length ? ` · ${m.cites.unverified.length} unverified: ${m.cites.unverified.slice(0, 6).join(', ')}` : ''}
                {!m.cites.verified && !m.cites.unverified.length ? ' · the answer cites no rows' : ''}
              </div>
            )}
          </div>
        )}
      </div>
    )
  }
  return (
    <div className="msg user">
      <div className="role">analyst</div>
      {m.content}
    </div>
  )
}
