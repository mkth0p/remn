import { useCallback, useEffect, useState } from 'react'
import { Badge, Dot, Tabs } from '../components/ui'
import { IconCheck, IconEdit, IconExternal, IconPlus, IconTrash } from '../components/Icons'
import { addNote, deleteNote, listNotes, updateNote } from '../data/caseNotes'
import type { CaseNote } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtTs, renderMarkdown } from '../util/format'

type Tab = 'timeline' | 'tasks' | 'notes'
const SEVS = ['critical', 'high', 'medium', 'low', 'info']

function toLocalInput(ms: number): string {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
}
function fromLocalInput(s: string): number | null {
  if (!s) return null
  const t = Date.parse(s.length === 16 ? s + ':00Z' : s + 'Z')
  return Number.isNaN(t) ? null : t
}

/**
 * Case notes: the curated timeline (entries added from findings, mails, events and chain
 * steps, or typed by hand), the task checklist and free-text notes. All three go into the
 * report.
 */
export function CaseView() {
  const kase = useStore((s) => s.currentCase)
  const setView = useStore((s) => s.setView)
  const setFocus = useStore((s) => s.setFocus)
  const [tab, setTab] = useState<Tab>('timeline')
  const [rows, setRows] = useState<CaseNote[]>([])
  const [editing, setEditing] = useState<{ id: number; text: string } | null>(null)
  const [draft, setDraft] = useState('')
  const [draftTs, setDraftTs] = useState(toLocalInput(Date.now()))
  const [draftSev, setDraftSev] = useState('info')
  const caseId = kase?.id
  const reload = useCallback(() => {
    if (caseId) listNotes(caseId).then(setRows)
  }, [caseId])
  useEffect(() => {
    reload()
    setEditing(null)
  }, [reload])
  if (!kase || !caseId) return null
  const timeline = rows.filter((r) => r.kind === 'timeline').sort((a, b) => a.ts - b.ts)
  const tasks = rows.filter((r) => r.kind === 'task').sort((a, b) => Number(a.done ?? false) - Number(b.done ?? false) || b.createdAt - a.createdAt)
  const notes = rows.filter((r) => r.kind === 'note').sort((a, b) => b.createdAt - a.createdAt)
  const openLink = (n: CaseNote) => {
    const l = n.link
    if (!l) return
    if (l.source === 'events' || l.source === 'mails') {
      setFocus({ source: l.source, id: Number(l.id) })
      setView(l.source)
    } else setView(l.source === 'chains' ? 'chains' : 'findings')
  }
  const add = async () => {
    const text = draft.trim()
    if (!text) return
    if (tab === 'timeline') {
      const ts = fromLocalInput(draftTs)
      if (ts == null) return toast('err', 'enter a time (UTC)')
      await addNote(caseId, 'timeline', text, { ts, severity: draftSev })
    } else await addNote(caseId, tab === 'tasks' ? 'task' : 'note', text)
    setDraft('')
    reload()
  }
  const saveEdit = async () => {
    if (!editing) return
    await updateNote(editing.id, { text: editing.text.trim() })
    setEditing(null)
    reload()
  }
  const remove = async (id: number) => {
    await deleteNote(id)
    reload()
  }
  const openTasks = tasks.filter((t) => !t.done).length
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Case notes</h1>
          <span className="sub">{timeline.length} timeline entr{timeline.length === 1 ? 'y' : 'ies'} · {openTasks} open task{openTasks === 1 ? '' : 's'} · {notes.length} note{notes.length === 1 ? '' : 's'} · everything here goes into the report</span>
        </div>
      </div>
      <Tabs tabs={[{ id: 'timeline' as Tab, label: <span>Timeline <span className="n">{timeline.length}</span></span> }, { id: 'tasks' as Tab, label: <span>Tasks <span className="n">{openTasks}</span></span> }, { id: 'notes' as Tab, label: <span>Notes <span className="n">{notes.length}</span></span> }]} active={tab} onChange={setTab} />
      <div className="querybar">
        <div className="row wrap" style={{ gap: 6 }}>
          {tab === 'timeline' && (
            <>
              <input type="datetime-local" className="input mono" value={draftTs} onChange={(e) => setDraftTs(e.target.value)} title="time of the event (UTC)" />
              <select className="select" value={draftSev} onChange={(e) => setDraftSev(e.target.value)}>{SEVS.map((s) => <option key={s} value={s}>{s}</option>)}</select>
            </>
          )}
          <div className="search"><input placeholder={tab === 'timeline' ? 'what happened at that time (Enter to add)' : tab === 'tasks' ? 'task to do (Enter to add)' : 'note (markdown, Enter to add; Shift+Enter for a new line)'} value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); add() } }} /></div>
          <button className="btn sm primary" onClick={add} disabled={!draft.trim()}><IconPlus /> add</button>
        </div>
        {tab === 'timeline' && <div className="hint">Findings, mails, events and chain steps have a "timeline" button that adds them here with a link back to the row.</div>}
      </div>
      <div className="view-body" style={{ padding: 0 }}>
        {tab === 'timeline' && (
          <div className="story">
            {!timeline.length && <div className="muted" style={{ padding: 24 }}>The curated timeline is empty. Add the events that matter from the Findings, Mails, Events or Chains pages, or type one above.</div>}
            {timeline.map((n) => (
              <div key={n.id} className="step" style={{ cursor: 'default', gridTemplateColumns: '150px 14px 1fr auto' }}>
                <span className="t">{fmtTs(n.ts)}</span>
                <Dot sev={n.severity ?? 'info'} />
                <span>
                  {editing?.id === n.id ? (
                    <div className="col" style={{ gap: 6 }}>
                      <textarea className="textarea" autoFocus value={editing?.text ?? ''} onChange={(e) => setEditing({ id: n.id!, text: e.target.value })} onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); saveEdit() } if (e.key === 'Escape') setEditing(null) }} />
                      <div className="row" style={{ gap: 6 }}><button className="btn sm primary" onClick={saveEdit}>save</button><button className="btn sm ghost" onClick={() => setEditing(null)}>cancel</button></div>
                    </div>
                  ) : (
                    <>
                      <div className="title" style={{ whiteSpace: 'pre-wrap' }}>{n.text}</div>
                      {n.link && <div className="sub">{n.link.source} {n.link.label ?? `#${n.link.id}`}</div>}
                    </>
                  )}
                </span>
                <span className="row" style={{ gap: 2 }}>
                  {n.link && <button className="btn icon ghost xs" title="open the linked row" onClick={() => openLink(n)}><IconExternal /></button>}
                  <button className="btn icon ghost xs" title="edit" onClick={() => setEditing({ id: n.id!, text: n.text })}><IconEdit /></button>
                  <button className="btn icon ghost xs" title="remove from the timeline" onClick={() => remove(n.id!)}><IconTrash /></button>
                </span>
              </div>
            ))}
          </div>
        )}
        {tab === 'tasks' && (
          <div className="story">
            {!tasks.length && <div className="muted" style={{ padding: 24 }}>No task yet. Typical entries: confirm the sender with the recipient, reset the account, block the domain, collect the host image.</div>}
            {tasks.map((n) => (
              <div key={n.id} className="step" style={{ cursor: 'default', gridTemplateColumns: '22px 1fr auto', opacity: n.done ? 0.55 : 1 }}>
                <label className="facet-item" style={{ padding: 0 }}><input type="checkbox" checked={Boolean(n.done)} onChange={(e) => updateNote(n.id!, { done: e.target.checked }).then(reload)} /><span className="box" /></label>
                <span>
                  {editing?.id === n.id ? (
                    <input className="input" autoFocus value={editing?.text ?? ''} onChange={(e) => setEditing({ id: n.id!, text: e.target.value })} onKeyDown={(e) => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') setEditing(null) }} onBlur={saveEdit} style={{ width: '100%' }} />
                  ) : (
                    <>
                      <div className="title" style={{ textDecoration: n.done ? 'line-through' : undefined }}>{n.text}</div>
                      <div className="sub">{n.done ? 'done' : 'open'} · {fmtTs(n.updatedAt)}</div>
                    </>
                  )}
                </span>
                <span className="row" style={{ gap: 2 }}>
                  {n.done ? <Badge sev="ok"><IconCheck /> done</Badge> : null}
                  <button className="btn icon ghost xs" title="edit" onClick={() => setEditing({ id: n.id!, text: n.text })}><IconEdit /></button>
                  <button className="btn icon ghost xs" title="delete" onClick={() => remove(n.id!)}><IconTrash /></button>
                </span>
              </div>
            ))}
          </div>
        )}
        {tab === 'notes' && (
          <div className="col" style={{ padding: 16, gap: 12 }}>
            {!notes.length && <div className="muted">No note yet. Notes take markdown and are printed in the report in this order.</div>}
            {notes.map((n) => (
              <div key={n.id} className="card col" style={{ gap: 6 }}>
                <div className="row" style={{ gap: 6 }}>
                  <span className="small mono muted">{fmtTs(n.createdAt)}{n.updatedAt !== n.createdAt ? ` · edited ${fmtTs(n.updatedAt)}` : ''}</span>
                  <span className="spacer" />
                  <button className="btn icon ghost xs" title="edit" onClick={() => setEditing({ id: n.id!, text: n.text })}><IconEdit /></button>
                  <button className="btn icon ghost xs" title="delete" onClick={() => remove(n.id!)}><IconTrash /></button>
                </div>
                {editing?.id === n.id ? (
                  <div className="col" style={{ gap: 6 }}>
                    <textarea className="textarea" autoFocus style={{ minHeight: 120 }} value={editing?.text ?? ''} onChange={(e) => setEditing({ id: n.id!, text: e.target.value })} onKeyDown={(e) => { if (e.key === 'Escape') setEditing(null) }} />
                    <div className="row" style={{ gap: 6 }}><button className="btn sm primary" onClick={saveEdit}>save</button><button className="btn sm ghost" onClick={() => setEditing(null)}>cancel</button></div>
                  </div>
                ) : (
                  <div className="md" dangerouslySetInnerHTML={{ __html: renderMarkdown(n.text) }} />
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
