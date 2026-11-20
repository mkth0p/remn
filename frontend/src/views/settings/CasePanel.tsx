import { useEffect, useState } from 'react'
import { getDb, type Case } from '../../db/schema'
import { toast, useStore } from '../../state/store'

/** The case's name, analyst and notes; a blank name keeps the one it had. */
export function CasePanel({ kase }: { kase: Case }) {
  const setCurrentCase = useStore((s) => s.setCurrentCase)
  const [name, setName] = useState(kase.name ?? '')
  const [analyst, setAnalyst] = useState(kase.analyst ?? '')
  const [notes, setNotes] = useState(kase.notes ?? '')
  useEffect(() => {
    setName(kase.name ?? '')
    setAnalyst(kase.analyst ?? '')
    setNotes(kase.notes ?? '')
  }, [kase.id, kase.name, kase.analyst, kase.notes])
  const saveMeta = async () => {
    await getDb().cases.update(kase.id!, { name: name.trim() || kase.name, analyst: analyst.trim(), notes, updatedAt: Date.now() })
    setCurrentCase({ ...kase, name: name.trim() || kase.name, analyst: analyst.trim(), notes })
    toast('ok', 'case saved')
  }
  return (
    <div className="panel">
      <div className="panel-h">case</div>
      <div className="panel-b col">
        <label className="field">
          <span>name</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        <label className="field">
          <span>analyst</span>
          <input className="input" value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="recorded in the chain of custody" />
        </label>
        <label className="field">
          <span>notes</span>
          <textarea className="textarea" value={notes} onChange={(e) => setNotes(e.target.value)} />
        </label>
        <div className="row">
          <button className="btn primary sm" onClick={saveMeta}>
            save
          </button>
        </div>
      </div>
    </div>
  )
}
