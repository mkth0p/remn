import { useEffect, useState } from 'react'
import { getDb } from '../db/schema'
import { addCitation, loadScenarioChoice, rowCitation } from '../data/questions/answers'
import { questionsOf } from '../data/questions/catalog'
import { toast, useStore } from '../state/store'
import { IconQuestion } from './Icons'

/**
 * "Cite for a question" on an event or mail: the row, by its record key, goes to the answer of the
 * question the analyst is working on (opened from the Questions page), or of one picked here.
 * Nothing shows when the case has no scenario chosen.
 */
export function CiteForQuestion({ source, row }: { source: 'events' | 'mails'; row: Record<string, unknown> }) {
  const kase = useStore((s) => s.currentCase)
  const active = useStore((s) => s.activeQuestion)
  const [scenarios, setScenarios] = useState<string[]>([])
  const [cited, setCited] = useState<string | null>(null)
  useEffect(() => {
    if (kase?.id) loadScenarioChoice(kase.id).then(setScenarios)
  }, [kase?.id])
  const questions = questionsOf(scenarios)
  if (!kase?.id || !questions.length || typeof row.id !== 'number') return null
  const cite = async (questionId: string) => {
    const evidence = typeof row.evidenceId === 'number' ? await getDb().evidence.get(row.evidenceId) : undefined
    await addCitation(kase.id!, questionId, rowCitation(row, source, evidence))
    setCited(questionId)
    toast('ok', `cited for ${questionId}`)
  }
  const target = questions.find((q) => q.id === active)
  if (target)
    return (
      <button className={'btn sm' + (cited === target.id ? ' active' : '')} onClick={() => cite(target.id)} title={`cite this record in the answer to ${target.id}: ${target.name}`}>
        <IconQuestion /> cite for {target.id}
      </button>
    )
  return (
    <select
      className="select small"
      aria-label="Cite for a question"
      value=""
      title="cite this record in the answer to one of the case's questions"
      onChange={(e) => e.target.value && cite(e.target.value)}
      style={{ maxWidth: 170 }}
    >
      <option value="">{cited ? `cited for ${cited}` : 'cite for question…'}</option>
      {questions.map((q) => (
        <option key={q.id} value={q.id}>
          {q.id} {q.name.length > 70 ? `${q.name.slice(0, 69)}…` : q.name}
        </option>
      ))}
    </select>
  )
}
