import { useRef, useState, type ReactNode } from 'react'
import { classNames } from '../util/format'
import { folderFiles } from '../data/folder'

export function Dropzone({
  onFiles,
  accept,
  children,
  multiple = true,
  compact,
  allowFolders,
}: {
  onFiles: (files: File[]) => void
  accept?: string
  children?: ReactNode
  multiple?: boolean
  compact?: boolean
  allowFolders?: boolean
}) {
  const [over, setOver] = useState(false)
  const [error, setError] = useState('')
  const [reading, setReading] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const folder = useRef<HTMLInputElement>(null)
  return (
    <div
      className={classNames('dropzone', over && 'over')}
      style={compact ? { padding: 12 } : undefined}
      onClick={() => input.current?.click()}
      onDragOver={(e) => {
        e.preventDefault()
        setOver(true)
      }}
      onDragLeave={() => setOver(false)}
      onDrop={async (e) => {
        e.preventDefault()
        setOver(false)
        const files = Array.from(e.dataTransfer.files)
        const entries = allowFolders
          ? Array.from(e.dataTransfer.items)
              .map((item) => item.webkitGetAsEntry?.())
              .filter((entry): entry is FileSystemEntry => !!entry)
          : []
        setError('')
        if (entries.some((entry) => entry.isDirectory)) {
          setReading(true)
          try {
            const all = await folderFiles(entries)
            if (all.length) onFiles(all)
          } catch (err) {
            setError((err as Error).message)
          } finally {
            setReading(false)
          }
        } else if (files.length) onFiles(multiple ? files : files.slice(0, 1))
      }}
    >
      <input
        ref={input}
        type="file"
        multiple={multiple}
        accept={accept}
        style={{ display: 'none' }}
        onChange={(e) => {
          const files = Array.from(e.target.files ?? [])
          if (files.length) onFiles(files)
          e.target.value = ''
        }}
      />
      {children ?? (
        <>
          <div className="big">drop evidence here</div>
          <div className="small" style={{ marginTop: 4 }}>
            Investigation packages (.zip / .tar) · .evtx · .pst / .ost · .msg · .eml · .mbox · M365 exports — or click to browse
          </div>
        </>
      )}
      {allowFolders && (
        <>
          <input
            type="file"
            multiple
            ref={(el) => {
              folder.current = el
              el?.setAttribute('webkitdirectory', '')
            }}
            style={{ display: 'none' }}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => {
              const files = Array.from(e.target.files ?? [])
              if (files.length > 20_000) setError('Folder exceeds 20,000 files. Split it into smaller packages.')
              else if (files.length) {
                setError('')
                onFiles(files)
              }
              e.target.value = ''
            }}
          />
          <button
            className="btn sm"
            style={{ marginTop: 10 }}
            disabled={reading}
            onClick={(e) => {
              e.stopPropagation()
              folder.current?.click()
            }}
          >
            {reading ? 'Reading folder…' : 'Import folder contents'}
          </button>
          <div className="small muted" style={{ marginTop: 6 }}>
            Folders import as individual evidence files with relative paths. Use a ZIP to keep one package inventory and collection manifest.
          </div>
        </>
      )}
      {error && (
        <div role="alert" style={{ color: 'var(--danger)' }}>
          {error}
        </div>
      )}
    </div>
  )
}
