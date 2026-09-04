import { useRef, useState, type ReactNode } from 'react'
import { classNames } from '../util/format'

export function Dropzone({ onFiles, accept, children, multiple = true, compact }: { onFiles: (files: File[]) => void; accept?: string; children?: ReactNode; multiple?: boolean; compact?: boolean }) {
  const [over, setOver] = useState(false)
  const input = useRef<HTMLInputElement>(null)
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
      onDrop={(e) => {
        e.preventDefault()
        setOver(false)
        const files = Array.from(e.dataTransfer.files)
        if (files.length) onFiles(multiple ? files : files.slice(0, 1))
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
          <div className="small" style={{ marginTop: 4 }}>.evtx · .pst / .ost · .msg · .eml · .mbox · .zip of .eml — or click to browse</div>
        </>
      )}
    </div>
  )
}
