/** Read dropped directories without losing relative provenance paths. */
export async function folderFiles(entries: FileSystemEntry[], cap = 20_000): Promise<File[]> {
  const files: File[] = []
  let visited = 0
  const walk = async (entry: FileSystemEntry, parent: string): Promise<void> => {
    if (++visited > cap) throw new Error(`Folder exceeds ${cap.toLocaleString()} entries. Split it into smaller packages.`)
    const path = parent ? `${parent}/${entry.name}` : entry.name
    if (entry.isFile) {
      const file = await new Promise<File>((resolve, reject) => (entry as FileSystemFileEntry).file(resolve, reject))
      Object.defineProperty(file, 'webkitRelativePath', { value: path })
      files.push(file)
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      while (true) {
        const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject))
        if (!batch.length) break
        for (const child of batch) await walk(child, path)
      }
    }
  }
  for (const entry of entries) await walk(entry, '')
  return files
}
