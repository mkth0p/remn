import { expect, it } from 'vitest'
import { folderFiles } from './folder'

function file(name: string): FileSystemEntry {
  return { name, isFile: true, isDirectory: false, file: (done: (f: File) => void) => done(new File(['x'], name)) } as unknown as FileSystemEntry
}
function folder(name: string, batches: FileSystemEntry[][]): FileSystemEntry {
  return {
    name,
    isFile: false,
    isDirectory: true,
    createReader: () => {
      let i = 0
      return { readEntries: (done: (e: FileSystemEntry[]) => void) => done(batches[i++] ?? []) }
    },
  } as unknown as FileSystemEntry
}
it('reads every directory batch and preserves full relative paths', async () => {
  const result = await folderFiles([folder('Package', [[folder('Processes', [[file('data.csv')]])], [file('summary.csv')]])])
  expect(result.map((f) => f.webkitRelativePath)).toEqual(['Package/Processes/data.csv', 'Package/summary.csv'])
})
it('rejects an oversized tree instead of silently dropping members', async () => {
  await expect(folderFiles([folder('Package', [[file('a'), file('b')]])], 2)).rejects.toThrow('exceeds')
})
