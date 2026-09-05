/**
 * Light / dark theme switch. The choice is stored per browser (localStorage) and applied as
 * `data-theme` on <html>, which theme.css keys its tokens on. index.html applies the stored value
 * before the first paint so a dark session never flashes light.
 */
export type Theme = 'light' | 'dark'

const KEY = 'remn-theme'

export function storedTheme(): Theme | null {
  try {
    const v = typeof localStorage !== 'undefined' ? localStorage.getItem(KEY) : null
    return v === 'dark' || v === 'light' ? v : null
  } catch {
    return null
  }
}

export function systemTheme(): Theme {
  try {
    return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

export function currentTheme(): Theme {
  return storedTheme() ?? systemTheme()
}

export function applyTheme(theme: Theme): void {
  if (typeof document === 'undefined') return
  document.documentElement.dataset.theme = theme
  const meta = document.querySelector('meta[name="color-scheme"]')
  if (meta) meta.setAttribute('content', theme)
}

export function setTheme(theme: Theme): void {
  try {
    localStorage.setItem(KEY, theme)
  } catch {
    /* private mode: the choice lasts for the session */
  }
  applyTheme(theme)
}
