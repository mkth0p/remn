/** The build of this page, `version+commit`, set by vite.config.ts. */
declare const __REMN_BUILD__: string

/** The committed rule measure, read by vite.config.ts at build time. */
declare module 'virtual:rule-measure' {
  const figures: import('./data/measureFigures').MeasureFigures
  export default figures
}
