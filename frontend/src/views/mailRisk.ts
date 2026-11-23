/** The severity a mail's risk score is shown with, in the bands the mails table colours its rows by. */
export const riskSev = (risk: number) => (risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 40 ? 'medium' : risk >= 20 ? 'low' : 'info')
