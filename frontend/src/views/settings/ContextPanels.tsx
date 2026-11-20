import { useState } from 'react'
import { ListInput, Toggle } from '../../components/ui'
import { getDb, type CaseSettings } from '../../db/schema'
import { toast } from '../../state/store'
import { getLocalTime, setLocalTime } from '../../util/format'

type Patch = (p: Partial<CaseSettings>) => void
const domain = (x: string) => x.toLowerCase().replace(/^@/, '')

/** Who the organisation is, for the mail rules: its domains, names and brands, and the senders and forwarders it trusts. */
export function OrganisationPanel({ s, patch, suggesting, onSuggest }: { s: CaseSettings; patch: Patch; suggesting: boolean; onSuggest: () => void }) {
  return (
    <div className="panel">
      <div className="panel-h">organisation context</div>
      <div className="panel-b col">
        <label className="field">
          <span>internal domains (one per line) - drives lookalike / spoof detection</span>
          <ListInput mono value={s.internalDomains} onChange={(v) => patch({ internalDomains: v.map(domain) })} placeholder={'company.com\ncompany.fr'} />
        </label>
        <label className="field">
          <span>VIP display names (CEO, CFO, IT admins…) - impersonation rule</span>
          <ListInput value={s.vipNames} onChange={(v) => patch({ vipNames: v })} placeholder={'Marie Lefevre\nJean Dupont'} />
        </label>
        <label className="field">
          <span>organisation display names (all staff, one per line) - employee-impersonation rules; the Sublime pack's $org_display_names</span>
          <ListInput value={s.orgDisplayNames ?? []} onChange={(v) => patch({ orgDisplayNames: v })} placeholder={'one display name per line'} />
        </label>
        <label className="field">
          <span>extra brands to protect (second-level labels)</span>
          <ListInput mono value={s.brands} onChange={(v) => patch({ brands: v.map((x) => x.toLowerCase()) })} placeholder={'mybank\nmysupplier'} />
        </label>
        <label className="field">
          <span>trusted senders (addresses or domains) - lower weak signals; some spoofing rules exempt them</span>
          <ListInput mono value={s.trustedSenders ?? []} onChange={(v) => patch({ trustedSenders: v.map(domain) })} placeholder={'notifications.supplier.com\nfacture@partenaire.fr'} />
        </label>
        <label className="field">
          <span>
            trusted ARC sealers (mailing lists and forwarders) - their verified ARC seal vouches for mail they forwarded; the internal domains always count. Applies to mail imported after the change.
          </span>
          <ListInput mono value={s.trustedArcSealers ?? []} onChange={(v) => patch({ trustedArcSealers: v.map(domain) })} placeholder={'lists.partner.org\ngoogle.com'} />
        </label>
        <div className="row">
          <button className="btn sm" onClick={onSuggest} disabled={suggesting}>
            {suggesting ? 'scanning…' : 'suggest trusted senders'}
          </button>
          <span className="small dim">known relays (Teams, GitHub…) are already built in when auth passes</span>
        </div>
        <div className="hint">
          After changing these settings, use Mails → rescore + refresh findings. Trust reduces weak signals; suspicious payloads retain their risk. Full reanalysis of missing attachment facts requires
          the original evidence.
        </div>
      </div>
    </div>
  )
}

/** The Windows rules' context: internal ranges, expected sign-in countries, admin and service accounts. */
export function WindowsPanel({ s, patch }: { s: CaseSettings; patch: Patch }) {
  return (
    <div className="panel">
      <div className="panel-h">windows context</div>
      <div className="panel-b col">
        <label className="field">
          <span>internal IP ranges (CIDR) - RDP/share rules exclude them</span>
          <ListInput mono value={s.internalIps} onChange={(v) => patch({ internalIps: v })} />
        </label>
        <label className="field">
          <span>expected sign-in countries (ISO codes) - Entra / M365 sign-in rules flag the rest</span>
          <ListInput mono value={s.expectedCountries ?? []} onChange={(v) => patch({ expectedCountries: v.map((x) => x.trim().toUpperCase()).filter(Boolean) })} placeholder={'FR\nDE\nUS'} />
        </label>
        <label className="field">
          <span>admin accounts (expected to have special privileges)</span>
          <ListInput mono value={s.adminAccounts} onChange={(v) => patch({ adminAccounts: v })} placeholder={'admin.jdoe\nsvc_backup'} />
        </label>
        <label className="field">
          <span>service accounts (excluded from out-of-hours rules)</span>
          <ListInput mono value={s.serviceAccounts} onChange={(v) => patch({ serviceAccounts: v })} placeholder={'svc_sql\nsvc_scan'} />
        </label>
      </div>
    </div>
  )
}

/** Business hours and weekend days for the out-of-hours rules, and how this browser shows timestamps. */
export function TimePanel({ s, patch }: { s: CaseSettings; patch: Patch }) {
  const [local, setLocal] = useState(getLocalTime())
  return (
    <div className="panel">
      <div className="panel-h">time</div>
      <div className="panel-b col">
        <div className="row">
          <label className="field">
            <span>business hours start</span>
            <input
              type="number"
              className="input mono"
              min={0}
              max={23}
              value={s.businessHours.start}
              onChange={(e) => patch({ businessHours: { ...s.businessHours, start: Number(e.target.value) } })}
            />
          </label>
          <label className="field">
            <span>end</span>
            <input type="number" className="input mono" min={0} max={24} value={s.businessHours.end} onChange={(e) => patch({ businessHours: { ...s.businessHours, end: Number(e.target.value) } })} />
          </label>
          <label className="field" style={{ flex: 1 }}>
            <span>time zone (IANA)</span>
            <input className="input mono" value={s.businessHours.tz} onChange={(e) => patch({ businessHours: { ...s.businessHours, tz: e.target.value } })} placeholder="Europe/Paris" />
          </label>
        </div>
        <label className="field">
          <span>weekend days</span>
          <div className="row wrap">
            {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d, i) => (
              <label key={d} className="checkbox small">
                <input
                  type="checkbox"
                  checked={s.weekendDays.includes(i)}
                  onChange={(e) => patch({ weekendDays: e.target.checked ? [...s.weekendDays, i].sort() : s.weekendDays.filter((x) => x !== i) })}
                />{' '}
                {d}
              </label>
            ))}
          </div>
        </label>
        <Toggle
          on={local}
          onChange={(v) => {
            setLocal(v)
            setLocalTime(v)
            getDb().kv.put({ key: 'localTime', value: v })
            toast('info', v ? 'timestamps shown in local time' : 'timestamps shown in UTC')
          }}
          label="display timestamps in local time instead of UTC (display only - data stays UTC)"
        />
      </div>
    </div>
  )
}
