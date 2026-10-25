import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import './App.css'

type NvdCve = {
  id: string
  sourceIdentifier?: string
  published: string
  lastModified: string
  vulnStatus?: string
  descriptions?: { lang: string; value: string }[]
  metrics?: Record<string, { cvssData: { version: string; baseScore: number; baseSeverity: string; vectorString?: string }; type?: string }[]>
  weaknesses?: { description?: { lang: string; value: string }[] }[]
  configurations?: { nodes?: { cpeMatch?: { criteria: string; vulnerable: boolean; versionStartIncluding?: string; versionEndExcluding?: string; versionEndIncluding?: string }[]; children?: { cpeMatch?: { criteria: string; vulnerable: boolean; versionStartIncluding?: string; versionEndExcluding?: string; versionEndIncluding?: string }[] }[] }[] }[]
  affected?: { affectedData?: { vendor?: string; product?: string; versions?: { version?: string; lessThan?: string; status?: string }[] }[] }[]
  references?: { url: string; tags?: string[] }[]
}

type Product = { vendor: string; name: string; versions: string[] }
type Recent = { id: string; description: string; date: string }
type SearchResult = { cve: NvdCve }
type NewsArticle = { url: string; title: string; seendate: string; domain: string; language?: string }

const HISTORY_KEY = 'cve-atlas-history-v1'
const DEFAULT_CVE = 'CVE-2021-44228'
const API_ROOT = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

function Icon({ name, size = 18 }: { name: 'search' | 'arrow' | 'external' | 'copy' | 'shield' | 'clock' | 'close' | 'refresh'; size?: number }) {
  const common = { width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const, 'aria-hidden': true as const }
  const paths: Record<string, ReactNode> = {
    search: <><circle cx="10.8" cy="10.8" r="6.7"/><path d="m16 16 4.2 4.2"/></>,
    arrow: <><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></>,
    external: <><path d="M14 4h6v6"/><path d="m20 4-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/></>,
    copy: <><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h3"/></>,
    shield: <><path d="M12 3 20 6v5c0 5.2-3.4 8.4-8 10-4.6-1.6-8-4.8-8-10V6l8-3Z"/><path d="m9 12 2 2 4-4"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    close: <><path d="m6 6 12 12M18 6 6 18"/></>,
    refresh: <><path d="M20 7v5h-5"/><path d="M4.9 9A7.5 7.5 0 0 1 18 6l2 6M4 17v-5h5"/><path d="M19.1 15A7.5 7.5 0 0 1 6 18l-2-6"/></>,
  }
  return <svg {...common}>{paths[name]}</svg>
}

function readHistory(): Recent[] {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]') as Recent[] } catch { return [] }
}

function formatDate(value?: string) {
  if (!value) return 'Not provided'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }).format(date)
}

function formatNewsDate(value?: string) {
  const compactDate = value?.match(/^(\d{4})(\d{2})(\d{2})/)
  return compactDate ? formatDate(`${compactDate[1]}-${compactDate[2]}-${compactDate[3]}`) : formatDate(value)
}

function getDescription(cve?: NvdCve) {
  return cve?.descriptions?.find((item) => item.lang === 'en')?.value || cve?.descriptions?.[0]?.value || 'No description is available in this record.'
}

function metricFor(cve: NvdCve) {
  const preference = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']
  for (const key of preference) {
    const metric = cve.metrics?.[key]?.[0]
    if (metric) return metric.cvssData
  }
  return undefined
}

function productsFor(cve: NvdCve): Product[] {
  const items = new Map<string, Product>()
  for (const affected of cve.affected || []) {
    for (const product of affected.affectedData || []) {
      if (!product.product) continue
      const key = `${product.vendor || ''}|${product.product}`
      const current = items.get(key) || { vendor: product.vendor || 'Vendor not listed', name: product.product, versions: [] }
      for (const version of product.versions || []) {
        if (version.status && version.status !== 'affected') continue
        const range = version.lessThan ? `${version.version || 'Earlier versions'} to < ${version.lessThan}` : version.version
        if (range && !current.versions.includes(range)) current.versions.push(range)
      }
      items.set(key, current)
    }
  }
  const nodes = cve.configurations?.flatMap((group) => group.nodes || []) || []
  const cpes = nodes.flatMap((node) => [...(node.cpeMatch || []), ...(node.children || []).flatMap((child) => child.cpeMatch || [])])
  for (const match of cpes) {
    if (!match.vulnerable) continue
    const parts = match.criteria.split(':')
    const vendor = (parts[3] || 'unknown').replaceAll('_', ' ')
    const name = (parts[4] || 'Product not listed').replaceAll('_', ' ')
    const key = `${vendor}|${name}`
    const current = items.get(key) || { vendor, name, versions: [] }
    const version = parts[5]
    const lower = match.versionStartIncluding
    const upper = match.versionEndExcluding ? `< ${match.versionEndExcluding}` : match.versionEndIncluding ? `≤ ${match.versionEndIncluding}` : ''
    const range = lower || upper ? `${lower || 'Earlier versions'}${upper ? ` to ${upper}` : ' and later'}` : (version !== '*' ? version : '')
    if (range && !current.versions.includes(range)) current.versions.push(range)
    items.set(key, current)
  }
  return [...items.values()].slice(0, 30)
}

function uniqueReferenceHosts(cve: NvdCve) {
  const hosts = new Set<string>()
  for (const reference of cve.references || []) {
    try { hosts.add(new URL(reference.url).hostname.replace(/^www\./, '')) } catch { /* Ignore malformed source links. */ }
  }
  return [...hosts].slice(0, 8)
}

function App() {
  const [input, setInput] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    return params.get('site') || params.get('cve')?.toUpperCase() || DEFAULT_CVE
  })
  const [cve, setCve] = useState<NvdCve>()
  const [history, setHistory] = useState<Recent[]>(readHistory)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [copiedLink, setCopiedLink] = useState(false)
  const [status, setStatus] = useState('Connecting to NVD')
  const [searchMode, setSearchMode] = useState<'cve' | 'site'>(() => new URLSearchParams(window.location.search).has('site') ? 'site' : 'cve')
  const [siteResults, setSiteResults] = useState<SearchResult[]>([])
  const [newsResults, setNewsResults] = useState<NewsArticle[]>([])
  const [newsUnavailable, setNewsUnavailable] = useState(false)
  const [siteTotal, setSiteTotal] = useState(0)
  const [siteQuery, setSiteQuery] = useState('')

  const lookup = useCallback(async (rawId: string) => {
    const id = rawId.trim().toUpperCase()
    setSearchMode('cve')
    setSiteResults([])
    setNewsResults([])
    setCve(undefined)
    if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
      setError('Enter a CVE ID in the format CVE-2024-12345.')
      return
    }
    setLoading(true)
    setError('')
    setStatus('Retrieving source record')
    setInput(id)
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 15000)
    try {
      const response = await fetch(`${API_ROOT}?cveId=${encodeURIComponent(id)}`, { signal: controller.signal })
      if (response.status === 429) throw new Error('NVD is receiving too many requests right now. Wait a moment, then try again.')
      if (!response.ok) throw new Error(`NVD returned an error (${response.status}). Try again shortly.`)
      const data = await response.json() as { vulnerabilities?: { cve: NvdCve }[] }
      const record = data.vulnerabilities?.[0]?.cve
      if (!record) throw new Error(`No public NVD record was found for ${id}. Check the ID or try again later.`)
      setCve(record)
      setStatus('Record retrieved')
      const nextHistory = [{ id: record.id, description: getDescription(record), date: record.published }, ...readHistory().filter((item) => item.id !== record.id)].slice(0, 7)
      setHistory(nextHistory)
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(nextHistory)) } catch { /* Lookup still works when storage is unavailable. */ }
      const params = new URLSearchParams(window.location.search)
      params.delete('site')
      params.set('cve', record.id)
      window.history.replaceState(null, '', `${window.location.pathname}?${params.toString()}`)
    } catch (cause) {
      const message = cause instanceof Error && cause.name === 'AbortError'
        ? 'NVD did not respond in time. Check your connection and retry.'
        : cause instanceof Error ? cause.message : 'Something went wrong while retrieving this CVE.'
      setError(message)
      setStatus('Source unavailable')
    } finally {
      window.clearTimeout(timeout)
      setLoading(false)
    }
  }, [])

  const searchSite = useCallback(async (rawQuery: string) => {
    const query = rawQuery.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '')
    if (query.length < 2) {
      setError('Enter a site name or domain with at least 2 characters.')
      return
    }
    setInput(query)
    setSiteQuery(query)
    setCve(undefined)
    setSiteResults([])
    setNewsResults([])
    setNewsUnavailable(false)
    setLoading(true)
    setError('')
    setStatus('Searching public references')
    const controller = new AbortController()
    const timeout = window.setTimeout(() => controller.abort(), 20000)
    try {
      const nvdParams = new URLSearchParams({ keywordSearch: query, resultsPerPage: '1' })
      const coverageQuery = `${query} (vulnerability OR vulnerabilities OR "security flaw" OR breach OR exploit OR hack OR CVE)`
      const newsParams = new URLSearchParams({ query: coverageQuery, mode: 'ArtList', format: 'json', maxrecords: '10', sort: 'HybridRel' })
      const startDate = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000)
      const endDate = new Date()
      const compactDate = (date: Date) => `${date.getUTCFullYear()}${(date.getUTCMonth() + 1).toString().padStart(2, '0')}${date.getUTCDate().toString().padStart(2, '0')}`
      newsParams.set('startdatetime', `${compactDate(startDate)}000000`)
      newsParams.set('enddatetime', `${compactDate(endDate)}235959`)
      const [nvdOutcome, newsOutcome] = await Promise.allSettled([
        fetch(`${API_ROOT}?${nvdParams.toString()}`, { signal: controller.signal }),
        fetch(`https://api.gdeltproject.org/api/v2/doc/doc?${newsParams.toString()}`, { signal: controller.signal }),
      ])
      if (nvdOutcome.status === 'rejected') throw nvdOutcome.reason
      const response = nvdOutcome.value
      if (response.status === 429) throw new Error('NVD is receiving too many requests right now. Wait a moment, then try again.')
      if (!response.ok) throw new Error(`NVD returned an error (${response.status}). Try again shortly.`)
      // NVD keyword pages begin with older records, so read the final page for recent matches.
      const countData = await response.json() as { totalResults?: number }
      const total = countData.totalResults || 0
      setSiteTotal(total)
      if (total > 0) {
        const latestParams = new URLSearchParams(nvdParams)
        latestParams.set('resultsPerPage', '20')
        latestParams.set('startIndex', Math.max(0, total - 20).toString())
        const latestResponse = await fetch(`${API_ROOT}?${latestParams.toString()}`, { signal: controller.signal })
        if (latestResponse.status === 429) throw new Error('NVD is receiving too many requests right now. Wait a moment, then try again.')
        if (!latestResponse.ok) throw new Error(`NVD returned an error (${latestResponse.status}). Try again shortly.`)
        const latestData = await latestResponse.json() as { vulnerabilities?: SearchResult[] }
        setSiteResults((latestData.vulnerabilities || []).sort((a, b) => b.cve.published.localeCompare(a.cve.published)))
      }
      if (newsOutcome.status === 'fulfilled' && newsOutcome.value.ok) {
        try {
          const newsData = await newsOutcome.value.json() as { articles?: NewsArticle[] }
          setNewsResults(newsData.articles || [])
        } catch {
          setNewsUnavailable(true)
        }
      } else {
        setNewsUnavailable(true)
      }
      setStatus('Search complete')
      const paramsInUrl = new URLSearchParams(window.location.search)
      paramsInUrl.delete('cve')
      paramsInUrl.set('site', query)
      window.history.replaceState(null, '', `${window.location.pathname}?${paramsInUrl.toString()}`)
    } catch (cause) {
      const message = cause instanceof Error && cause.name === 'AbortError'
        ? 'NVD did not respond in time. Check your connection and retry.'
        : cause instanceof Error ? cause.message : 'Something went wrong while searching public references.'
      setError(message)
      setStatus('Source unavailable')
    } finally {
      window.clearTimeout(timeout)
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    if (params.has('site')) void searchSite(params.get('site') || '')
    else void lookup(input)
  }, [])

  const score = useMemo(() => cve ? metricFor(cve) : undefined, [cve])
  const products = useMemo(() => cve ? productsFor(cve) : [], [cve])
  const weaknesses = useMemo(() => [...new Set((cve?.weaknesses || []).flatMap((item) => (item.description || []).filter((entry) => entry.lang === 'en').map((entry) => entry.value)))], [cve])
  const referenceHosts = useMemo(() => cve ? uniqueReferenceHosts(cve) : [], [cve])
  const disclosureQuery = siteQuery ? `"${siteQuery}" (vulnerability OR "security flaw" OR breach OR CVE)` : ''
  const googleDisclosureUrl = disclosureQuery ? `https://www.google.com/search?q=${encodeURIComponent(disclosureQuery)}` : ''
  const bingDisclosureUrl = disclosureQuery ? `https://www.bing.com/search?q=${encodeURIComponent(disclosureQuery)}` : ''

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (searchMode === 'site') void searchSite(input)
    else void lookup(input)
  }

  const copyId = async () => {
    if (!cve) return
    try {
      await navigator.clipboard.writeText(cve.id)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch { setError('Clipboard access is unavailable in this browser.') }
  }

  const copySearchLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopiedLink(true)
      window.setTimeout(() => setCopiedLink(false), 1500)
    } catch { setError('Could not copy the link. Copy it from the address bar instead.') }
  }

  const clearHistory = () => {
    try { localStorage.removeItem(HISTORY_KEY) } catch { /* The visible list still clears for this session. */ }
    setHistory([])
  }

  return (
    <div className="app-shell">
      <aside className="history-rail" aria-label="Recent CVE lookups">
        <a className="brand" href="/" aria-label="CVE Atlas home">
          <span className="brand-mark"><span /><span /><span /></span>
          <span className="brand-name">CVE <b>ATLAS</b></span>
        </a>
        <div className="rail-section">
          <div className="rail-heading"><span>Recent lookups</span><span className="rail-count">{history.length.toString().padStart(2, '0')}</span></div>
          {history.length ? <div className="history-list">
            {history.map((item, index) => <button className={`history-item ${cve?.id === item.id ? 'selected' : ''}`} key={item.id} onClick={() => { setInput(item.id); void lookup(item.id) }}>
              <span className={`history-line line-${index % 4}`} />
              <span className="history-copy"><b>{item.id}</b><small>{item.description.slice(0, 60)}{item.description.length > 60 ? '…' : ''}</small></span>
            </button>)}
          </div> : <p className="history-empty">Your lookups appear here on this device.</p>}
          {!!history.length && <button className="clear-history" onClick={clearHistory}>Clear history</button>}
        </div>
        <div className="rail-bottom"><span className="rail-live"><i /> NVD public data</span><span className="rail-version">ATLAS / 01</span></div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div className="breadcrumbs"><span>Research</span><span className="crumb-slash">/</span><span className="crumb-current">{searchMode === 'site' ? 'Site search' : 'CVE lookup'}</span></div>
          <div className="topbar-status"><span className={`status-mark ${loading ? 'is-loading' : error ? 'is-error' : 'is-ready'}`} />{status}</div>
        </header>

        <section className="search-zone" aria-labelledby="page-title">
          <div className="search-heading">
            <div className="heading-rail"><span className="rail-overline">PUBLIC VULNERABILITY RECORDS</span><h1 id="page-title">{searchMode === 'site' ? 'Search by site.' : 'Find a CVE.'}</h1></div>
            <p>{searchMode === 'site' ? <>Find CVE records that mention a site or product.<br />A mention does not confirm it was found there.</> : <>Look up the record. Follow its sources.<br />Know what the record leaves out.</>}</p>
          </div>
          <div className="search-modes" role="group" aria-label="Search type">
            <button type="button" className={searchMode === 'cve' ? 'active' : ''} onClick={() => { setSearchMode('cve'); setError(''); setSiteResults([]); setInput(cve?.id || DEFAULT_CVE) }}>CVE ID</button>
            <button type="button" className={searchMode === 'site' ? 'active' : ''} onClick={() => { setSearchMode('site'); setError(''); setCve(undefined); setInput(siteQuery) }}>Site or product</button>
          </div>
          <form className="search-form" onSubmit={submit}>
            <label className="search-input-wrap" htmlFor="cve-search"><Icon name="search" size={19} /><span className="sr-only">{searchMode === 'site' ? 'Site name, product, or domain' : 'CVE identifier'}</span><input id="cve-search" value={input} onChange={(event) => setInput(event.target.value)} placeholder={searchMode === 'site' ? 'example.com or product name' : 'CVE-2024-12345'} autoComplete="off" spellCheck={false} /></label>
            {input && <button className="clear-input" type="button" aria-label="Clear search" onClick={() => setInput('')}><Icon name="close" size={17} /></button>}
            <button className="search-button" type="submit" disabled={loading}><span>{loading ? 'Searching' : searchMode === 'site' ? 'Search site' : 'Search CVE'}</span><Icon name={loading ? 'refresh' : 'arrow'} size={17} /></button>
          </form>
          <div className="search-meta"><span>{searchMode === 'site' ? 'Try' : 'Example'}</span><button type="button" onClick={() => searchMode === 'site' ? (setInput('wordpress.org'), void searchSite('wordpress.org')) : (setInput('CVE-2021-44228'), void lookup('CVE-2021-44228'))}>{searchMode === 'site' ? 'wordpress.org' : 'CVE-2021-44228'} <Icon name="arrow" size={13} /></button><span className="meta-divider" /><span>Source: NIST National Vulnerability Database</span></div>
        </section>

        {error && <div className="error-banner" role="alert"><span className="error-glyph">!</span><span>{error}</span><button type="button" onClick={() => searchMode === 'site' ? void searchSite(input) : void lookup(input)}>Try again</button></div>}

        {loading && !cve && searchMode === 'cve' && <section className="loading-state" aria-live="polite"><div className="loading-rail"><span /></div><p>Opening the source record…</p></section>}
        {loading && searchMode === 'site' && <section className="loading-state" aria-live="polite"><div className="loading-rail"><span /></div><p>Searching NVD for matching CVE records…</p></section>}

        {searchMode === 'site' && !loading && !error && <section className="site-results" aria-live="polite">
          <div className="site-results-heading"><div><span className="rail-overline">NVD KEYWORD MATCHES</span><h2>{siteQuery ? `Results for “${siteQuery}”` : 'Search a site or product'}</h2></div>{siteQuery && <span className="site-total">{siteTotal.toLocaleString()} public records</span>}</div>
          {siteQuery && <p className="match-disclaimer">These records mention your search term in NVD searchable content. They do not prove the vulnerability was discovered, attempted, or exploited on that domain.</p>}
          {siteQuery && siteResults.length === 0 && <div className="no-match-note"><p><b>No NVD CVE records matched this term.</b> That only means NVD returned no matching CVE records. A website-specific security disclosure may be published without a CVE ID, or indexed elsewhere.</p><div className="web-search-links"><span>Search public reporting</span><a href={googleDisclosureUrl} target="_blank" rel="noreferrer">Google <Icon name="external" size={13} /></a><a href={bingDisclosureUrl} target="_blank" rel="noreferrer">Bing <Icon name="external" size={13} /></a></div></div>}
          {siteResults.map(({ cve: record }) => {
            const recordScore = metricFor(record)
            return <button className="site-result-row" key={record.id} onClick={() => { setInput(record.id); void lookup(record.id) }}>
              <span className="result-main"><b>{record.id}</b><span>{getDescription(record)}</span></span>
              <span className="result-meta"><small>{formatDate(record.published)}</small>{recordScore && <b className={`severity severity-${recordScore.baseSeverity.toLowerCase()}`}>{recordScore.baseSeverity} · {recordScore.baseScore.toFixed(1)}</b>}<Icon name="arrow" size={16} /></span>
            </button>
          })}
          {siteTotal > siteResults.length && <p className="result-cap">Showing the newest {siteResults.length} matches from {siteTotal.toLocaleString()}. Refine the term for a narrower search.</p>}
          {siteQuery && <div className="coverage-section"><div className="site-results-heading coverage-heading"><div><span className="rail-overline">INDEPENDENT NEWS INDEX</span><h2>Public reporting</h2></div><span className="site-total">GDELT · Past 6 months</span></div><p className="match-disclaimer">News articles can describe disclosures without a CVE ID. Coverage is a lead for research, not validation of the claims.</p>{newsUnavailable && <p className="section-empty">The news index is temporarily unavailable. Search the wider web below.</p>}{!newsUnavailable && newsResults.length === 0 && <p className="section-empty">No matching news coverage found in this index.</p>}{newsResults.map((article) => <a className="news-result-row" key={article.url} href={article.url} target="_blank" rel="noreferrer"><span className="result-main"><b>{article.title}</b><span>{article.domain} · {formatNewsDate(article.seendate)}</span></span><Icon name="external" size={15} /></a>)}{siteResults.length > 0 && <div className="web-search-links"><span>Search wider coverage</span><a href={googleDisclosureUrl} target="_blank" rel="noreferrer">Google <Icon name="external" size={13} /></a><a href={bingDisclosureUrl} target="_blank" rel="noreferrer">Bing <Icon name="external" size={13} /></a></div>}</div>}
        </section>}

        {!loading && !cve && !error && searchMode === 'cve' && <section className="empty-report"><div className="empty-index">— — —</div><h2>Start with a CVE ID</h2><p>Enter an identifier above to open its public record and supporting references.</p></section>}

        {cve && <article className="report" aria-label={`Report for ${cve.id}`}>
          <div className="report-main">
            <div className="report-kicker"><span className="live-dot" /> SOURCE RECORD <span className="kicker-rule" /> {cve.vulnStatus || 'Status not provided'}</div>
            <div className="report-title-row"><h2>{cve.id}</h2><div className="report-actions"><button className="icon-button" title={copied ? 'Copied' : 'Copy CVE ID'} aria-label={copied ? 'Copied CVE ID' : 'Copy CVE ID'} onClick={copyId}><Icon name="copy" size={17} /><span>{copied ? 'Copied' : 'Copy ID'}</span></button><button className="icon-button" title={copiedLink ? 'Copied search link' : 'Copy search link'} aria-label={copiedLink ? 'Copied search link' : 'Copy search link'} onClick={copySearchLink}><Icon name="copy" size={17} /><span>{copiedLink ? 'Link copied' : 'Copy link'}</span></button><a className="source-link" href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer">Open NVD <Icon name="external" size={15} /></a></div></div>
            <p className="description">{getDescription(cve)}</p>
            <div className="data-rail" aria-label="CVE summary">
              <div className="data-point"><span className="data-label">PUBLISHED</span><b>{formatDate(cve.published)}</b></div>
              <div className="data-point"><span className="data-label">REPORTING SOURCE</span><b>{cve.sourceIdentifier || 'Not provided'}</b><small>Source listed in the record</small></div>
              <div className="data-point"><span className="data-label">LAST UPDATED</span><b>{formatDate(cve.lastModified)}</b></div>
              <div className="data-point"><span className="data-label">ASSESSMENT</span><b>{score ? `${score.baseSeverity} · ${score.baseScore.toFixed(1)}` : 'Not assessed'}</b><small>{score ? `CVSS ${score.version}` : 'No NVD score available'}</small></div>
            </div>

            <section className="report-section affected-section">
              <div className="section-title"><span className="section-rail" /><h3>Affected products</h3><span className="section-count">{products.length.toString().padStart(2, '0')}</span></div>
              {products.length ? <div className="product-list">{products.map((product) => <div className="product-row" key={`${product.vendor}-${product.name}`}><span className="product-mark" /><div className="product-name"><b>{product.name}</b><small>{product.vendor}</small></div><span className="product-version">{product.versions.length ? product.versions.slice(0, 2).join(' · ') : 'Version details not listed'}</span></div>)}</div> : <p className="section-empty">No affected product details are listed in this NVD record.</p>}
            </section>

            <section className="report-section">
              <div className="section-title"><span className="section-rail rail-blue" /><h3>Weakness classification</h3></div>
              {weaknesses.length ? <div className="tag-list">{weaknesses.map((weakness) => <span className="weakness-tag" key={weakness}>{weakness.startsWith('CWE-') ? weakness : `CWE · ${weakness}`}</span>)}</div> : <p className="section-empty">No weakness classification is provided.</p>}
            </section>
          </div>

          <aside className="report-side">
            <section className="side-block domain-block">
              <div className="side-label"><span className="side-line" /> DISCOVERY DOMAIN</div>
              <div className="unknown-state"><span className="unknown-mark">?</span><p>Not stated in<br />this CVE record</p></div>
              <small className="side-note">A CVE may describe an affected product without naming the website or domain where it was discovered or tested.</small>
            </section>
            <section className="side-block">
              <div className="side-label"><span className="side-line side-line-muted" /> REFERENCE DOMAINS <span className="ref-count">{referenceHosts.length.toString().padStart(2, '0')}</span></div>
              {referenceHosts.length ? <ul className="domain-list">{referenceHosts.map((host) => <li key={host}><span className="domain-tick" />{host}</li>)}</ul> : <p className="side-empty">No reference links listed.</p>}
              <small className="side-note">These are domains linked as references, not confirmed discovery or attack locations.</small>
            </section>
            <section className="side-block references-block">
              <div className="side-label"><span className="side-line side-line-dim" /> SOURCE REFERENCES <span className="ref-count">{(cve.references || []).length.toString().padStart(2, '0')}</span></div>
              {(cve.references || []).slice(0, 6).map((reference, index) => <a className="reference-link" href={reference.url} target="_blank" rel="noreferrer" key={`${reference.url}-${index}`}><span>{(reference.tags || []).find((tag) => tag !== 'Third Party Advisory') || 'Reference'}</span><Icon name="external" size={13} /></a>)}
              {!(cve.references || []).length && <p className="side-empty">No references listed.</p>}
              {(cve.references || []).length > 6 && <a className="all-references" href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noreferrer">View all {cve.references?.length} references <Icon name="arrow" size={13} /></a>}
            </section>
          </aside>
        </article>}

        <footer className="page-footer"><div><Icon name="shield" size={15} /><span>Public source data. Verify before acting.</span></div><span>Record fields reflect what NVD provides; missing details stay unfilled.<span className="footer-credit">Made by <a href="https://github.com/ashyyhere" target="_blank" rel="noreferrer">ashyyhere</a> with &lt;3</span></span></footer>
      </main>
    </div>
  )
}

export default App
