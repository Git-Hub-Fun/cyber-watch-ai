#!/usr/bin/env python3
"""Cyber Watch AI: free-tier scheduled cloud collector with feed health, retries and enrichment."""
import os,json,re,sqlite3,urllib.request,urllib.parse,html,datetime,time
from xml.etree import ElementTree as ET
DB=os.getenv('DB_PATH','state.db'); OUT='docs/index.html'; MAX=int(os.getenv('MAX_ITEMS','300'))
FEEDS=[
 ('CISA','CISA advisories','https://www.cisa.gov/news-events/cybersecurity-advisories.xml',5),
 ('BleepingComputer','BleepingComputer','https://www.bleepingcomputer.com/feed/',4),
 ('The Hacker News','The Hacker News','https://feeds.feedburner.com/TheHackersNews',4),
 ('Krebs on Security','Krebs on Security','https://krebsonsecurity.com/feed/',3),
 ('SANS ISC','SANS ISC','https://isc.sans.edu/rssfeed.xml',4),
 ('Google Security Blog','Google Security Blog','https://security.googleblog.com/feeds/posts/default?alt=rss',3),
 ('Microsoft Security Blog','Microsoft Security Blog','https://www.microsoft.com/en-us/security/blog/feed/',4),
 ('Cisco Security','Cisco Security','https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml',4),
 ('Exploit-DB','Exploit-DB','https://www.exploit-db.com/rss.xml',4),
 ('Packet Storm','Packet Storm','https://packetstormsecurity.com/feeds/','3'),
 ('NVD','NVD CVE feed','https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml',5),
]
CRIT=['actively exploited','zero-day','zero day','0-day','remote code execution','rce','critical','known exploited','ransomware']
HIGH=['exploit','vulnerability','cve-','security advisory','breach','malware','phishing']
def score(text,w):
 t=text.lower();s=int(w)
 if any(k in t for k in CRIT):s+=5
 if any(k in t for k in HIGH):s+=2
 cves=re.findall(r'CVE-\d{4}-\d{4,7}',text.upper());s+=min(len(set(cves)),3)
 return min(s,10),','.join(sorted(set(cves)))
def fetch(url,timeout=20,retries=3):
 last=None
 for attempt in range(retries):
  try:
   req=urllib.request.Request(url,headers={'User-Agent':'CyberWatchAI/3.0 (+public threat intelligence monitor)'})
   with urllib.request.urlopen(req,timeout=timeout) as r:return r.read()
  except Exception as e:
   last=e
   if attempt+1<retries:time.sleep(min(2**attempt,8))
 raise last
def init():
 db=sqlite3.connect(DB);db.execute('CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY,title TEXT,url TEXT,source TEXT,published TEXT,score INTEGER,cves TEXT,summary TEXT)')
 db.execute('CREATE TABLE IF NOT EXISTS feed_health (source TEXT PRIMARY KEY,last_attempt TEXT,last_success TEXT,status TEXT,entries INTEGER,error TEXT,consecutive_failures INTEGER DEFAULT 0)')
 db.execute('CREATE TABLE IF NOT EXISTS enrichment (cve TEXT PRIMARY KEY,epss REAL,percentile REAL,updated TEXT)');db.commit();return db
def parse_feed(tab,name,url,w,db):
 now=datetime.datetime.now(datetime.timezone.utc).isoformat();out=[]
 try:
  root=ET.fromstring(fetch(url));entries=[e for e in root.iter() if e.tag.split('}')[-1].lower() in ('item','entry')]
  for e in entries[:80]:
   def get(*tags):
    tags=[t.lower() for t in tags]
    for child in list(e):
     local=child.tag.split('}')[-1].lower()
     if local in tags:
      if child.text and child.text.strip():return child.text.strip()
      if child.get('href'):return child.get('href').strip()
      txt=' '.join(x.strip() for x in child.itertext() if x and x.strip())
      if txt:return txt
    return ''
   title=get('title');link=get('link','guid')
   for child in list(e):
    if child.tag.split('}')[-1].lower()=='link' and child.get('href') and child.get('rel','alternate')=='alternate':link=child.get('href');break
   desc=get('description','summary','content','encoded');desc=html.unescape(re.sub(r'<[^>]+>',' ',desc));desc=re.sub(r'\s+',' ',desc)[:600]
   pub=get('pubDate','published','updated','date')
   if title and link:
    s,cves=score(title+' '+desc,w);out.append((link.strip(),title,link.strip(),tab,pub,s,cves,desc))
  db.execute('INSERT OR REPLACE INTO feed_health VALUES(?,?,?,?,?,?,?)',(tab,now,now,'OK',len(out),'',0));print(f'Feed OK: {name} — {len(out)} entries')
 except Exception as ex:
  old=db.execute('SELECT consecutive_failures,last_success FROM feed_health WHERE source=?',(tab,)).fetchone();fail=(old[0] if old else 0)+1;success=(old[1] if old else '')
  db.execute('INSERT OR REPLACE INTO feed_health VALUES(?,?,?,?,?,?,?)',(tab,now,success,'ERROR',0,str(ex)[:350],fail));print(f'Feed failure {name}: {str(ex)[:200]}')
 return out
def nvd_feed():
 try:
  end=datetime.datetime.now(datetime.timezone.utc);start=end-datetime.timedelta(days=7);fmt=lambda d:d.strftime('%Y-%m-%dT%H:%M:%S.000')
  url='https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate='+urllib.parse.quote(fmt(start))+'&pubEndDate='+urllib.parse.quote(fmt(end))+'&resultsPerPage=100'
  data=json.loads(fetch(url,timeout=30));out=[]
  for v in data.get('vulnerabilities',[]):
   c=v.get('cve',{});cid=c.get('id','');desc=' '.join(x.get('value','') for x in c.get('descriptions',[]) if x.get('lang')=='en');title=cid+' — '+(desc[:250] or 'New NVD CVE record');link='https://nvd.nist.gov/vuln/detail/'+cid
   if cid:s,cves=score(title,5);out.append((link,title,link,'NVD CVE feed',c.get('published',''),s,cid,desc[:600]))
  return out
 except Exception as ex:print('NVD error',str(ex)[:200]);return []
def kev_feed():
 try:
  data=json.loads(fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'));out=[]
  for v in data.get('vulnerabilities',[]):
   cve=v.get('cveID','');title=f"{cve} — {v.get('vendorProject','')} {v.get('product','')}: {v.get('vulnerabilityName','')}";desc=f"Known exploited vulnerability. Added: {v.get('dateAdded','')}. Due date: {v.get('dueDate','n/a')}. Action: {v.get('requiredAction','')}"
   out.append((cve,title,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog','CISA KEV',v.get('dateAdded',''),10,cve,desc))
  return out
 except Exception as e:print('KEV error',e);return []
def enrich_epss(db,cves):
 cves=sorted(set(cves));result={}
 for i in range(0,len(cves),100):
  batch=cves[i:i+100]
  try:
   url='https://api.first.org/data/v1/epss?cve='+','.join(batch);data=json.loads(fetch(url,timeout=20))
   for x in data.get('data',[]):
    cid=x.get('cve');epss=float(x.get('epss',0));pct=float(x.get('percentile',0));result[cid]=(epss,pct)
    db.execute('INSERT OR REPLACE INTO enrichment VALUES(?,?,?,?)',(cid,epss,pct,datetime.datetime.now(datetime.timezone.utc).isoformat()))
  except Exception as e:print('EPSS enrichment error:',str(e)[:160])
 db.commit();return result
def ai_analysis(items,enrichment):
 key=os.getenv('GEMINI_API_KEY');
 if not key or not items:return 'AI analyst is optional: configure GEMINI_API_KEY to enable generated analysis. This dashboard currently displays heuristic priorities and source evidence.'
 # Send a bounded, evidence-only batch; fail safely if quota/network unavailable.
 payload={'contents':[{'parts':[{'text':'Analyze these public cyber threat intelligence headlines and descriptions for a security analyst. Return concise HTML-free text: 1) overall situation, 2) urgent items, 3) defensive actions. Do not invent facts; label uncertainty. Data:\n'+json.dumps([{'title':x[1],'source':x[3],'score':x[5],'cves':x[6],'summary':x[7][:240]} for x in items[:18]])}]}]}
 try:
  req=urllib.request.Request('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key='+urllib.parse.quote(key),data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
  data=json.loads(urllib.request.urlopen(req,timeout=25).read());return data['candidates'][0]['content']['parts'][0]['text'][:5000]
 except Exception as e:return 'AI analysis unavailable (API quota, key, or network issue): '+str(e)[:220]
def telegram(msg):
 token=os.getenv('TELEGRAM_BOT_TOKEN');chat=os.getenv('TELEGRAM_CHAT_ID')
 if not token or not chat:return
 try:
  data=urllib.parse.urlencode({'chat_id':chat,'text':msg,'parse_mode':'HTML','disable_web_page_preview':'true'}).encode();fetch('https://api.telegram.org/bot'+token+'/sendMessage',timeout=20,retries=2) if False else urllib.request.urlopen(urllib.request.Request('https://api.telegram.org/bot'+token+'/sendMessage',data=data),timeout=20).read()
 except Exception as e:print('Telegram notification failure:',str(e)[:180])
def esc(x):return html.escape(str(x or ''),quote=True)
def main():
 db=init();items=[]
 for tab,name,url,w in FEEDS:items+=parse_feed(tab,name,url,w,db)
 items+=nvd_feed();items+=kev_feed();new=[]
 for item in items:
  try:db.execute('INSERT INTO seen VALUES (?,?,?,?,?,?,?,?)',item);new.append(item)
  except sqlite3.IntegrityError:pass
 db.commit();allcves=[]
 for r in db.execute('SELECT cves FROM seen').fetchall():allcves+=re.findall(r'CVE-\d{4}-\d{4,7}',(r[0] or '').upper())
 enrich_epss(db,allcves)
 rows=db.execute('SELECT id,title,url,source,published,score,cves,summary FROM seen ORDER BY score DESC,published DESC').fetchall()[:MAX];health=db.execute('SELECT source,last_attempt,last_success,status,entries,error,consecutive_failures FROM feed_health ORDER BY source').fetchall();enrichment=dict((x[0],x[1:3]) for x in db.execute('SELECT cve,epss,percentile FROM enrichment').fetchall());db.close()
 new.sort(key=lambda x:x[5],reverse=True);os.makedirs('docs',exist_ok=True)
 tabs=['All Intelligence','CISA','CISA KEV','NVD','BleepingComputer','The Hacker News','Krebs on Security','SANS ISC','Google Security Blog','Microsoft Security Blog','Cisco Security','Exploit-DB','Packet Storm']
 # Lightweight keyword-based ATT&CK mapping: heuristic, not confirmed technique attribution.
 attack_rules=[
  ('T1566','Phishing',['phishing','spear phishing','email lure']),
  ('T1190','Exploit Public-Facing Application',['remote code execution','rce','web application','zero-day','zero day']),
  ('T1486','Data Encrypted for Impact',['ransomware','encrypt files','encrypted data']),
  ('T1059','Command and Scripting Interpreter',['powershell','command line','script','bash']),
  ('T1003','OS Credential Dumping',['credential dump','password dump','lsass','mimikatz']),
  ('T1071','Application Layer Protocol',['c2','command-and-control','command and control']),
  ('T1055','Process Injection',['process injection','inject into']),
  ('T1021','Remote Services',['rdp','remote desktop','ssh']),
  ('T exfil','Exfiltration',['data exfiltration','exfiltrate','data theft']),
  ('T1195','Supply Chain Compromise',['supply chain','trojanized update','compromised package']),
  ('T1110','Brute Force',['brute force','password spraying']),
  ('T1098','Account Manipulation',['account takeover','account manipulation']),
 ]
 def map_attack(text):
  t=text.lower();return [(tid,name) for tid,name,keys in attack_rules if any(k in t for k in keys)]
 def level(score):return 'CRITICAL' if score>=9 else ('HIGH' if score>=7 else ('MEDIUM' if score>=4 else 'LOW'))
 tabs=['All Intelligence','CISA KEV','NVD','CISA','BleepingComputer','The Hacker News','Krebs on Security','SANS ISC','Google Security Blog','Microsoft Security Blog','Cisco Security','Exploit-DB','Packet Storm']
 cardhtml=[];levels={'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0};mapped_count=0
 for r in rows:
  source=r[3];tab='CISA KEV' if source=='CISA KEV' else ('NVD' if source=='NVD CVE feed' else source);cveids=re.findall(r'CVE-\d{4}-\d{4,7}',(r[6] or '').upper());ep=''
  if cveids:
   epvals=[enrichment[c][0] for c in cveids if c in enrichment];ep=' · EPSS '+', '.join(f'{v:.1%}' for v in epvals[:3]) if epvals else ''
  techniques=map_attack(r[1]+' '+r[7]);mapped_count+=bool(techniques);tags=' '.join(tid+' '+name for tid,name in techniques);tagshtml=' '.join(f'<span class="attack" title="Heuristic ATT&amp;CK mapping">{esc(tid)} · {esc(name)}</span>' for tid,name in techniques) or '<span class="muted">No keyword mapping</span>'
  sev=level(r[5]);levels[sev]+=1
  searchable=esc((r[1]+' '+r[7]+' '+r[3]+' '+r[6]+' '+tags).lower())
  cardhtml.append(f'<article data-source="{esc(tab)}" data-score="{r[5]}" data-severity="{sev}" data-date="{esc(r[4] or '')}" data-search="{searchable}"><div class="meta"><span class="pill">{esc(source)}</span><span class="score {sev.lower()}">{sev} · {r[5]}/10</span></div><h2>{esc(r[1])}</h2><p>{esc(r[7])}</p><div class="tags">{tagshtml}</div><small>{esc(r[4])} · {esc(r[6])} {esc(ep)}</small><p><a href="{esc(r[2])}" target="_blank" rel="noopener">Open source ↗</a></p></article>')
 source_links={'CISA':'https://www.cisa.gov/news-events/cybersecurity-advisories','CISA KEV':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog','NVD':'https://nvd.nist.gov/vuln/search','BleepingComputer':'https://www.bleepingcomputer.com/','The Hacker News':'https://thehackernews.com/','Krebs on Security':'https://krebsonsecurity.com/','SANS ISC':'https://isc.sans.edu/','Google Security Blog':'https://security.googleblog.com/','Microsoft Security Blog':'https://www.microsoft.com/en-us/security/blog/','Cisco Security':'https://sec.cloudapps.cisco.com/security/center/','Exploit-DB':'https://www.exploit-db.com/','Packet Storm':'https://packetstormsecurity.com/'}
 nav=''.join(f'<button class="tab" data-tab="{esc(t)}">{esc(t)}</button>' for t in tabs);links=''.join(f'<a href="{u}" target="_blank" rel="noopener">{esc(s)} ↗</a>' for s,u in source_links.items());stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
 healthhtml=''.join(f'<tr><td>{esc(h[0])}</td><td class="{("ok" if h[3]=="OK" else "bad")}">{esc(h[3])}</td><td>{esc(h[2] or "Never")}</td><td>{h[4]}</td><td>{h[6]}</td><td>{esc(h[5])}</td></tr>' for h in health)
 analyst=ai_analysis(new if new else rows[:10],enrichment);aihtml=esc(analyst).replace('\n','<br>')
 page=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cyber Watch AI | SOC Intelligence</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#07111f;color:#e7edf7;font-family:Inter,system-ui,Segoe UI,sans-serif}}header{{padding:36px max(22px,calc((100vw - 1200px)/2));background:radial-gradient(ellipse at top right,#123a58,#0c1a2b 60%);border-bottom:1px solid #1c3852}}h1{{font-size:clamp(28px,4vw,40px);margin:0}}header p{{color:#9eb3ca}}.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}}.stat,.panel{{background:#10263c;border:1px solid #244660;border-radius:12px;padding:12px 18px}}.stat strong{{font-size:20px;display:block}}main{{max-width:1200px;margin:auto;padding:24px}}.tabs{{display:flex;gap:8px;overflow:auto;padding:8px 0 14px}}button{{cursor:pointer;color:#c9d9ea;background:#102238;border:1px solid #28435e;border-radius:10px;padding:10px 14px;white-space:nowrap}}button.active{{background:#1476a7;color:white;border-color:#3cb7e9}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}}article{{background:#0e1d30;border:1px solid #213750;padding:18px;border-radius:14px}}.meta{{display:flex;justify-content:space-between;gap:8px}}.pill,.attack{{background:#193d5c;padding:4px 9px;border-radius:20px;font-size:12px;display:inline-block;margin:3px}}.score{{color:#fbbf24;font-weight:bold}}.critical{{color:#f87171}}.high{{color:#fb923c}}.medium{{color:#facc15}}.low{{color:#86efac}}a{{color:#7dd3fc}}small,.muted{{color:#9fb1c8}}p{{line-height:1.55}}.sources{{display:flex;flex-wrap:wrap;gap:12px;margin:22px 0}}.sources a{{font-size:13px}}.foot{{color:#90a4bd;margin:26px 0}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:9px;border-bottom:1px solid #244660;vertical-align:top}}.tablewrap{{overflow-x:auto}}.panel{{margin:14px 0}}.bad{{color:#fca5a5}}.ok{{color:#86efac}}.toolbar{{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}}input,select{{background:#102238;color:#e7edf7;border:1px solid #28435e;border-radius:10px;padding:11px;min-width:160px}}.tags{{margin:10px 0}}.empty{{padding:40px;color:#9eb3ca}}.summarycards{{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0}}.summarycards span{{padding:8px 12px;border:1px solid #28435e;border-radius:10px}}
</style></head><body><header><h1>🛡️ Cyber Watch AI · SOC Console</h1><p>Threat intelligence · Heuristic prioritization · ATT&amp;CK mapping · EPSS · Feed resilience</p><div class="stats"><div class="stat"><strong>{len(rows)}</strong><span>Tracked items</span></div><div class="stat"><strong>{len(new)}</strong><span>New this run</span></div><div class="stat"><strong>{stamp}</strong><span>Last run (UTC)</span></div><div class="stat"><strong>{sum(1 for h in health if h[3]=='OK')}/{len(health)}</strong><span>Healthy feeds</span></div></div></header><main><h2>Alert prioritization</h2><div class="summarycards"><span class="critical">Critical: {levels['CRITICAL']}</span><span class="high">High: {levels['HIGH']}</span><span class="medium">Medium: {levels['MEDIUM']}</span><span class="low">Low: {levels['LOW']}</span><span>ATT&amp;CK keyword mapped: {mapped_count}</span></div><h2>Agent status</h2><div class="panel"><p><b>Scheduler:</b> GitHub Actions · <b>Retries:</b> exponential backoff · <b>CVE enrichment:</b> EPSS · <b>Notifications:</b> Telegram optional</p><p class="muted">Collector is schedule-triggered. ATT&amp;CK mapping and priority scores are heuristic and should be validated by analysts.</p></div><h2>Feed health</h2><div class="tablewrap"><table><thead><tr><th>Source</th><th>Status</th><th>Last success</th><th>Entries</th><th>Failures</th><th>Latest error</th></tr></thead><tbody>{healthhtml}</tbody></table></div><h2>AI analyst</h2><div class="panel">{aihtml}</div><h2>Sources</h2><div class="sources">{links}</div><h2>Intelligence explorer</h2><div class="toolbar"><input id="search" type="search" placeholder="Search titles, CVEs, source, ATT&amp;CK…"><select id="source"><option value="">All sources</option>{''.join(f'<option>{esc(t)}</option>' for t in tabs[1:])}</select><select id="severity"><option value="">All priorities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select><select id="attack"><option value="">All mapping states</option><option value="mapped">ATT&amp;CK mapped</option><option value="unmapped">Unmapped</option></select><label>From <input id="dateFrom" type="date" aria-label="Filter from date"></label><label>To <input id="dateTo" type="date" aria-label="Filter to date"></label><button id="clearDates" type="button">Clear dates</button></div><div class="tabs">{nav}</div><div class="grid" id="feed">{''.join(cardhtml)}</div><div class="empty" id="empty" hidden>No matching records. Try changing search or filters.</div><p class="foot">Priority 0–10 is heuristic and not CVSS. ATT&amp;CK techniques are keyword-based hypotheses, not confirmed attribution. EPSS estimates exploitation probability; it is not evidence of compromise. Confirm findings against primary sources.</p></main><script>
const cards=[...document.querySelectorAll('article')],tabs=[...document.querySelectorAll('.tab')],empty=document.getElementById('empty'),search=document.getElementById('search'),source=document.getElementById('source'),severity=document.getElementById('severity'),attack=document.getElementById('attack'),dateFrom=document.getElementById('dateFrom'),dateTo=document.getElementById('dateTo');let activeTab='All Intelligence';function filter(){{tabs.forEach(b=>b.classList.toggle('active',b.dataset.tab===activeTab));let n=0;cards.forEach(c=>{{let ok=(activeTab==='All Intelligence'||c.dataset.source===activeTab)&&(!source.value||c.dataset.source===source.value)&&(!severity.value||c.dataset.severity===severity.value)&&(!search.value||c.dataset.search.includes(search.value.toLowerCase()))&&(attack.value===''||(attack.value==='mapped'?c.querySelector('.attack')!==null&&!c.querySelector('.muted'):c.querySelector('.muted')!==null))&&(!dateFrom.value||((Date.parse(c.dataset.date)||0)>=Date.parse(dateFrom.value+'T00:00:00Z')))&&(!dateTo.value||((Date.parse(c.dataset.date)||0)<=Date.parse(dateTo.value+'T23:59:59Z')));c.hidden=!ok;if(ok)n++}});empty.hidden=n>0}}tabs.forEach(b=>b.addEventListener('click',()=>{{activeTab=b.dataset.tab;filter()}}));[search,source,severity,attack,dateFrom,dateTo].forEach(x=>x.addEventListener('input',filter));document.getElementById('clearDates').addEventListener('click',()=>{{dateFrom.value='';dateTo.value='';filter()}});filter();</script></body></html>'''
 open(OUT,'w',encoding='utf-8').write(page)
 threshold=int(os.getenv('TELEGRAM_MIN_SCORE','8'))
 if new:
  alerts=[r for r in new if r[5]>=threshold]
  if alerts:
   lines=['<b>🛡️ Cyber Watch AI — New high-priority intelligence</b>']
   for r in alerts[:10]:lines.append(f"\n<b>[{r[5]}/10] {esc(r[1])[:170]}</b>\n{esc(r[3])} · CVEs: {esc(r[6] or 'none detected')}\n<a href='{esc(r[2])}'>Source</a>")
   telegram('\n'.join(lines)[:4000])
 print(f'Run complete: {len(new)} new items; {len(rows)} stored records; {len(health)} feeds tracked')
if __name__=='__main__':main()
