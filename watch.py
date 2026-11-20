#!/usr/bin/env python3
"""Free cloud Cyber Watch: RSS/CISA KEV monitor with Telegram delivery."""
import os, json, re, sqlite3, urllib.request, urllib.parse, csv, io, html, datetime, time
from xml.etree import ElementTree as ET

DB=os.getenv('DB_PATH','state.db'); OUT='docs/index.html'; MAX=int(os.getenv('MAX_ITEMS','50'))
FEEDS=[
 ('CISA advisories','https://www.cisa.gov/news-events/cybersecurity-advisories.xml',5),
 ('CISA news','https://www.cisa.gov/news.xml',3),
 ('BleepingComputer','https://www.bleepingcomputer.com/feed/',3),
 ('The Hacker News','https://feeds.feedburner.com/TheHackersNews',3),
 ('Krebs on Security','https://krebsonsecurity.com/feed/',3),
 ('SANS ISC','https://isc.sans.edu/rssfeed.xml',3),
 ('Google Security Blog','https://security.googleblog.com/feeds/posts/default?alt=rss',3),
 ('Microsoft Security Blog','https://www.microsoft.com/en-us/security/blog/feed/',3),
 ('Cisco Security','https://sec.cloudapps.cisco.com/security/center/rss.x',4),
 ('Ubuntu Security','https://ubuntu.com/security/notices/rss.xml',3),
]
KEYS={'critical':['actively exploited','zero-day','0-day','remote code execution','rce','critical','kev','known exploited','ransomware'],'high':['exploit','vulnerability','cve-','security advisory','breach','malware','phishing']}
def score(text, weight):
 t=text.lower(); s=weight
 if any(k in t for k in KEYS['critical']): s+=5
 if any(k in t for k in KEYS['high']): s+=2
 cves=re.findall(r'CVE-\d{4}-\d{4,7}',t.upper()); s+=min(len(cves),3)
 return min(s,10),cves
def fetch(url,timeout=15):
 req=urllib.request.Request(url,headers={'User-Agent':'CyberWatchAI/1.0 (security feed monitor)'})
 with urllib.request.urlopen(req,timeout=timeout) as r:return r.read()
def init():
 db=sqlite3.connect(DB); db.execute('CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, title TEXT, url TEXT, source TEXT, published TEXT, score INTEGER, cves TEXT, summary TEXT)'); db.commit(); return db
def parse_feed(name,url,w):
 try:
  root=ET.fromstring(fetch(url)); entries=root.findall('.//item')
  if not entries: entries=root.findall('.//{http://www.w3.org/2005/Atom}entry')
  out=[]
  for e in entries[:40]:
   def get(tag):
    x=e.find(tag) or e.find('{http://www.w3.org/2005/Atom}'+tag)
    return (x.text or '').strip() if x is not None and x.text else ''
   title=get('title'); link=get('link')
   if not link:
    x=e.find('{http://www.w3.org/2005/Atom}link'); link=x.get('href','') if x is not None else ''
   desc=get('description') or get('summary') or get('content')
   desc=re.sub('<[^>]+>',' ',desc); desc=html.unescape(re.sub(r'\s+',' ',desc))[:500]
   published=get('pubDate') or get('published') or get('updated')
   if title and link:
    s,cves=score(title+' '+desc,w); ident=link.strip()
    out.append((ident,title,link,name,published,s,','.join(cves),desc))
  return out
 except Exception as ex: print(f'Feed failure {name}: {ex}'); return []
def kev_feed():
 url='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
 try:
  data=json.loads(fetch(url)); out=[]
  for v in data.get('vulnerabilities',[]):
   cve=v.get('cveID',''); title=f"{cve} — {v.get('vendorProject','')} {v.get('product','')}: {v.get('vulnerabilityName','')}"
   desc=f"Known exploited vulnerability. Due date: {v.get('dueDate','n/a')}. Required action: {v.get('requiredAction','')}"
   link='https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
   out.append((cve,title,link,'CISA KEV',v.get('dateAdded',''),10,cve,desc))
  return out
 except Exception as e: print('KEV error:',e); return []
def telegram(msg):
 token=os.getenv('TELEGRAM_BOT_TOKEN'); chat=os.getenv('TELEGRAM_CHAT_ID')
 if not token or not chat:return
 url='https://api.telegram.org/bot'+token+'/sendMessage'
 data=urllib.parse.urlencode({'chat_id':chat,'text':msg,'parse_mode':'HTML','disable_web_page_preview':'true'}).encode()
 urllib.request.urlopen(urllib.request.Request(url,data=data),timeout=20).read()
def esc(x): return html.escape(str(x or ''),quote=False)
def main():
 db=init(); feeds=[]
 for n,u,w in FEEDS: feeds+=parse_feed(n,u,w)
 feeds+=kev_feed(); new=[]
 for item in feeds:
  try:
   db.execute('INSERT INTO seen VALUES (?,?,?,?,?,?,?,?)',item); new.append(item)
  except sqlite3.IntegrityError: pass
 db.commit(); db.close()
 # Build snapshot from all stored entries
 db=sqlite3.connect(DB); rows=db.execute('SELECT id,title,url,source,published,score,cves,summary FROM seen ORDER BY score DESC').fetchall(); db.close()
 rows=rows[:MAX]; new.sort(key=lambda x:x[5],reverse=True)
 os.makedirs('docs',exist_ok=True)
 cards=''.join(f'<article><div class="meta"><span class="pill">{esc(r[3])}</span><span class="score">Priority {r[5]}/10</span></div><h2>{esc(r[1])}</h2><p>{esc(r[7])}</p><small>{esc(r[4])} · {esc(r[6])}</small><p><a href="{esc(r[2])}" target="_blank" rel="noopener">Open source ↗</a></p></article>' for r in rows)
 htmlpage=f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Cyber Watch AI</title><style>body{{margin:0;background:#0b1220;color:#e8eef8;font-family:system-ui;max-width:1100px;margin:auto;padding:24px}}header{{padding:28px;background:#14233b;border-radius:16px}}h1{{margin:0}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-top:20px}}article{{background:#111d30;border:1px solid #263a57;padding:18px;border-radius:14px}}.meta{{display:flex;justify-content:space-between}}.pill{{background:#193d5c;padding:4px 9px;border-radius:20px}}.score{{color:#fbbf24}}a{{color:#7dd3fc}}small{{color:#9fb1c8}}p{{line-height:1.5}}.foot{{color:#90a4bd;margin-top:20px}}</style></head><body><header><h1>🛡️ Cyber Watch AI</h1><p>Open-source threat intelligence digest · Updated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p><p>{len(rows)} tracked items · {len(new)} new items this run</p></header><main class="grid">{cards}</main><p class="foot">Automated feed monitor. Priority is heuristic, not a formal severity rating. Verify details with the linked source.</p></body></html>'''
 open(OUT,'w',encoding='utf-8').write(htmlpage)
 if new:
  top=new[:12]; lines=['<b>🛡️ Cyber Watch AI — New intelligence</b>']
  for r in top: lines.append(f"\n<b>[{r[5]}/10] {esc(r[1])[:180]}</b>\n{esc(r[3])} · CVEs: {esc(r[6] or 'none detected')}\n<a href='{esc(r[2])}'>Source</a>")
  msg='\n'.join(lines)
  for chunk in [msg[i:i+3800] for i in range(0,len(msg),3800)]: telegram(chunk)
 print(f'Run complete: {len(new)} new items, {len(rows)} dashboard records')
if __name__=='__main__':main()
