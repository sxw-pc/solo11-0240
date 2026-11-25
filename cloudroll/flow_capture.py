import hashlib,json

def import_page(db,page,rows):
 db.execute('CREATE TABLE IF NOT EXISTS flow_pages(id TEXT PRIMARY KEY,digest TEXT NOT NULL)')
 db.execute('CREATE TABLE IF NOT EXISTS flow_rows(page TEXT,line_no INTEGER,edge TEXT,ip TEXT,tenant TEXT,bytes INTEGER,PRIMARY KEY(page,line_no))')
 if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'edge','ip','tenant','bytes'} or type(r['bytes']) is not int or r['bytes']<0 for r in rows):raise ValueError('invalid_flow_page')
 digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 old=db.execute('SELECT digest FROM flow_pages WHERE id=?',(page,)).fetchone()
 if old:
  if old[0]!=digest:raise ValueError('flow_page_conflict')
  return 'replayed'
 db.execute('INSERT INTO flow_pages VALUES (?,?)',(page,digest))
 for i,r in enumerate(rows,1):db.execute('INSERT INTO flow_rows VALUES (?,?,?,?,?,?)',(page,i,r['edge'],r['ip'],r['tenant'],r['bytes']))
 return 'captured'
