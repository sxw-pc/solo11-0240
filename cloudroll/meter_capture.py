import hashlib,json

def import_page(db,page,rows):
    db.execute('CREATE TABLE IF NOT EXISTS meter_pages (id TEXT PRIMARY KEY,digest TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS meter_rows (page TEXT,line_no INTEGER,host TEXT,tenant TEXT,minute INTEGER,core_seconds INTEGER,PRIMARY KEY(page,line_no))')
    if not isinstance(rows,list) or any(not isinstance(r,dict) or set(r)!={'host','tenant','minute','core_seconds'} or type(r['minute']) is not int or type(r['core_seconds']) is not int or r['core_seconds']<0 for r in rows):raise ValueError('invalid_meter_page')
    digest=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    prior=db.execute('SELECT digest FROM meter_pages WHERE id=?',(page,)).fetchone()
    if prior:
        if prior[0]!=digest:raise ValueError('meter_page_conflict')
        return 'replayed'
    db.execute('INSERT INTO meter_pages VALUES (?,?)',(page,digest))
    for i,r in enumerate(rows,1):db.execute('INSERT INTO meter_rows VALUES (?,?,?,?,?,?)',(page,i,r['host'],r['tenant'],r['minute'],r['core_seconds']))
    return 'captured'
