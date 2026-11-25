def issue(db,tenant):
 db.execute('CREATE TABLE IF NOT EXISTS tenant_notices(tenant TEXT,bytes INTEGER)')
 value=db.execute('SELECT COALESCE(SUM(bytes),0) FROM flow_rows WHERE tenant=?',(tenant,)).fetchone()[0]
 db.execute('INSERT INTO tenant_notices VALUES (?,?)',(tenant,value))
 return value
