def issue(db,tenant):
    db.execute('CREATE TABLE IF NOT EXISTS tenant_charges (tenant TEXT,core_seconds INTEGER)')
    value=db.execute('SELECT COALESCE(SUM(core_seconds),0) FROM meter_rows WHERE tenant=?',(tenant,)).fetchone()[0]
    db.execute('INSERT INTO tenant_charges VALUES (?,?)',(tenant,value))
    return value
