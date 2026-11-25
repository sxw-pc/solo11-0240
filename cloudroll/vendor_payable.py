def close(db,invoice):
    db.execute('CREATE TABLE IF NOT EXISTS vendor_payables (invoice TEXT,core_seconds INTEGER)')
    value=db.execute('SELECT COALESCE(SUM(core_seconds),0) FROM meter_rows').fetchone()[0]
    db.execute('INSERT INTO vendor_payables VALUES (?,?)',(invoice,value))
    return value
