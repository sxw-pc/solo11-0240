"""Small baseline that records a route actually issued to a browser."""
def issue(db, receipt, account, device, digest):
    db.execute('CREATE TABLE IF NOT EXISTS delivered_routes (receipt TEXT PRIMARY KEY, account TEXT NOT NULL, device TEXT NOT NULL, digest TEXT NOT NULL)')
    previous=db.execute('SELECT account,device,digest FROM delivered_routes WHERE receipt=?',(receipt,)).fetchone()
    if previous:
        if tuple(previous)!=(account,device,digest):raise ValueError('route_receipt_conflict')
        return 'replayed'
    db.execute('INSERT INTO delivered_routes VALUES (?,?,?,?)',(receipt,account,device,digest))
    return 'issued'
