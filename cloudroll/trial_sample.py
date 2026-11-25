"""Small baseline that writes analytical samples from real route receipts."""
def record(db, sample, receipt, outcome):
    db.execute('CREATE TABLE IF NOT EXISTS trial_samples (sample TEXT PRIMARY KEY, receipt TEXT NOT NULL, digest TEXT NOT NULL, outcome INTEGER NOT NULL)')
    route=db.execute('SELECT digest FROM delivered_routes WHERE receipt=?',(receipt,)).fetchone()
    if not route:raise ValueError('unknown_route_receipt')
    prior=db.execute('SELECT receipt,digest,outcome FROM trial_samples WHERE sample=?',(sample,)).fetchone()
    if prior:
        if tuple(prior)!=(receipt,route[0],outcome):raise ValueError('sample_conflict')
        return 'replayed'
    db.execute('INSERT INTO trial_samples VALUES (?,?,?,?)',(sample,receipt,route[0],outcome))
    return 'recorded'
