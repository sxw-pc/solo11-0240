def block(db,edge):
 db.execute('CREATE TABLE IF NOT EXISTS edge_blocks(edge TEXT,bytes INTEGER)')
 value=db.execute('SELECT COALESCE(SUM(bytes),0) FROM flow_rows WHERE edge=?',(edge,)).fetchone()[0]
 db.execute('INSERT INTO edge_blocks VALUES (?,?)',(edge,value))
 return value
