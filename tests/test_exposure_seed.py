import sqlite3,unittest
from cloudroll.route_delivery import issue
from cloudroll.trial_sample import record
class ExposureSeed(unittest.TestCase):
 def test_issued_route_changes_written_sample(self):
  db=sqlite3.connect(':memory:')
  self.assertEqual(issue(db,'r1','a','d1','old'),'issued')
  self.assertEqual(record(db,'s1','r1',1),'recorded')
  self.assertEqual(issue(db,'r2','b','d2','new'),'issued')
  self.assertEqual(record(db,'s2','r2',0),'recorded')
  self.assertEqual(db.execute('SELECT digest FROM trial_samples ORDER BY sample').fetchall(),[('old',),('new',)])
  self.assertEqual(issue(db,'r1','a','d1','old'),'replayed')
  with self.assertRaises(ValueError):issue(db,'r1','a','d1','new')
