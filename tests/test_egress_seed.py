import sqlite3,unittest
from cloudroll.flow_capture import import_page
from cloudroll.tenant_notice import issue
from cloudroll.edge_quarantine import block
class EgressSeed(unittest.TestCase):
 def test_capture_changes_two_written_outcomes(self):
  db=sqlite3.connect(':memory:')
  rows=[{'edge':'e1','ip':'10.0.0.1','tenant':'t1','bytes':800},{'edge':'e1','ip':'10.0.0.2','tenant':'t2','bytes':200}]
  self.assertEqual(import_page(db,'f1',rows),'captured')
  self.assertEqual(issue(db,'t1'),800)
  self.assertEqual(block(db,'e1'),1000)
  self.assertEqual(import_page(db,'f1',rows),'replayed')
  with self.assertRaises(ValueError):import_page(db,'f1',[{**rows[0],'bytes':900}])
