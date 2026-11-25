import sqlite3,unittest
from cloudroll.meter_capture import import_page
from cloudroll.vendor_payable import close
from cloudroll.tenant_charge import issue
class UsageBillingSeed(unittest.TestCase):
 def test_capture_drives_two_written_ledgers(self):
  db=sqlite3.connect(':memory:')
  rows=[{'host':'h1','tenant':'t1','minute':1,'core_seconds':60},{'host':'h2','tenant':'t2','minute':1,'core_seconds':30}]
  self.assertEqual(import_page(db,'p1',rows),'captured')
  self.assertEqual(close(db,'i1'),90)
  self.assertEqual(issue(db,'t1'),60)
  self.assertEqual(import_page(db,'p1',rows),'replayed')
  with self.assertRaises(ValueError):import_page(db,'p1',[{**rows[0],'core_seconds':70}])
