import pathlib
import tempfile
import unittest
import cloudroll
from cloudroll import artifact, stage, recovery
from cloudroll.cli import run
from cloudroll.store import open_db, one

class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=open_db(str(pathlib.Path(self.temp.name)/"run.sqlite"))
    def tearDown(self):
        self.db.close();self.temp.cleanup()
    def seed(self,client=1):
        artifact.baseline(self.db,"svc",3,1)
        artifact.register(self.db,"old","oldhash",3,3)
        artifact.register(self.db,"new","newhash",2,4)
        artifact.contract(self.db,"new",1,2)
        artifact.population(self.db,"svc",client,5)
    def test_module_local(self):
        print("module_file",cloudroll.__file__)
        self.assertIn("solo11-0240",str(pathlib.Path(cloudroll.__file__).resolve()))
    def test_client_and_window_admission(self):
        self.seed(0)
        self.assertEqual(artifact.plan(self.db,"e1","p1","svc","new",1,10),"unsupported_active_clients")
        artifact.proxy(self.db,"px","svc",0,10)
        self.assertEqual(artifact.plan(self.db,"e2","p1","svc","new",1,10),"locked")
        self.assertTrue(artifact.plan(self.db,"e3","p2","svc","new",5,9).startswith("window_conflict"))
        self.assertEqual(artifact.revoke(self.db,"e4","new",2),"revoked")
        self.assertEqual(one(self.db,"SELECT status FROM plan WHERE id='p1'")["status"],"blocked_revoked")
    def test_fixed_stage_member_and_window(self):
        self.seed()
        artifact.plan(self.db,"e1","p1","svc","new",1,10)
        stage.start(self.db,"s1","p1",[{"replica":"a","generation":1},{"replica":"b","generation":1}],2,6)
        self.assertEqual(stage.receipt(self.db,"r3","s1","c",1,"newhash"),"not_a_fixed_member")
        stage.receipt(self.db,"r1","s1","a",1,"newhash")
        stage.sample(self.db,"h1","s1","a",1,"newhash",True)
        self.assertIn("failed",stage.decide(self.db,"s1",7))
        self.assertEqual(one(self.db,"SELECT status FROM recovery WHERE id='rec-s1'")["status"],"open")
    def test_recovery_requires_every_member_and_handles_orphan(self):
        self.seed()
        artifact.plan(self.db,"e1","p1","svc","new",1,10)
        stage.start(self.db,"s1","p1",[{"replica":"a","generation":1},{"replica":"b","generation":1}],2,6)
        stage.decide(self.db,"s1",7)
        recovery.stable(self.db,"svc","old",3,1)
        self.assertEqual(recovery.choose(self.db,"rec-s1"),"old")
        recovery.compensate(self.db,"c1","rec-s1","a",1,"oldhash")
        self.assertEqual(recovery.close(self.db,"rec-s1"),"incomplete_compensation")
        self.assertEqual(recovery.orphan(self.db,"o1","svc","alienhash",1),"quarantined")
        recovery.compensate(self.db,"c2","rec-s1","b",1,"oldhash")
        self.assertEqual(recovery.close(self.db,"rec-s1"),"incomplete_compensation")
    def test_six_fixtures(self):
        root=pathlib.Path(__file__).resolve().parents[1]
        expected={"artifact_normal":"locked","artifact_failure":"unsupported_active_clients","stage_normal":"passed","stage_failure":"failed:a:health,b","recovery_normal":"closed","recovery_failure":"incomplete_compensation"}
        for name,want in expected.items():
            output=run(str(pathlib.Path(self.temp.name)/(name+".sqlite")),root/"fixtures"/(name+".json"))
            self.assertEqual(output["results"][-1]["result"],want,name)
            self.assertTrue(output["audit"]["verified"],(name,output["audit"]["mismatches"]))

if __name__=="__main__":unittest.main()
