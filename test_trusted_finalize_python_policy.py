import json,os,subprocess,sys,tempfile,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SCRIPT=ROOT/"operator_packs/finex_trusted_utc_phase_d_v1/TRUSTED_FINALIZE_PYTHON_POLICY.ps1"
POWER=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/WindowsPowerShell/v1.0/powershell.exe"
SSH=Path(os.environ.get("SystemRoot",r"C:\Windows"))/"System32/OpenSSH/ssh-keygen.exe"

@unittest.skipUnless(POWER.is_file() and SSH.is_file(),"Windows PowerShell/OpenSSH unavailable")
class TrustedFinalizePolicyTests(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.key=self.root/"policy-authority";created=self.invoke("-SetupKey","-AuthorityPrivateKeyPath",self.key);self.assertEqual(0,created.returncode,created.stdout+created.stderr)
 def tearDown(self):self.temp.cleanup()
 def invoke(self,*arguments,env=None):return subprocess.run([str(POWER),"-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",str(SCRIPT),*map(str,arguments)],capture_output=True,text=True,timeout=60,check=False,env=env)
 def prepared(self,name="policy.json"):
  policy=self.root/name;result=self.invoke("-Prepare","-PythonPath",Path(sys.executable).resolve(),"-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy);self.assertEqual(0,result.returncode,result.stdout+result.stderr);return policy
 def signed(self,name="policy.json"):
  policy=self.prepared(name);signature=Path(str(policy)+".sig");result=self.invoke("-Sign","-PythonPath",Path(sys.executable).resolve(),"-AuthorityPrivateKeyPath",self.key,"-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy,"-SignaturePath",signature);self.assertEqual(0,result.returncode,result.stdout+result.stderr);return policy,signature
 def test_prepare_sign_verify_and_fake_environment_are_safe(self):
  policy,signature=self.signed();fake=self.root/"fake-windows/System32/OpenSSH/ssh-keygen.exe";marker=self.root/"fake-ran";fake.parent.mkdir(parents=True);fake.write_text("@echo off\r\necho ran>\""+str(marker)+"\"\r\n",encoding="ascii");environment=os.environ.copy();environment["WINDIR"]=str(self.root/"fake-windows");environment["ProgramData"]=str(self.root/"fake-program-data");result=self.invoke("-Verify","-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy,"-SignaturePath",signature,env=environment);self.assertEqual(0,result.returncode,result.stdout+result.stderr);self.assertIn('"order_capability":"DISABLED"',result.stdout);self.assertFalse(marker.exists())
 def test_tamper_and_key_substitution_are_rejected(self):
  policy,signature=self.signed();value=json.loads(policy.read_bytes());value["python_sha256"]="0"*64;policy.write_text(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n",encoding="utf-8");result=self.invoke("-Verify","-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy,"-SignaturePath",signature);self.assertNotEqual(0,result.returncode)
  policy,signature=self.signed("policy-substitution.json");other=self.root/"other";self.assertEqual(0,self.invoke("-SetupKey","-AuthorityPrivateKeyPath",other).returncode);result=self.invoke("-Verify","-AuthorityPublicKeyPath",Path(str(other)+".pub"),"-PolicyPath",policy,"-SignaturePath",signature);self.assertNotEqual(0,result.returncode);self.assertIn("FINALIZE_POLICY_SIGNATURE_INVALID",result.stdout+result.stderr)
 def test_output_collision_and_invalid_python_hash_fail(self):
  policy=self.prepared();result=self.invoke("-Prepare","-PythonPath",Path(sys.executable).resolve(),"-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy);self.assertNotEqual(0,result.returncode);self.assertIn("FINALIZE_POLICY_OUTPUT_COLLISION",result.stdout+result.stderr);value=json.loads(policy.read_bytes());value["python_sha256"]="0"*64;policy.write_bytes((json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode());result=self.invoke("-Sign","-PythonPath",Path(sys.executable).resolve(),"-AuthorityPrivateKeyPath",self.key,"-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy,"-SignaturePath",str(policy)+".sig");self.assertNotEqual(0,result.returncode);self.assertIn("FINALIZE_POLICY_PYTHON_HASH_MISMATCH",result.stdout+result.stderr)
 def test_source_runtime_drift_before_sign_is_rejected(self):
  source=self.root/"offline-python.exe";source.write_bytes(Path(sys.executable).read_bytes());policy=self.root/"source-drift-policy.json";prepared=self.invoke("-Prepare","-PythonPath",source,"-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy);self.assertEqual(0,prepared.returncode,prepared.stdout+prepared.stderr);source.write_bytes(source.read_bytes()+b"drift");result=self.invoke("-Sign","-PythonPath",source,"-AuthorityPrivateKeyPath",self.key,"-AuthorityPublicKeyPath",Path(str(self.key)+".pub"),"-PolicyPath",policy,"-SignaturePath",str(policy)+".sig");self.assertNotEqual(0,result.returncode);self.assertIn("FINALIZE_POLICY_PYTHON_HASH_MISMATCH",result.stdout+result.stderr);self.assertFalse(Path(str(policy)+".sig").exists())
 def test_install_contract_is_fixed_elevated_acl_only(self):
  source=SCRIPT.read_text("utf-8");build=(ROOT/"operator_packs/finex_trusted_utc_phase_d_v1/BUILD_FINEX_PHASE_D.ps1").read_text("utf-8");self.assertIn("SpecialFolder]::CommonApplicationData",source);self.assertIn("[Environment]::SystemDirectory",source);self.assertNotIn("$env:ProgramData",source+build);self.assertNotIn("$env:WINDIR",source+build);self.assertIn("phase-d-python-runtime",source+build);self.assertIn("Get-ChildItem -LiteralPath $runtime -Recurse -Force",source+build);self.assertIn("FINALIZE_POLICY_INSTALL_ELEVATION_REQUIRED",source);self.assertIn("$acl.SetOwner($admins)",source);self.assertIn("SetAccessRuleProtection($true,$false)",source);self.assertNotIn("New-NetFirewallRule",source);self.assertNotIn("Register-ScheduledTask",source);self.assertNotIn("MetaTrader",source)

if __name__=="__main__":unittest.main()
