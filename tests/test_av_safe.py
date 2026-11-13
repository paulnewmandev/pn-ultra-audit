"""Antivirus safety: no shipped file may contain a contiguous malware signature (Windows Defender blocked kb_trace.py for a webshell example and
the tool could not start). Payload examples are assembled from fragments at runtime instead."""
import os, re, subprocess, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
J = "".join
# the signatures themselves are assembled from fragments so THIS file does not contain them either
DENY = [J(["@ev", "al($_"]), J(["ev", "al($_POST"]), J(["eval(base", "64_decode("]), J(["eval(gz", "inflate("]), J(["assert($", "_POST"]), J(["sys", "tem($_GET"]), J(["sys", "tem($_POST"]), J(["sys", "tem($_REQUEST"]), J(["pass", "thru($_"]),
        J(["shell_", "exec($_"]), J(["EICAR-STAN", "DARD-ANTIVIRUS"]), J(["X5O!P%", "@AP[4"]), J(["bash -i >", "& /dev/tcp"]), J(["/dev/tcp/", "203."]), J(["nc -e ", "/bin/sh"]), J(["nc -e ", "/bin/bash"]), J(["str", "atum+tcp://"]),
        J(["c9", "9shell"]), J(["r5", "7shell"]), J(["b37", "4k"]), J(["Files", "Man"]), J(["China ", "Chopper"]), J(["import socket,", "subprocess,os"])]


class AvSafe(unittest.TestCase):
    def test_no_shipped_file_contains_a_contiguous_malware_signature(self):
        try: files = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"], capture_output=True, text=True, timeout=60, check=True).stdout.split("\0")
        except (OSError, subprocess.SubprocessError): self.skipTest("not a git checkout")
        bad = []
        for rel in filter(None, files):
            if rel.endswith((".png", ".jpg", ".gif", ".pdf", ".ico", ".woff", ".woff2", ".zip")): continue
            try:
                with open(os.path.join(ROOT, rel), encoding="utf-8", errors="ignore") as fh: text = fh.read()
            except OSError: continue
            low = text.lower()
            for sig in DENY:
                if sig.lower() in low: bad.append((rel, sig[:14]))
        self.assertEqual(bad, [], "malware-looking literals would make antivirus products block the repository")

    def test_the_detector_still_knows_the_signatures(self):
        from engine import malware
        self.assertTrue(any(r for r in malware.LINE_RULES if r[0] == "MAL-WEBSHELL-SIG"))
        self.assertTrue(re.search(malware.EICAR.pattern, J(["X5O!P%", "@AP[4\\PZX54(P^)7CC)7}$EI", "CAR-STANDARD-ANTIVIRUS-TE", "ST-FILE!$H+H*"]).encode()))


if __name__ == "__main__":
    unittest.main()
