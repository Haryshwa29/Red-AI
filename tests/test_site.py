"""RED-AI Practice Range: flags are reachable via their intended bug class."""
import base64
import unittest
from redai_range import site


def body(path, query="", headers=None):
    code, _, b = site.respond(path, query, headers or {})
    return code, b.decode("utf-8", "replace")


class TestPracticeRange(unittest.TestCase):
    def test_index_and_robots(self):
        self.assertEqual(body("/")[0], 200)
        self.assertIn("/s3cr3t-admin/", body("/robots.txt")[1])

    def test_content_discovery_and_secrets(self):
        self.assertIn("FLAG{exposed_backup_file}", body("/backup/flag.txt")[1])
        self.assertIn("FLAG{dotenv_secret_leak}", body("/.env")[1])
        self.assertIn("FLAG{directory_listing}", body("/uploads/notes.txt")[1])
        self.assertIn("FLAG{robots_breadcrumb}", body("/s3cr3t-admin/")[1])

    def test_hidden_internal(self):
        self.assertIn("FLAG{hidden_internal_dashboard}", body("/internal")[1])

    def test_lfi_traversal(self):
        self.assertIn("FLAG{lfi_path_traversal}", body("/view", "file=../../flag")[1])
        self.assertIn("root:x:0:0", body("/view", "file=/etc/passwd")[1])

    def test_sqli_union(self):
        code, out = body("/product", "id=1' UNION SELECT flag,'' FROM secret--")
        self.assertIn("FLAG{sqli_union_select}", out)

    def test_default_creds_basic_auth(self):
        self.assertEqual(body("/admin")[0], 401)
        ok = "Basic " + base64.b64encode(b"admin:admin").decode()
        self.assertIn("FLAG{default_credentials}", body("/admin", "", {"Authorization": ok})[1])

    def test_command_injection_simulated(self):
        self.assertIn("FLAG{command_injection}", body("/ping", "host=127.0.0.1; cat flag")[1])

    def test_idor_and_cookie(self):
        self.assertIn("FLAG{idor_broken_access}", body("/api/user", "id=1337")[1])
        tampered = base64.b64encode(b"role=admin").decode()
        self.assertIn("FLAG{cookie_tampering_weak_session}",
                      body("/account", "", {"Cookie": f"session={tampered}"})[1])

    def test_no_real_filesystem_access(self):
        # the LFI backend must NOT serve a real host file
        self.assertEqual(body("/view", "file=/home/claude/redai-work/pyproject.toml")[0], 404)


if __name__ == "__main__":
    unittest.main()
