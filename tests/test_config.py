import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from paradox import config


class ExposedKeysTests(unittest.TestCase):
    def warnings(self, mode, posix=True):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("sys.stderr", io.StringIO()) as err, mock.patch.object(config, "POSIX_MODES", posix):
            path = Path(d) / ".env"
            path.write_text("SOME_KEY=s3cret\n")
            path.chmod(mode)
            config.load_dotenv(path)
            self.assertEqual(os.environ["SOME_KEY"], "s3cret")      # still loads
        return err.getvalue()

    def test_private_file_is_quiet(self):
        self.assertEqual(self.warnings(0o600), "")

    def test_group_or_world_access_warns_once_without_contents(self):
        for mode in (0o644, 0o640, 0o604):
            text = self.warnings(mode)
            self.assertEqual(text.count("warning"), 1, oct(mode))
            self.assertIn("chmod 600", text)
            self.assertNotIn("s3cret", text)

    def test_platforms_without_posix_modes_are_quiet(self):
        self.assertEqual(self.warnings(0o644, posix=False), "")


class DotenvTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {}, clear=True):
            path = Path(d) / ".env"
            path.write_text(text)
            config.load_dotenv(path)
            return dict(os.environ)

    def test_inline_comments_are_not_values(self):
        env = self.load("OTX_API_KEY=            # optional, raises limits\n"
                        "ABUSEIPDB_API_KEY=abc123  # mine\n"
                        "VIRUSTOTAL_API_KEY=\t# tab comment\n")
        self.assertEqual(env["OTX_API_KEY"], "")
        self.assertEqual(env["ABUSEIPDB_API_KEY"], "abc123")
        self.assertEqual(env["VIRUSTOTAL_API_KEY"], "")

    def test_quoted_values_keep_hashes(self):
        env = self.load('A="has # hash"  # comment\nB=\'x#y\'\nC=plain#nospace\n')
        self.assertEqual(env, {"A": "has # hash", "B": "x#y", "C": "plain#nospace"})

    def test_existing_environment_wins(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"K": "shell"}, clear=True):
            (Path(d) / ".env").write_text("K=file\n")
            config.load_dotenv(Path(d) / ".env")
            self.assertEqual(os.environ["K"], "shell")


if __name__ == "__main__":
    unittest.main()
