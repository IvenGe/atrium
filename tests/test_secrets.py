"""SecretBox: Fernet encryption of stored credentials, with HUB_SECRET_KEY or a generated key file."""

import os
import stat

import pytest
from cryptography.fernet import Fernet

from hub.config import Settings
from hub.secrets import KEY_FILE, SecretBox, SecretError


def test_key_file_is_created_on_first_use_and_reused(tmp_path):
    box = SecretBox(key_file=tmp_path / "data" / KEY_FILE)
    assert not (tmp_path / "data" / KEY_FILE).exists()  # nothing happens until a secret is stored
    token = box.encrypt("hunter2-but-longer")
    assert token != "hunter2-but-longer" and "hunter2" not in token
    key_file = tmp_path / "data" / KEY_FILE
    assert key_file.is_file()
    if os.name == "posix":
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    again = SecretBox(key_file=key_file)  # a restarted hub reads the same key
    assert again.decrypt(token) == "hunter2-but-longer"
    assert box.source == "key file"


def test_environment_key_wins_and_rotates(tmp_path):
    old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
    token = SecretBox(old).encrypt("api-token-1")
    rotated = SecretBox(f"{new},{old}")  # the first key encrypts, every key decrypts
    assert rotated.decrypt(token) == "api-token-1"
    assert SecretBox(new).decrypt(rotated.encrypt("x")) == "x"
    assert rotated.source == "HUB_SECRET_KEY"
    settings = Settings(data_dir=tmp_path, secret_key=old)
    box = SecretBox.for_settings(settings)
    assert box.decrypt(token) == "api-token-1"
    assert not (tmp_path / KEY_FILE).exists()


def test_wrong_or_invalid_keys_fail_clearly(tmp_path):
    token = SecretBox(Fernet.generate_key().decode()).encrypt("value")
    with pytest.raises(SecretError, match="enter the secret again"):
        SecretBox(Fernet.generate_key().decode()).decrypt(token)
    with pytest.raises(SecretError, match="Fernet keys"):
        SecretBox("not-a-key").encrypt("value")
    with pytest.raises(SecretError):
        SecretBox().encrypt("value")  # neither a key nor a key file


def test_settings_read_the_key_from_the_environment(tmp_path, monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HUB_SECRET_KEY", key)
    monkeypatch.setenv("HUB_FLOW_INTERVAL", "12")
    settings = Settings.from_env()
    assert settings.secret_key == key and settings.flow_interval == 12.0
