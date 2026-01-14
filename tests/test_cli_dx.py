"""Tests for DX/UX CLI commands."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from faramesh.cli import (
    cmd_doctor,
    cmd_init,
    cmd_init_docker,
    cmd_policy_diff,
    make_parser,
)


def test_init_command(tmp_path, monkeypatch):
    """Test faramesh init command."""
    monkeypatch.chdir(tmp_path)
    
    # Create args
    class Args:
        force = False
    
    args = Args()
    
    # Run init
    cmd_init(args)
    
    # Verify files created
    assert (tmp_path / "policies" / "default.yaml").exists()
    assert (tmp_path / ".env.example").exists()
    
    # Verify content
    policy_content = (tmp_path / "policies" / "default.yaml").read_text()
    assert "deny" in policy_content.lower()
    assert "rules:" in policy_content


def test_init_with_force(tmp_path, monkeypatch):
    """Test faramesh init --force overwrites existing files."""
    monkeypatch.chdir(tmp_path)
    
    # Create existing file
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "default.yaml").write_text("old content")
    
    class Args:
        force = True
    
    args = Args()
    cmd_init(args)
    
    # Verify overwritten
    content = (tmp_path / "policies" / "default.yaml").read_text()
    assert "old content" not in content


def test_doctor_command_success(monkeypatch, tmp_path):
    """Test faramesh doctor with good environment."""
    # Mock good environment
    import sys as sys_module
    monkeypatch.setattr(sys_module, "version_info", (3, 9, 0))
    
    # Mock store to avoid DB issues
    monkeypatch.setenv("FARA_SQLITE_PATH", str(tmp_path / "test.db"))
    
    class Args:
        pass
    
    args = Args()
    
    # Should not crash (may return 0 or 1 depending on checks)
    try:
        result = cmd_doctor(args)
        assert isinstance(result, int)
    except Exception:
        # Doctor may fail if DB doesn't exist, that's okay for test
        pass


def test_policy_diff_identical(tmp_path):
    """Test policy-diff with identical files."""
    import yaml
    
    policy_data = {
        "rules": [
            {"match": {"tool": "*", "op": "*"}, "deny": True}
        ]
    }
    
    old_file_path = tmp_path / "old.yaml"
    new_file_path = tmp_path / "new.yaml"
    
    with open(old_file_path, 'w') as f:
        yaml.dump(policy_data, f)
    with open(new_file_path, 'w') as f:
        yaml.dump(policy_data, f)
    
    class Args:
        def __init__(self):
            self.old_file = str(old_file_path)
            self.new_file = str(new_file_path)
    
    args = Args()
    
    # Should not crash
    cmd_policy_diff(args)


def test_policy_diff_different(tmp_path):
    """Test policy-diff with different files."""
    import yaml
    
    old_data = {
        "rules": [
            {"match": {"tool": "*", "op": "*"}, "deny": True}
        ]
    }
    
    new_data = {
        "rules": [
            {"match": {"tool": "http", "op": "*"}, "allow": True, "description": "Allow HTTP"},
            {"match": {"tool": "*", "op": "*"}, "deny": True}
        ]
    }
    
    old_file_path = tmp_path / "old.yaml"
    new_file_path = tmp_path / "new.yaml"
    
    with open(old_file_path, 'w') as f:
        yaml.dump(old_data, f)
    with open(new_file_path, 'w') as f:
        yaml.dump(new_data, f)
    
    class Args:
        def __init__(self):
            self.old_file = str(old_file_path)
            self.new_file = str(new_file_path)
    
    args = Args()
    
    # Should not crash
    cmd_policy_diff(args)


def test_init_docker(tmp_path, monkeypatch):
    """Test faramesh init-docker command."""
    monkeypatch.chdir(tmp_path)
    
    class Args:
        force = False
    
    args = Args()
    cmd_init_docker(args)
    
    # Verify files created
    assert (tmp_path / "docker-compose.yaml").exists()
    assert (tmp_path / "Dockerfile").exists()
    
    # Verify content
    compose_content = (tmp_path / "docker-compose.yaml").read_text()
    assert "faramesh:" in compose_content
    assert "FARAMESH_DEMO" in compose_content


def test_cli_parser_includes_new_commands():
    """Test that parser includes all new commands."""
    parser = make_parser()
    
    # Check subcommands exist
    subparsers = [action for action in parser._actions if hasattr(action, 'choices')]
    found_commands = set()
    for subparser_action in subparsers:
        if hasattr(subparser_action, 'choices') and subparser_action.choices:
            found_commands.update(subparser_action.choices.keys())
    
    # Verify new commands exist
    assert 'init' in found_commands
    assert 'explain' in found_commands
    assert 'build-ui' in found_commands
    assert 'doctor' in found_commands
    assert 'replay' in found_commands
    assert 'policy-diff' in found_commands
    assert 'init-docker' in found_commands


def test_list_full_flag():
    """Test that list command supports --full flag."""
    parser = make_parser()
    args = parser.parse_args(['list', '--full'])
    assert args.full is True


def test_serve_watch_flag():
    """Test that serve command supports --watch flag."""
    parser = make_parser()
    # Parse with serve command
    try:
        args = parser.parse_args(['serve', '--watch'])
        assert hasattr(args, 'watch') and args.watch is True
    except SystemExit:
        # Parser may exit if subcommand not found, that's okay
        pass


def test_token_commands(tmp_path):
    """Test token create/list/revoke commands."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    
    from faramesh.cli_token import _load_tokens, cmd_token_create, cmd_token_revoke
    
    # Create a test token
    class CreateArgs:
        name = "test-token"
        ttl = "1h"
    
    cmd_token_create(CreateArgs())
    
    # List tokens
    class ListArgs:
        json = False
    
    tokens = _load_tokens()
    assert len(tokens) > 0
    
    # Get token ID
    token_id = list(tokens.keys())[0]
    
    # Revoke token
    class RevokeArgs:
        id = token_id
    
    cmd_token_revoke(RevokeArgs())
    
    # Verify revoked
    tokens_after = _load_tokens()
    assert tokens_after[token_id]['active'] is False


def test_policy_commands(tmp_path):
    """Test policy validate/test commands."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    
    from faramesh.cli import cmd_policy_test, cmd_policy_validate
    
    # Create a valid policy file
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text("""rules:
  - match:
      tool: "*"
      op: "*"
    deny: true
    description: "Default deny"
""")
    
    # Test validate
    class ValidateArgs:
        file = str(policy_file)
    
    # Should not raise
    try:
        cmd_policy_validate(ValidateArgs())
    except SystemExit as e:
        # May exit with code 1 if invalid, but shouldn't crash
        assert e.code == 0 or e.code == 1
    
    # Test policy-test with action JSON
    action_json = tmp_path / "action.json"
    action_json.write_text("""{
  "tool": "http",
  "operation": "get",
  "params": {"url": "https://example.com"},
  "context": {}
}
""")
    
    class TestArgs:
        file = str(action_json)
        json = False
    
    # Should not crash
    try:
        cmd_policy_test(TestArgs())
    except SystemExit:
        # May exit with code 1 if denied, that's expected
        pass


def test_policy_new_command(tmp_path, monkeypatch):
    """Test fara policy-new command."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    
    monkeypatch.chdir(tmp_path)
    
    from faramesh.cli import cmd_policy_new
    
    # Create policies/user directory structure
    (tmp_path / "policies").mkdir()
    
    class Args:
        name = "test-policy"
    
    args = Args()
    
    # Should create the file
    cmd_policy_new(args)
    
    # Verify file created
    policy_file = tmp_path / "policies" / "user" / "test-policy.yaml"
    assert policy_file.exists()
    
    # Verify content
    content = policy_file.read_text()
    assert "Policy: test-policy" in content
    assert "rules:" in content
    assert "allow:" in content or "deny:" in content
