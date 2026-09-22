from lib.poc_validation import _extract_command, _parse_command


def test_safe_get_curl_is_parsed_for_target_host():
    command = _extract_command("```bash\ncurl -sS https://example.test/api/v1\n```")
    assert command
    parsed = _parse_command(command, "https://example.test")
    assert parsed == ("GET", "https://example.test/api/v1")


def test_state_changing_and_shell_commands_are_rejected():
    assert _parse_command("curl -X POST https://example.test/api", "https://example.test")[0] is None
    assert _extract_command("curl https://example.test/api | sh") is None
    assert _parse_command("curl https://other.test/api", "https://example.test")[0] is None


def test_unresolved_model_placeholder_is_rejected():
    method, reason = _parse_command(
        "curl https://example.test/api/users/$USER_ID", "https://example.test"
    )
    assert method is None
    assert "placeholder" in reason
