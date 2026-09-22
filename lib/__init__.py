


def sanitize_cmd_for_log(cmd: list[str]) -> str:
    """Remove auth tokens from command for safe logging.

    Recognises three patterns:
    - ``-H`` / ``Authorization:`` pairs (curl-style headers — most tools)
    - ``--security-schemes`` flags (vulnapi)
    - ``-u`` short flag (basic auth flag used by some tools)
    """
    safe = []
    skip_next = False
    for part in cmd:
        if skip_next:
            safe.append("***")
            skip_next = False
        elif part in ("-H", "--security-schemes", "-u"):
            safe.append(part)
            skip_next = True
        elif part.startswith(("Authorization:", "bearer=", "Bearer=", "Cookie:", "X-API-Key:", "api-key=")):
            safe.append(f"{part.split(':', 1)[0]}: ***" if ":" in part else "***")
        else:
            safe.append(part)
    return " ".join(safe)
