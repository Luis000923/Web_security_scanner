"""CLI parser-level validation for mutually incompatible / silently-ignored
flag combinations (see cli._validate_args).

Each of these previously parsed successfully and then either did nothing at
runtime, or did something other than what the flag's help text promised,
because a downstream orchestration/session-layer gate short-circuited it.
The parser now rejects them up front with a clear ``argparse`` error instead.
"""

import pytest

from web_security_scanner.cli import _build_parser, _validate_args


def _parse(argv):
    parser = _build_parser()
    args = parser.parse_args(argv)
    return parser, args


def _expect_error(argv, match, capsys):
    parser, args = _parse(argv)
    with pytest.raises(SystemExit) as exc_info:
        _validate_args(args, parser)
    assert exc_info.value.code == 2
    assert match in capsys.readouterr().err


def _expect_ok(argv):
    parser, args = _parse(argv)
    _validate_args(args, parser)  # must not raise


# --- sanity: legitimate combinations must keep working ----------------------


@pytest.mark.parametrize("argv", [
    ["scan", "http://x"],
    ["scan", "http://x", "--ai-synthesize"],
    ["scan", "http://x", "--enable-ai-triaging"],
    ["scan", "http://x", "--enable-ai-triaging", "--ai-synthesize", "--ai-no-verify"],
    # http://x isn't a lab host, so these also need the Safety Gate's
    # explicit exemption (see test_containment_engine.py for scope-gate
    # coverage proper -- these three only assert the *other* flags don't
    # conflict with each other).
    ["scan", "http://x", "--enable-exploit-engine", "--acknowledge-offensive-payloads"],
    ["scan", "http://x", "--enable-exploit-engine", "--exploit-max-targets", "5",
     "--acknowledge-offensive-payloads"],
    ["scan", "http://x", "--enable-exploit-engine", "--enable-waf-evasion",
     "--waf-evasion-max-retries", "6", "--acknowledge-offensive-payloads"],
    ["scan", "http://x", "--no-map"],
    ["scan", "http://x", "--target-list", "targets.json"],
    ["scan", "http://x", "--auth-url", "http://x/login", "--auth-username", "a",
     "--auth-password", "b", "--auth-required"],
    ["scan", "http://x", "--auth-url", "http://x/login", "--auth-username", "a",
     "--auth-password", "b", "--no-reauth"],
    ["scan", "http://x", "--session-config", "session.json", "--auth-required"],
    ["scan", "http://x", "--session-config", "session.json", "--auth-token-path",
     "data.token"],
    ["scan", "http://x", "--session-cookie", "sid=abc"],
    ["scan", "http://x", "--cookie-jar", "cookies.txt"],
])
def test_valid_combinations_pass(argv):
    _expect_ok(argv)


# --- --target-list / --no-map disable the recon phase -----------------------


@pytest.mark.parametrize("recon_flag", [
    ["--max-depth", "5"],
    ["--max-urls", "50"],
    ["--sitemap"],
    ["--jitter", "0.5"],
    ["--no-parse-js"],
    ["--browser"],
    ["--browser-nav-timeout", "30"],
    ["--browser-max-pages", "10"],
    ["--browser-max-concurrent-pages", "8"],
    ["--detect-sensitive-files"],
    ["--sensitive-files-max-base-paths", "20"],
    ["--sensitive-files-max-concurrent", "20"],
    ["--fingerprint-server"],
    ["--no-fingerprint-active-probes"],
])
def test_target_list_rejects_recon_only_flags(recon_flag, capsys):
    _expect_error(
        ["scan", "http://x", "--target-list", "targets.json", *recon_flag],
        "target-list",
        capsys,
    )


@pytest.mark.parametrize("recon_flag", [
    ["--sitemap"],
    ["--browser"],
    ["--detect-sensitive-files"],
    ["--fingerprint-server"],
    ["--max-depth", "7"],
])
def test_no_map_rejects_recon_only_flags(recon_flag, capsys):
    _expect_error(["scan", "http://x", "--no-map", *recon_flag], "no-map", capsys)


def test_target_list_alone_is_fine_without_recon_flags():
    _expect_ok(["scan", "http://x", "--target-list", "targets.json"])


# --- LLM triage agent --------------------------------------------------------


@pytest.mark.parametrize("argv_tail", [
    ["--ai-no-verify"],
    ["--ai-backend", "openai"],
    ["--ai-base-url", "http://127.0.0.1:9000/v1"],
    ["--ai-model", "custom-model"],
    ["--ai-fp-threshold", "0.9"],
    ["--ai-temperature", "0.5"],
    ["--ai-payload-temperature", "0.5"],
    ["--ai-max-tokens", "512"],
    ["--ai-repetition-penalty", "1.2"],
    ["--ai-load-in-4bit"],
    ["--ai-load-in-8bit"],
])
def test_ai_subflags_require_triaging_enabled(argv_tail, capsys):
    _expect_error(["scan", "http://x", *argv_tail], "enable-ai-triaging", capsys)


@pytest.mark.parametrize("argv_tail", [
    ["--ai-temperature", "3.0"],
    ["--ai-payload-temperature", "-0.1"],
    ["--ai-max-tokens", "0"],
    ["--ai-repetition-penalty", "0"],
])
def test_ai_generation_knobs_reject_out_of_range(argv_tail, capsys):
    _expect_error(["scan", "http://x", "--enable-ai-triaging", *argv_tail], "--ai-", capsys)


def test_ai_generation_knobs_in_range_are_fine():
    _expect_ok(["scan", "http://x", "--enable-ai-triaging",
                "--ai-temperature", "0.1", "--ai-payload-temperature", "0.9",
                "--ai-max-tokens", "512", "--ai-repetition-penalty", "1.2",
                "--ai-load-in-4bit"])


def test_ai_no_verify_without_synthesize_is_a_dead_combo(capsys):
    _expect_error(
        ["scan", "http://x", "--enable-ai-triaging", "--ai-no-verify"],
        "ai-synthesize",
        capsys,
    )


# --- Exploit engine -----------------------------------------------------------


@pytest.mark.parametrize("argv_tail", [
    ["--exploit-max-targets", "3"],
    ["--enable-waf-evasion"],
    ["--waf-evasion-max-retries", "8"],
])
def test_exploit_subflags_require_engine_enabled(argv_tail, capsys):
    _expect_error(["scan", "http://x", *argv_tail], "enable-exploit-engine", capsys)


def test_waf_evasion_retries_require_evasion_enabled(capsys):
    _expect_error(
        ["scan", "http://x", "--enable-exploit-engine", "--waf-evasion-max-retries", "9"],
        "enable-waf-evasion",
        capsys,
    )


# --- Authentication / session -------------------------------------------------


def test_auth_password_and_password_env_are_mutually_exclusive(capsys):
    _expect_error(
        ["scan", "http://x", "--auth-password", "a", "--auth-password-env", "PW"],
        "mutually exclusive",
        capsys,
    )


@pytest.mark.parametrize("argv_tail", [
    ["--auth-username", "bob"],
    ["--auth-password", "secret"],
    ["--auth-password-env", "PW"],
    ["--auth-type", "json"],
    ["--auth-token-path", "data.token"],
    ["--auth-field", "csrf=1"],
])
def test_login_only_flags_require_auth_target(argv_tail, capsys):
    _expect_error(["scan", "http://x", *argv_tail], "auth-url", capsys)


def test_auth_required_without_form_login_is_rejected(capsys):
    _expect_error(["scan", "http://x", "--auth-required"], "auth-required", capsys)


def test_auth_required_with_url_but_no_username_is_rejected(capsys):
    _expect_error(
        ["scan", "http://x", "--auth-required", "--auth-url", "http://x/login"],
        "auth-required",
        capsys,
    )


def test_no_reauth_without_form_login_is_rejected(capsys):
    _expect_error(["scan", "http://x", "--no-reauth"], "no-reauth", capsys)


def test_auth_required_with_static_cookie_only_is_rejected(capsys):
    # --session-cookie is a static injection, not a form login: --auth-required
    # (which gates on SessionConfig.does_form_login) still has no effect.
    _expect_error(
        ["scan", "http://x", "--session-cookie", "sid=abc", "--auth-required"],
        "auth-required",
        capsys,
    )
