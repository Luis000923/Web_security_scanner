"""DOM Syntactic Execution Context Analyzer for Reflected XSS.

Performs syntactic inspection of reflected payloads within the DOM tree to determine
if execution is syntactically viable, distinguishing real vulnerabilities from benign
reflections and safely encoded values.

Contexts analyzed:
1. SCRIPT_TAG: Inside <script> blocks (unquoted JS expressions or unescaped string literals/closing tags).
2. EVENT_HANDLER: Inside event handler attributes (onload, onerror, onclick, etc.).
3. URI_SINK: Inside href/src/action attributes (javascript: / data: URI schemes).
4. ATTRIBUTE_VALUE: Inside normal HTML attributes (requires unescaped quote breakout).
5. HTML_BODY: In HTML body text between tags (requires unescaped < and >).
6. RCDATA_TAG: Inside <textarea>, <title>, <style>, <noscript> (requires specific unescaped closing tag).
7. HTML_COMMENT: Inside <!-- ... --> comments (requires unescaped -->).
8. NON_HTML: In application/json, text/plain, etc.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment

# Attributes that act as event handlers executing JS directly
_EVENT_HANDLER_ATTR_PREFIX = "on"

# Attributes that accept executable URI schemes
_URI_SINK_ATTRS = frozenset({"href", "src", "action", "formaction", "data", "xlink:href"})

# Tags where child content is parsed as raw text (RCDATA / CDATA), not executable HTML
_RCDATA_TAGS = frozenset({"textarea", "title", "style", "noscript", "template", "xmp", "iframe"})

# Dangerous unescaped characters required for HTML breakout
_HTML_TAG_CHARS = ("<", ">")
_QUOTE_CHARS = ('"', "'")


@dataclass(frozen=True)
class XSSContextAnalysis:
    """Outcome of DOM syntactic context inspection for an XSS payload reflection."""

    is_executable: bool
    context: str
    confidence: str | None  # "CONFIRMED", "HIGH", "LOW", or None
    reason: str
    tag_name: str | None = None
    attribute_name: str | None = None


class DOMContextInspector:
    """Inspects the exact syntactic context of a reflected payload in the DOM."""

    @classmethod
    def analyze(
        cls,
        text: str,
        payload: str,
        content_type: str = "text/html",
    ) -> XSSContextAnalysis:
        if not text or not payload or payload not in text:
            return XSSContextAnalysis(
                is_executable=False,
                context="none",
                confidence=None,
                reason="Payload was not reflected in the response body.",
            )

        # 1. Non-HTML content types: cannot execute directly as HTML/DOM
        if "html" not in (content_type or "").lower():
            # In JSON or text/plain, reflection is only dangerous via content-sniffing
            return XSSContextAnalysis(
                is_executable=True,
                context="non_html",
                confidence="LOW",
                reason=f"Payload reflected in non-HTML content-type ({content_type or 'unknown'}), exploitable via MIME-sniffing only.",
            )

        # 2. URI Sink reflection (e.g. href="javascript:alert(1)")
        lower_p = payload.lower()
        if lower_p.startswith(("javascript:", "data:")):
            uri_re = re.compile(
                r'(?:href|src|action|formaction)\s*=\s*[\'"]\s*' + re.escape(payload),
                re.IGNORECASE,
            )
            if uri_re.search(text):
                return XSSContextAnalysis(
                    is_executable=True,
                    context="uri_sink",
                    confidence="HIGH",
                    reason="Executable URI scheme (javascript:/data:) reflected directly into navigation sink attribute.",
                    attribute_name="href/src",
                )

        # 3. Check for direct context breakouts in raw HTML source
        idx = text.find(payload)
        prefix = text[:idx]

        # A. Comment breakout: prefix has unclosed <!--
        last_comment_open = prefix.rfind("<!--")
        last_comment_close = prefix.rfind("-->")
        if last_comment_open != -1 and (last_comment_close == -1 or last_comment_close < last_comment_open):
            if "-->" in payload:
                return XSSContextAnalysis(
                    is_executable=True,
                    context="html_comment",
                    confidence="HIGH",
                    reason="Payload reflected in HTML comment with unescaped closing '-->' breakout.",
                )
            return XSSContextAnalysis(
                is_executable=False,
                context="html_comment",
                confidence=None,
                reason="Payload reflected harmlessly inside HTML comment without '-->' breakout.",
            )

        # B. RCDATA tag breakout: prefix has unclosed <textarea, <title, <style
        for rc_tag in _RCDATA_TAGS:
            last_open = prefix.lower().rfind(f"<{rc_tag}")
            last_close = prefix.lower().rfind(f"</{rc_tag}")
            if last_open != -1 and (last_close == -1 or last_close < last_open):
                closing_str = f"</{rc_tag}"
                if closing_str in payload.lower():
                    return XSSContextAnalysis(
                        is_executable=True,
                        context="rcdata_breakout",
                        confidence="HIGH",
                        reason=f"Payload breaks out of non-executable <{rc_tag}> tag using unescaped closing tag.",
                        tag_name=rc_tag,
                    )
                return XSSContextAnalysis(
                    is_executable=False,
                    context="rcdata_enclosed",
                    confidence=None,
                    reason=f"Payload safely enclosed inside non-executable <{rc_tag}> tag without breakout.",
                    tag_name=rc_tag,
                )

        # C. Attribute breakout: prefix ends with attr=" and payload starts with matching quote
        attr_match = re.search(r'<[a-zA-Z0-9]+[^>]*\b([a-zA-Z0-9_:-]+)\s*=\s*(["\'])$', prefix)
        if attr_match:
            attr_name = attr_match.group(1)
            quote_char = attr_match.group(2)
            if payload.startswith(quote_char):
                return XSSContextAnalysis(
                    is_executable=True,
                    context="attribute_breakout",
                    confidence="HIGH",
                    reason=f"Payload breaks out of attribute '{attr_name}' with unescaped {quote_char} quote.",
                    attribute_name=attr_name,
                )

        # 4. Parse HTML DOM using BeautifulSoup
        try:
            soup = BeautifulSoup(text, "html.parser")
        except Exception:
            # Fallback to regex-based assessment if parsing fails
            return cls._fallback_regex_analyze(text, payload)

        # Find occurrences across DOM nodes
        # A. Check inside comments
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            if payload in comment:
                # Inside comment: to execute, payload MUST break out using '-->'
                if "-->" in payload:
                    return XSSContextAnalysis(
                        is_executable=True,
                        context="html_comment",
                        confidence="HIGH",
                        reason="Payload reflected in HTML comment with unescaped closing '-->' breakout.",
                    )
                return XSSContextAnalysis(
                    is_executable=False,
                    context="html_comment",
                    confidence=None,
                    reason="Payload reflected harmlessly inside HTML comment without '-->' breakout.",
                )

        # B. Check inside <script> tags
        for script_tag in soup.find_all("script"):
            script_text = script_tag.string or script_tag.get_text()
            if script_text and payload in script_text:
                return cls._analyze_script_context(text, script_text, payload)

        # C. Check inside RCDATA tags (<textarea>, <title>, etc.)
        # Named rc_element, not rc_tag, so mypy doesn't unify it with the
        # plain tag-*name* string bound to rc_tag in the raw-text scan above
        # (same function scope, otherwise a str/Tag type clash).
        for rc_element in soup.find_all(list(_RCDATA_TAGS)):
            rc_text = rc_element.string or rc_element.get_text()
            if rc_text and payload in rc_text:
                closing_tag = f"</{rc_element.name}"
                if closing_tag.lower() in payload.lower():
                    return XSSContextAnalysis(
                        is_executable=True,
                        context="rcdata_breakout",
                        confidence="HIGH",
                        reason=f"Payload breaks out of non-executable <{rc_element.name}> tag using unescaped closing tag.",
                        tag_name=rc_element.name,
                    )
                return XSSContextAnalysis(
                    is_executable=False,
                    context="rcdata_enclosed",
                    confidence=None,
                    reason=f"Payload safely enclosed inside non-executable <{rc_element.name}> tag without breakout.",
                    tag_name=rc_element.name,
                )

        # D. Check inside element attributes
        for tag in soup.find_all(True):
            for attr_name, attr_val in list(tag.attrs.items()):
                val_str = " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
                if payload in val_str:
                    # 1. Is it an event handler attribute (onload, onerror, onclick)?
                    if attr_name.lower().startswith(_EVENT_HANDLER_ATTR_PREFIX):
                        return XSSContextAnalysis(
                            is_executable=True,
                            context="event_handler",
                            confidence="HIGH",
                            reason=f"Payload reflected inside event handler attribute '{attr_name}', executed directly as JS.",
                            tag_name=tag.name,
                            attribute_name=attr_name,
                        )

                    # 2. Regular attribute: MUST verify unescaped quote breakout in raw HTML
                    return cls._analyze_attribute_breakout(text, payload, tag.name, attr_name)

        # E. Check in HTML body text nodes
        # If payload reached here, it's reflected in standard HTML body text.
        # To execute, < and > must be present unescaped in raw HTML
        if ("<" in payload and ">" in payload) or ("<" in payload and "/" in payload):
            # Check if raw HTML contains the unescaped tags
            escaped_p = html.escape(payload)
            if escaped_p != payload and payload in text:
                return XSSContextAnalysis(
                    is_executable=True,
                    context="html_body",
                    confidence="HIGH",
                    reason="Payload reflected unescaped in HTML body, injecting raw HTML/JavaScript elements.",
                )

        # If payload only has innocuous characters or was escaped
        return XSSContextAnalysis(
            is_executable=False,
            context="html_body_inert",
            confidence=None,
            reason="Payload reflected as inert text without unescaped executable HTML tags.",
        )

    @classmethod
    def _analyze_script_context(
        cls, full_html: str, script_text: str, payload: str
    ) -> XSSContextAnalysis:
        """Inspect payload inside a <script> block."""
        # Check if payload contains </script> closing tag
        if "</script" in payload.lower():
            return XSSContextAnalysis(
                is_executable=True,
                context="script_breakout",
                confidence="HIGH",
                reason="Payload breaks out of <script> tag with unescaped </script>.",
                tag_name="script",
            )

        # Find position of payload in script
        idx = script_text.find(payload)
        prefix = script_text[:idx]

        # Check if reflection is inside a string literal ("...", '...', `...`)
        # Count preceding unescaped quotes
        double_quotes = len(re.findall(r'(?<!\\)"', prefix))
        single_quotes = len(re.findall(r"(?<!\\)'", prefix))
        backticks = len(re.findall(r"(?<!\\)`", prefix))

        in_double_quote = (double_quotes % 2) != 0
        in_single_quote = (single_quotes % 2) != 0
        in_backtick = (backticks % 2) != 0

        if in_double_quote:
            if '"' in payload and not re.search(r'\\"', payload):
                return XSSContextAnalysis(
                    is_executable=True,
                    context="script_string_breakout",
                    confidence="HIGH",
                    reason="Payload breaks out of double-quoted JS string literal with unescaped quote.",
                    tag_name="script",
                )
            return XSSContextAnalysis(
                is_executable=False,
                context="script_string_safe",
                confidence=None,
                reason="Payload enclosed in double-quoted JS string literal without unescaped breakout quote.",
                tag_name="script",
            )

        if in_single_quote:
            if "'" in payload and not re.search(r"\\'", payload):
                return XSSContextAnalysis(
                    is_executable=True,
                    context="script_string_breakout",
                    confidence="HIGH",
                    reason="Payload breaks out of single-quoted JS string literal with unescaped quote.",
                    tag_name="script",
                )
            return XSSContextAnalysis(
                is_executable=False,
                context="script_string_safe",
                confidence=None,
                reason="Payload enclosed in single-quoted JS string literal without unescaped breakout quote.",
                tag_name="script",
            )

        if in_backtick:
            if ("`" in payload and not re.search(r"\\`", payload)) or "${" in payload:
                return XSSContextAnalysis(
                    is_executable=True,
                    context="script_template_breakout",
                    confidence="HIGH",
                    reason="Payload breaks out of JS template literal with unescaped backtick or ${} interpolation.",
                    tag_name="script",
                )
            return XSSContextAnalysis(
                is_executable=False,
                context="script_template_safe",
                confidence=None,
                reason="Payload safely enclosed in JS template literal.",
                tag_name="script",
            )

        # Unquoted JS context: executes directly as a statement/expression
        return XSSContextAnalysis(
            is_executable=True,
            context="script_direct",
            confidence="HIGH",
            reason="Payload reflected directly as executable JavaScript code outside string literals.",
            tag_name="script",
        )

    @classmethod
    def _analyze_attribute_breakout(
        cls, full_html: str, payload: str, tag_name: str, attr_name: str
    ) -> XSSContextAnalysis:
        """Inspect reflection in a regular HTML attribute to verify quote breakout."""
        # Find raw attribute definition in the source HTML
        pattern = re.compile(
            rf"""<{re.escape(tag_name)}[^>]*\b{re.escape(attr_name)}\s*=\s*(["'])(.*?)\1""",
            re.IGNORECASE | re.DOTALL,
        )
        for match in pattern.finditer(full_html):
            quote = match.group(1)
            raw_val = match.group(2)

            if payload in raw_val:
                # If the raw value literally contains the unescaped breakout quote:
                if quote in payload:
                    return XSSContextAnalysis(
                        is_executable=True,
                        context="attribute_breakout",
                        confidence="HIGH",
                        reason=f"Payload contains unescaped {quote} breakout matching enclosing attribute '{attr_name}'.",
                        tag_name=tag_name,
                        attribute_name=attr_name,
                    )
                # If quotes are escaped or absent, payload cannot escape the attribute
                return XSSContextAnalysis(
                    is_executable=False,
                    context="attribute_enclosed_safe",
                    confidence=None,
                    reason=f"Payload safely contained inside attribute '{attr_name}' without unescaped {quote} breakout.",
                    tag_name=tag_name,
                    attribute_name=attr_name,
                )

        # Fallback if raw tag match wasn't found
        if any(q in payload for q in _QUOTE_CHARS) and (">" in payload or "on" in payload.lower()):
            return XSSContextAnalysis(
                is_executable=True,
                context="attribute_breakout",
                confidence="HIGH",
                reason=f"Payload breaks out of attribute '{attr_name}' with quotes and injects HTML/events.",
                tag_name=tag_name,
                attribute_name=attr_name,
            )

        return XSSContextAnalysis(
            is_executable=False,
            context="attribute_safe",
            confidence=None,
            reason=f"Payload safely enclosed in attribute '{attr_name}'.",
            tag_name=tag_name,
            attribute_name=attr_name,
        )

    @classmethod
    def _fallback_regex_analyze(cls, text: str, payload: str) -> XSSContextAnalysis:
        """Fallback syntactic heuristic when HTML parsing fails."""
        if any(c in payload for c in ("<", ">", '"', "'")) and payload in text:
            return XSSContextAnalysis(
                is_executable=True,
                context="regex_fallback",
                confidence="HIGH",
                reason="Payload with dangerous characters reflected verbatim in document.",
            )
        return XSSContextAnalysis(
            is_executable=False,
            context="regex_fallback",
            confidence=None,
            reason="Payload contains no dangerous breakout characters.",
        )
