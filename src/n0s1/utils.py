import hashlib
import logging
import os
import re
import toml
import yaml

# Global variables that will be set by the main module
DEBUG = False
cfg = {}
report_json = {}

def log_message(message, level=logging.INFO):
    global DEBUG
    debug_file = "n0s1_debug.log"

    if level == logging.NOTSET or level == logging.DEBUG:
        logging.debug(message)
    if level == logging.INFO:
        logging.info(message)
    if level == logging.WARNING:
        logging.warning(message)
    if level == logging.ERROR:
        logging.error(message)
    if level == logging.CRITICAL:
        logging.critical(message)

    if DEBUG:
        with open(debug_file, "a") as f:
            if f.tell() == 0:
                f.write("Debug logging message for n0s1\n")
            f.write(f"{message}\n")


def _safe_re_search(regex_str, text):
    global DEBUG
    m = None
    try:
        m = re.search(regex_str, text)
    except Exception:
        try:
            regex_str = regex_str.replace("(?i)", "")
            m = re.search(regex_str, text, re.IGNORECASE)
        except Exception as e:
            if DEBUG:
                log_message(str(e))
    return m


def match_regex(regex_config, text):
    for c in regex_config["rules"]:
        regex_str = c["regex"]
        modifiers = ["(?i)", "(?m)", "(?s)", "(?x)", "(?g)", "(?u)", "(?A)", "(?L)", "(?U)", ]
        for modifier in modifiers:
            if regex_str.find(modifier) > 0:
                regex_str = regex_str.replace(modifier, "")
                regex_str = modifier + regex_str
        if m := _safe_re_search(regex_str, text):
            begin = m.regs[0][0]
            end = m.regs[0][1]
            matched_text = text[begin:end]
            sanitized_text, snippet_text = sanitize_text(text, begin, end)
            tmp = text[:begin]
            lines = tmp.split("\n")
            line_number = len(lines)
            return c, matched_text, sanitized_text, snippet_text, line_number
    return None, None, None, None, None

def generate_sha1_hash(to_hash):
    try:
        message_digest = hashlib.sha256()
        string_m = str(to_hash)
        byte_m = bytes(string_m, encoding='utf')
        message_digest.update(byte_m)
        return message_digest.hexdigest()
    except TypeError as e:
        raise "Unable to generate SHA-256 hash for input string" from e


def sanitize_text(text, begin, end):
    text_len = len(text)
    s_begin = max(begin - 20, 0)
    s_end = min(end + 20, text_len)
    sanitized_text = f"{text[s_begin:begin]}<REDACTED>{text[end:s_end]}"
    snippet_text = text[s_begin:s_end]
    return sanitized_text, snippet_text

def load_regex_config(regex_config_file=None):
    if not regex_config_file:
        install_path = os.path.dirname(os.path.abspath(__file__))
        regex_config_file = f"{install_path}/config/regex.yaml"
    regex_config = None
    if os.path.exists(regex_config_file):
        with open(regex_config_file, "r") as f:
            extension = os.path.splitext(regex_config_file)[1]
            if extension.lower() == ".yaml".lower():
                regex_config = yaml.load(f, Loader=yaml.FullLoader)
            else:
                regex_config = toml.load(f)
    else:
        log_message(f"Regex file [{regex_config_file}] not found!", level=logging.WARNING)
    return regex_config


def load_n0s1_config(n0s1_config_file):
    cfg = None
    if os.path.exists(n0s1_config_file):
        with open(n0s1_config_file, "r") as f:
            cfg = yaml.load(f, Loader=yaml.FullLoader)
    else:
        log_message(f"Config file [{n0s1_config_file}] not found!", level=logging.WARNING)
    return cfg

def get_version():
    try:
        here = pathlib.Path(__file__).parent.resolve()
        init_file = pathlib.Path(here / "__init__.py")
        n0s1_version = re.search(r'^__version__ = [\'"]([^\'"]*)[\'"]', init_file.read_text(), re.M).group(1)
    except Exception:
        n0s1_version = "0.0.1"
    return n0s1_version
