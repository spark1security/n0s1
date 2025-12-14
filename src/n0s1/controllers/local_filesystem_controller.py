import logging
import os
from pathlib import Path
from typing import Iterator, Union, Dict, Any, Tuple


try:
    from . import hollow_controller as hollow_controller
except Exception:
    import n0s1.controllers.hollow_controller as hollow_controller


def read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        return None  # binary or non-text file
    except Exception:
        return None


def iter_files_from_fs_map(fs_map: Dict[str, Any], log_message=None) -> Iterator[Tuple[str, str]]:
    """
    Recursively traverses a filesystem JSON map and yields (path, content)
    for each readable text file.
    """

    if not fs_map:
        return

    # Root file case
    if fs_map.get("type") == "file":
        content = read_file(fs_map["path"])
        if content is not None:
            yield fs_map["path"], content
        return

    # Files in current directory
    for file_entry in fs_map.get("files", []):
        content = read_file(file_entry["path"])
        if content is not None:
            yield file_entry["path"], content

    # Recurse into subdirectories
    for subdir in fs_map.get("subdirectories", []):
        if log_message:
            subdir_path = subdir.get("path", None)
            total_files = len(subdir.get("files", []))
            if subdir_path:
                log_message(f"Reading [{total_files}] files from directory {subdir_path} ...", logging.INFO)
        yield from iter_files_from_fs_map(subdir, log_message)


def build_fs_map(path: Union[str, Path], levels: int = -1) -> Dict[str, Any]:
    """
    levels = -1 → no depth limit
    levels = 0 → only the current directory (no recursion)
    Output is pure JSON-compatible (dict, list, str)
    """
    path = Path(path)

    if path.is_file():
        return {
            "type": "file",
            "name": path.name,
            "path": str(path)
        }

    if not path.is_dir():
        return {}

    result = {
        "type": "directory",
        "name": path.name,
        "path": str(path),
        "files": [],
        "subdirectories": []
    }

    if levels == 0:
        return result

    next_level = levels - 1 if levels > 0 else -1

    for item in path.iterdir():
        if item.is_file():
            result["files"].append({
                "name": item.name,
                "path": str(item)
            })
        elif item.is_dir():
            result["subdirectories"].append(
                build_fs_map(item, next_level)
            )

    return result


class LocalController(hollow_controller.HollowController):
    def __init__(self):
        super().__init__()

    def set_config(self, config=None):
        super().set_config(config)
        self._path = config.get("scan_path", "")
        self._path = os.path.expanduser(self._path)
        return self.is_connected()

    def get_name(self):
        return "LocalFilesystem"

    def is_connected(self):
        if self._path:
            if os.path.exists(self._path):
                self.log_message(f"Accessing {self.get_name()} path: [{self._path}].")
                return True
            else:
                self.log_message(f"Unable to access {self._path} in {self.get_name()}. Check your permissions and if the path exists.", logging.ERROR)
                return False
        return False

    def get_mapping(self, levels=-1, limit=None):
        if not self._path:
            return {}
        message = f"Mapping path: {self._path}"
        self.log_message(message, logging.INFO)
        return build_fs_map(self._path, levels)

    def get_data(self, include_comments=False, limit=None):
        if not self._path:
            return {}

        total_files = 0
        fs_map = {}
        if self._scan_scope:
            fs_map = self._scan_scope
        else:
            fs_map = self.get_mapping()

        for file_path, file_content in iter_files_from_fs_map(fs_map, self.log_message):
            if file_path and file_content:
                file = self.pack_data(file_path, file_content)
                total_files += 1
                yield file

        message = f"Total of [{total_files}] file(s) scanned from base path: {self._path}"
        self.log_message(message, logging.INFO)

    def post_comment(self, issue, comment):
        message = f"Unable to post comment to {issue} using {self.get_name()}!"
        self.log_message(message, logging.ERROR)
        return False

    def pack_data(self, file_path, file_data):
        ticket_data = {
            "ticket": {
                "file": {
                    "name": "file",
                    "data": file_data,
                    "data_type": "str"
                },
            },
            "url": file_path,
            "issue_id": file_path
        }
        return ticket_data
