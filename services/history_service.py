"""
history_service.py - Thread-safe persistent analysis history.
Stores up to MAX_SIZE recent analysis results in a local JSON file.
"""
from __future__ import annotations
import os
import json
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from flask import current_app

from services.sanitization_service import sanitize_result

MAX_SIZE = 50
HISTORY_FILE = "history.json"
_lock = threading.Lock()


def _history_file() -> str:
    try:
        return current_app.config.get("HISTORY_FILE", HISTORY_FILE)
    except RuntimeError:
        return HISTORY_FILE


def _history_max_size() -> int:
    try:
        return int(current_app.config.get("HISTORY_MAX_SIZE", MAX_SIZE))
    except RuntimeError:
        return MAX_SIZE


def _store_full_history() -> bool:
    try:
        return bool(current_app.config.get("STORE_FULL_HISTORY", False))
    except RuntimeError:
        return False

def _load_history() -> List[Dict[str, Any]]:
    """Internal helper to load history from the JSON file."""
    history_file = _history_file()
    if not os.path.exists(history_file):
        return []
    try:
        with open(history_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception as e:
        print(f"Error loading history: {e}")
    return []

def _save_history(history: List[Dict[str, Any]]) -> None:
    """Internal helper to save history to the JSON file."""
    try:
        history_file = _history_file()
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving history: {e}")

def add_entry(entry: Dict[str, Any]) -> None:
    """Add an analysis result to history, evicting oldest if needed."""
    with _lock:
        history = _load_history()
        stored_entry = sanitize_result(entry, keep_findings=_store_full_history())
        stored_entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        history.append(stored_entry)
        max_size = _history_max_size()
        while len(history) > max_size:
            history.pop(0)
        _save_history(history)

def get_history_summary() -> List[Dict[str, Any]]:
    """Return a copy of the history list (newest first) without full findings."""
    with _lock:
        history = _load_history()
        summaries = []
        for item in reversed(history):
            # Create a lightweight version for the list view
            summary_item = {
                "id": item.get("id"),
                "filename": item.get("filename"),
                "file_type": item.get("file_type"),
                "summary": item.get("summary"),
                "timestamp": item.get("timestamp"),
                "lines_analyzed": item.get("lines_analyzed"),
            }
            summaries.append(summary_item)
        return summaries

def get_entry_by_id(entry_id: str) -> Optional[Dict[str, Any]]:
    """Return the full analysis entry by its ID."""
    with _lock:
        history = _load_history()
        for item in history:
            if item.get("id") == entry_id:
                return item
        return None

def clear_history() -> None:
    """Clear all stored history entries."""
    with _lock:
        _save_history([])
