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

MAX_SIZE = 50
HISTORY_FILE = "history.json"
_lock = threading.Lock()

def _load_history() -> List[Dict[str, Any]]:
    """Internal helper to load history from the JSON file."""
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception as e:
        print(f"Error loading history: {e}")
    return []

def _save_history(history: List[Dict[str, Any]]) -> None:
    """Internal helper to save history to the JSON file."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"Error saving history: {e}")

def add_entry(entry: Dict[str, Any]) -> None:
    """Add an analysis result to history, evicting oldest if needed."""
    with _lock:
        history = _load_history()
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        history.append(entry)
        if len(history) > MAX_SIZE:
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
                "timestamp": item.get("timestamp")
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
