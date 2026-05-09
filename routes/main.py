"""
routes/main.py - Main page routes.
"""
from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@main_bp.route("/health")
def health():
    """Azure App Service health probe endpoint."""
    return {"status": "ok"}, 200
