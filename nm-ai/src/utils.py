import calendar
import logging
import os

logger = logging.getLogger(__name__)


def ensure_dir(path):
    if not path:
        return
    os.makedirs(path, exist_ok=True)


def extract_and_increment_month(filename):
    """Extract month name from filename and bump to the next month name."""
    basename = os.path.basename(filename)
    previous_month = basename.replace('_', ' ').split()[0].strip().title()
    logger.info("Previous File Month: %s", previous_month)
    try:
        idx = list(calendar.month_name).index(previous_month)
        next_idx = idx % 12 + 1
        next_month = calendar.month_name[next_idx]
        return previous_month, next_month
    except ValueError as exc:
        raise ValueError(f"Error: '{previous_month}' not a valid month name") from exc


def build_workdir(outdir, name="_tmp"):
    """Create and return a temp work directory under outdir."""
    if not outdir:
        outdir = "."
    workdir = os.path.join(outdir, name)
    ensure_dir(workdir)
    return workdir
