"""QThread-based async worker for running blocking IOCTL/SCM calls off the UI thread.

The worker's ``finished`` / ``failed`` signals are bounced through a small
QObject parented to the caller (which lives on the UI thread). That guarantees
``on_success`` / ``on_error`` slots run on the UI thread no matter what kind
of Python callable they are — direct connections to free functions otherwise
fire on whichever thread the signal is emitted from.
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QObject, Qt, QThread, Signal, Slot


class _WorkerObject(QObject):
    finished = Signal(object)
    failed   = Signal(str)

    def __init__(self, func: Callable[..., Any], args: tuple, kwargs: dict):
        super().__init__()
        self._func   = func
        self._args   = args
        self._kwargs = kwargs

    @Slot()
    def run(self) -> None:
        try:
            result = self._func(*self._args, **self._kwargs)
            self.finished.emit(result)
        except Exception as e:                       # noqa: BLE001 — surface every error
            self.failed.emit(f"{type(e).__name__}: {e}")


class _CallbackBouncer(QObject):
    """Lives on the UI thread; re-emits worker signals via queued connections.

    Slots connected to ``ui_success`` / ``ui_error`` therefore always run on
    the bouncer's (UI) thread, even when the source signal is emitted from
    a worker thread.
    """

    ui_success = Signal(object)
    ui_error   = Signal(str)


def run_async(parent: QObject, func: Callable[..., Any], *args,
              on_success: Callable[[Any], None] | None = None,
              on_error:   Callable[[str], None] | None = None,
              **kwargs) -> QThread:
    """Run *func* in a worker thread; deliver the result via Qt signals.

    The thread, worker, and callback bouncer are all parented to *parent*
    so Qt cleans them up; the worker is moved to the new thread, runs
    ``func``, emits finished/failed, then the thread is quit and everything
    is scheduled for deletion via ``deleteLater``.
    """
    thread   = QThread(parent)
    worker   = _WorkerObject(func, args, kwargs)
    bouncer  = _CallbackBouncer(parent)              # lives on UI thread

    worker.moveToThread(thread)

    # Worker → bouncer (cross-thread, auto-queued because of differing affinities)
    worker.finished.connect(bouncer.ui_success)
    worker.failed.connect(bouncer.ui_error)

    # Bouncer → user callbacks (same-thread → direct, runs on UI thread)
    if on_success is not None:
        bouncer.ui_success.connect(on_success, Qt.DirectConnection)
    if on_error is not None:
        bouncer.ui_error.connect(on_error, Qt.DirectConnection)

    # Worker lifecycle
    thread.started.connect(worker.run)
    worker.finished.connect(thread.quit)
    worker.failed.connect(thread.quit)

    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(bouncer.deleteLater)
    thread.finished.connect(thread.deleteLater)

    # Hold a strong reference until the thread is done (PySide6 doesn't
    # always keep workers alive via signal connections alone).
    if not hasattr(parent, "_pending_workers"):
        parent._pending_workers = []                 # type: ignore[attr-defined]
    parent._pending_workers.append((thread, worker, bouncer))

    def _cleanup():
        try:
            parent._pending_workers.remove((thread, worker, bouncer))   # type: ignore[attr-defined]
        except (ValueError, AttributeError):
            pass
    thread.finished.connect(_cleanup)

    thread.start()
    return thread
