"""
In-process background task queue (lightweight alternative to Celery for this project).
"""

import queue
import threading
import time
import traceback
from typing import Any, Callable, Dict, Optional


class BackgroundQueue:
    def __init__(self, workers: int = 2):
        self._queue: queue.Queue = queue.Queue()
        self._workers = workers
        self._running = False
        self._threads: list = []
        self._stats = {"processed": 0, "failed": 0, "last_error": None}

    def start(self):
        if self._running:
            return
        self._running = True
        for i in range(self._workers):
            t = threading.Thread(target=self._worker_loop, name=f"cds-worker-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._running = False
        for _ in self._threads:
            self._queue.put(None)
        self._threads.clear()

    def submit(self, fn: Callable, *args, **kwargs) -> None:
        self._queue.put((fn, args, kwargs))

    def _worker_loop(self):
        while self._running:
            item = self._queue.get()
            if item is None:
                break
            fn, args, kwargs = item
            try:
                fn(*args, **kwargs)
                self._stats["processed"] += 1
            except Exception as exc:
                self._stats["failed"] += 1
                self._stats["last_error"] = str(exc)
                traceback.print_exc()
            finally:
                self._queue.task_done()
            time.sleep(0.01)

    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)


_queue: Optional[BackgroundQueue] = None
_lock = threading.Lock()


def get_background_queue() -> BackgroundQueue:
    global _queue
    with _lock:
        if _queue is None:
            _queue = BackgroundQueue(workers=2)
            _queue.start()
        return _queue
