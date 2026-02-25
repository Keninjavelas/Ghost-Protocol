"""
sandbox/docker_manager.py
Manages isolated Docker containers per attacker session.
- No outbound networking (network=none)
- CPU/memory limits applied
- Auto-remove on destroy
"""
from __future__ import annotations

import asyncio
from typing import Optional

import docker
import structlog
from docker.errors import DockerException, NotFound

from config.settings import settings

log = structlog.get_logger(__name__)


class DockerManager:
    """Wraps the docker SDK in async-compatible methods via run_in_executor."""

    def __init__(self) -> None:
        self._client: Optional[docker.DockerClient] = None

    def _get_client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    async def spawn_container(self, session_id: str) -> str:
        """
        Spawn a sandboxed Docker container for the given session.
        Returns the container ID.
        """
        loop = asyncio.get_event_loop()
        container_id = await loop.run_in_executor(
            None, self._spawn_container_sync, session_id
        )
        return container_id

    def _spawn_container_sync(self, session_id: str) -> str:
        client = self._get_client()
        try:
            container = client.containers.run(
                image=settings.SANDBOX_IMAGE,
                command="sleep infinity",
                detach=True,
                name=f"ghost_sandbox_{session_id[:8]}",
                network_mode=settings.SANDBOX_NETWORK,  # "none" – no outbound
                mem_limit=settings.SANDBOX_MEM_LIMIT,
                cpu_quota=settings.SANDBOX_CPU_QUOTA,
                cpu_period=100000,
                read_only=False,
                remove=settings.SANDBOX_AUTO_REMOVE,
                user="nobody",
                labels={
                    "ghost.session_id": session_id,
                    "ghost.managed": "true",
                },
            )
            log.info(
                "container_started",
                session_id=session_id,
                container_id=container.id[:12],
                image=settings.SANDBOX_IMAGE,
            )
            return container.id
        except DockerException as exc:
            log.error("container_start_failed", session_id=session_id, error=str(exc))
            raise

    async def destroy_container(self, container_id: str) -> None:
        """Stop and remove the container."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._destroy_container_sync, container_id)

    def _destroy_container_sync(self, container_id: str) -> None:
        client = self._get_client()
        try:
            container = client.containers.get(container_id)
            container.stop(timeout=3)
            container.remove(force=True)
            log.info("container_removed", container_id=container_id[:12])
        except NotFound:
            log.info("container_already_gone", container_id=container_id[:12])
        except DockerException as exc:
            log.warning("container_remove_error", error=str(exc))

    async def is_container_running(self, container_id: str) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._is_running_sync, container_id
        )

    def _is_running_sync(self, container_id: str) -> bool:
        try:
            container = self._get_client().containers.get(container_id)
            return container.status == "running"
        except (NotFound, DockerException):
            return False

    def close(self) -> None:
        if self._client:
            self._client.close()
            self._client = None
