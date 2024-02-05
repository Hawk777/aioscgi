"""Tests the core module."""

from __future__ import annotations

import asyncio
from typing import Self
from unittest import TestCase

from aioscgi.container import Container
from aioscgi.lifespan import Manager
from aioscgi.types import EventOrScope, ReceiveFunction, SendFunction


class TestManager(TestCase):
    """Tests the lifespan manager."""

    def test_lifespan_startup_successful(self: Self) -> None:
        """Test successful application startup using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            startup_seen = False
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal startup_seen, shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                startup_seen = True
                await send({"type": "lifespan.startup.complete"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()
            started_called = False

            def started(error_message: str | None) -> None:
                nonlocal started_called
                assert error_message is None
                started_called = True

            def shutdown_complete(_error_message: str | None) -> None:
                raise NotImplementedError

            uut = Manager(
                Container(app, None),
                loop.create_future(),
                asyncio.Lock(),
                started,
                loop.create_future(),
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(startup_seen)
            self.assertFalse(started_called)
            self.assertFalse(shutdown_seen)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished.
            self.assertTrue(startup_seen)
            self.assertTrue(started_called)
            self.assertFalse(shutdown_seen)

            # The lifespan manager should keep running after a successful start, so
            # cancel it.
            uut_future.cancel()
            await uut_future

        asyncio.run(impl())

    def test_lifespan_startup_failed(self: Self) -> None:
        """Test failed application startup using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            startup_seen = False
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal startup_seen, shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                startup_seen = True
                await send({"type": "lifespan.startup.failed", "message": "FOO"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()
            started_called = False

            def started(error_message: str | None) -> None:
                nonlocal started_called
                assert error_message == "FOO"
                started_called = True

            def shutdown_complete(_error_message: str | None) -> None:
                raise NotImplementedError

            uut = Manager(
                Container(app, None),
                loop.create_future(),
                asyncio.Lock(),
                started,
                loop.create_future(),
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(startup_seen)
            self.assertFalse(started_called)
            self.assertFalse(shutdown_seen)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished.
            self.assertTrue(startup_seen)
            self.assertTrue(started_called)
            self.assertFalse(shutdown_seen)

            # The lifespan manager should return promptly after failed startup.
            await uut_future

        asyncio.run(impl())

    def test_lifespan_shutdown_successful(self: Self) -> None:
        """Test successful application shutdown using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                await send({"type": "lifespan.startup.complete"})
                event = await receive()
                assert event["type"] == "lifespan.shutdown"
                shutdown_seen = True
                await send({"type": "lifespan.shutdown.complete"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()

            def started(error_message: str | None) -> None:
                assert error_message is None

            shutdown_complete_called = False

            def shutdown_complete(error_message: str | None) -> None:
                nonlocal shutdown_complete_called
                assert error_message is None
                shutdown_complete_called = True

            shutting_down = loop.create_future()
            uut = Manager(
                Container(app, None),
                loop.create_future(),
                asyncio.Lock(),
                started,
                shutting_down,
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished, but shutdown should not have
            # started.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Initiate shutdown.
            shutting_down.set_result(None)

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, shutdown should have finished.
            self.assertTrue(shutdown_seen)
            self.assertTrue(shutdown_complete_called)

            # The lifespan manager should return promptly after shutdown.
            await uut_future

        asyncio.run(impl())

    def test_lifespan_shutdown_failed(self: Self) -> None:
        """Test failed application shutdown using the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            shutdown_seen = False

            async def app(
                scope: EventOrScope, receive: ReceiveFunction, send: SendFunction
            ) -> None:
                nonlocal shutdown_seen
                assert scope["type"] == "lifespan"
                event = await receive()
                assert event["type"] == "lifespan.startup"
                await send({"type": "lifespan.startup.complete"})
                event = await receive()
                assert event["type"] == "lifespan.shutdown"
                shutdown_seen = True
                await send({"type": "lifespan.shutdown.failed", "message": "FOO"})

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()

            def started(error_message: str | None) -> None:
                assert error_message is None

            shutdown_complete_called = False

            def shutdown_complete(error_message: str | None) -> None:
                nonlocal shutdown_complete_called
                assert error_message == "FOO"
                shutdown_complete_called = True

            shutting_down = loop.create_future()
            uut = Manager(
                Container(app, None),
                loop.create_future(),
                asyncio.Lock(),
                started,
                shutting_down,
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished, but shutdown should not have
            # started.
            self.assertFalse(shutdown_seen)
            self.assertFalse(shutdown_complete_called)

            # Initiate shutdown.
            shutting_down.set_result(None)

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, shutdown should have finished.
            self.assertTrue(shutdown_seen)
            self.assertTrue(shutdown_complete_called)

            # The lifespan manager should return promptly after shutdown.
            await uut_future

        asyncio.run(impl())

    def test_lifespan_not_supported(self: Self) -> None:
        """Test an application not supporting the lifespan protocol."""

        async def impl() -> None:
            # Create the application.
            async def app(
                _scope: EventOrScope, _receive: ReceiveFunction, _send: SendFunction
            ) -> None:
                msg = "Lifespan protocol not supported"
                raise ValueError(msg)

            # Create the lifespan manager.
            loop = asyncio.get_running_loop()
            started_called = False

            def started(error_message: str | None) -> None:
                nonlocal started_called
                assert error_message is None
                started_called = True

            shutdown_complete_called = False

            def shutdown_complete(error_message: str | None) -> None:
                nonlocal shutdown_complete_called
                assert error_message is None
                shutdown_complete_called = True

            shutting_down = loop.create_future()
            uut = Manager(
                Container(app, None),
                loop.create_future(),
                asyncio.Lock(),
                started,
                shutting_down,
                shutdown_complete,
            )

            # At this point, nothing should have happened.
            self.assertFalse(started_called)
            self.assertFalse(shutdown_complete_called)

            # Fork off a task.
            uut_future = asyncio.ensure_future(uut.run())

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, startup should have finished, but shutdown should not have
            # started.
            self.assertTrue(started_called)
            self.assertFalse(shutdown_complete_called)

            # Initiate shutdown.
            shutting_down.set_result(None)

            # Let the task run.
            await asyncio.sleep(0)

            # At this point, shutdown should have finished.
            self.assertTrue(started_called)
            self.assertTrue(shutdown_complete_called)

            # The lifespan manager should return promptly after shutdown.
            await uut_future

        asyncio.run(impl())
