"""
AMCDS Dashboard Backend - FastAPI with WebSocket support.
"""
from __future__ import annotations
import os
import json
import logging
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)


# Connection managers
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass


manager = ConnectionManager()
db_pool = None
redis_client = None
neo4j_driver = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db_pool, redis_client, neo4j_driver
    # Startup
    try:
        import asyncpg
        db_pool = await asyncpg.create_pool(
            host=os.environ.get("POSTGRES_HOST", "postgres"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            database=os.environ.get("POSTGRES_DB", "amcds"),
            user=os.environ.get("POSTGRES_USER", "amcds"),
            password=os.environ.get("POSTGRES_PASSWORD", "amcds_secure_2024"),
            min_size=2, max_size=5,
        )
        logger.info("PostgreSQL pool created")
    except Exception as e:
        logger.warning("PostgreSQL not available: %s", e)

    try:
        import redis.asyncio as aioredis
        redis_client = aioredis.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", "6379")),
        )
        logger.info("Redis connected")
    except Exception as e:
        logger.warning("Redis not available: %s", e)

    try:
        from neo4j import AsyncGraphDatabase
        neo4j_auth = os.environ.get("NEO4J_AUTH", "neo4j/amcds_graph_2024").split("/")
        neo4j_driver = AsyncGraphDatabase.driver(
            f"bolt://{os.environ.get('NEO4J_HOST', 'neo4j')}:{os.environ.get('NEO4J_BOLT_PORT', '7687')}",
            auth=(neo4j_auth[0], neo4j_auth[1]),
        )
        logger.info("Neo4j connected")
    except Exception as e:
        logger.warning("Neo4j not available: %s", e)

    yield

    # Shutdown
    if db_pool:
        await db_pool.close()
    if redis_client:
        await redis_client.close()
    if neo4j_driver:
        await neo4j_driver.close()


app = FastAPI(
    title="AMCDS Dashboard API",
    description="Autonomous Multi-Agent Cyber Defense System Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health():
    return {"status": "healthy", "service": "amcds-dashboard"}


@app.get("/api/incidents")
async def list_incidents(limit: int = Query(50, le=200), offset: int = 0):
    if not db_pool:
        return {"incidents": [], "total": 0}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT * FROM incidents ORDER BY created_at DESC LIMIT $1 OFFSET $2", limit, offset
        )
        total = await conn.fetchval("SELECT COUNT(*) FROM incidents")
    return {"incidents": [dict(r) for r in rows], "total": total}


@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str):
    if not db_pool:
        return {"error": "Database not available"}
    async with db_pool.acquire() as conn:
        incident = await conn.fetchrow("SELECT * FROM incidents WHERE incident_id = $1", incident_id)
        alerts = await conn.fetch("SELECT * FROM alerts WHERE alert_id = ANY(SELECT unnest(string_to_array($1, ',')))", incident_id)
    return {"incident": dict(incident) if incident else None, "alerts": [dict(a) for a in alerts]}


@app.get("/api/alerts")
async def list_alerts(limit: int = Query(100, le=500), severity: str | None = None):
    if not db_pool:
        return {"alerts": [], "total": 0}
    async with db_pool.acquire() as conn:
        if severity:
            rows = await conn.fetch("SELECT * FROM alerts WHERE severity = $1 ORDER BY created_at DESC LIMIT $2", severity, limit)
        else:
            rows = await conn.fetch("SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1", limit)
    return {"alerts": [dict(r) for r in rows]}


@app.get("/api/topology")
async def get_topology():
    """Return network topology graph data."""
    if not neo4j_driver:
        return {"nodes": [], "edges": []}
    async with neo4j_driver.session() as session:
        result = await session.run(
            "MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 500"
        )
        nodes, edges = [], []
        seen_nodes = set()
        async for record in result:
            n = record["n"]
            if n.element_id not in seen_nodes:
                seen_nodes.add(n.element_id)
                nodes.append(dict(n))
            if record["r"] and record["m"]:
                edges.append({"source": dict(n).get("id"), "target": dict(record["m"]).get("id"), "type": record["r"].type})
    return {"nodes": nodes, "edges": edges}


@app.get("/api/strategies")
async def list_strategies():
    if not db_pool:
        return {"strategies": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM strategies ORDER BY created_at DESC LIMIT 50")
    return {"strategies": [dict(r) for r in rows]}


@app.get("/api/decisions")
async def list_decisions():
    if not db_pool:
        return {"decisions": []}
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM decisions ORDER BY timestamp DESC LIMIT 50")
    return {"decisions": [dict(r) for r in rows]}


@app.get("/api/simulation/status")
async def simulation_status():
    stats = {}
    if redis_client:
        try:
            keys = await redis_client.keys("*")
            stats["redis_keys"] = len(keys)
        except Exception:
            pass
    if db_pool:
        async with db_pool.acquire() as conn:
            stats["total_alerts"] = await conn.fetchval("SELECT COUNT(*) FROM alerts") or 0
            stats["total_incidents"] = await conn.fetchval("SELECT COUNT(*) FROM incidents") or 0
            stats["open_incidents"] = await conn.fetchval("SELECT COUNT(*) FROM incidents WHERE status = 'open'") or 0
    return {"status": "running", "stats": stats}


@app.post("/api/simulation/reset")
async def reset_simulation():
    if db_pool:
        async with db_pool.acquire() as conn:
            await conn.execute("TRUNCATE alerts, incidents, strategies, decisions, telemetry_stats CASCADE")
    if redis_client:
        await redis_client.flushdb()
    return {"status": "reset_complete"}


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo or handle client messages
    except WebSocketDisconnect:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080, workers=1)
