.PHONY: up down logs seed report test ssh-log http-log clean migrate

DOCKER_COMPOSE := docker compose -f docker-compose.yml

up:
	$(DOCKER_COMPOSE) up -d --build

down:
	$(DOCKER_COMPOSE) down

logs:
	$(DOCKER_COMPOSE) logs -f --tail=200

seed:
	docker compose -f docker-compose.yml exec api python /app/scripts/seed_demo_data.py

report:
	docker compose -f docker-compose.yml exec api python -c "import asyncio; from analytics.reporter import generate_json_report, generate_pdf_report; asyncio.run(generate_json_report(7)); asyncio.run(generate_pdf_report(7))"

test:
	cd /app 2>/dev/null || true; pytest tests/ -v --tb=short 2>/dev/null || docker compose -f docker-compose.yml run --rm --no-deps api pytest /app/tests -v --tb=short

migrate:
	docker compose -f docker-compose.yml exec api alembic -c /app/pipeline/alembic.ini upgrade head

ssh-log:
	$(DOCKER_COMPOSE) logs -f ssh-honeypot

http-log:
	$(DOCKER_COMPOSE) logs -f http-honeypot

clean:
	$(DOCKER_COMPOSE) down -v --remove-orphans
