"""Detect GraphQL endpoints and check whether introspection is enabled."""
from app.core.context import ScanContext
from app.core.finding import Finding
from app.core.severity import Severity

ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphql/console", "/graphiql"]
INTROSPECTION = {"query": "{__schema{queryType{name} types{name}}}"}


async def run(ctx: ScanContext) -> list[Finding]:
    findings = []

    for path in ENDPOINTS:
        url = ctx.base_url + path
        try:
            r = await ctx.client.post(url, json=INTROSPECTION)
        except Exception:
            continue

        body = r.text.lower()
        # A GraphQL endpoint responds with JSON containing "data" or "errors".
        if r.status_code in (200, 400) and ("__schema" in body or '"data"' in body or '"errors"' in body):
            if "__schema" in body and '"types"' in body:
                findings.append(Finding(
                    title="GraphQL Introspection Enabled",
                    description=f"The GraphQL endpoint at {path} allows introspection, exposing the full API "
                                "schema (types, queries, mutations). This hands attackers a complete map of the API.",
                    severity=Severity.MEDIUM,
                    category="Scanner / GraphQL",
                    evidence=f"POST {url} returned a populated __schema.",
                    recommendation="Disable introspection in production (e.g. validationRules / NoSchemaIntrospection).",
                    url=url,
                    cvss=5.3,
                ))
            else:
                findings.append(Finding(
                    title=f"GraphQL Endpoint Found: {path}",
                    description="A GraphQL endpoint is exposed (introspection appears disabled).",
                    severity=Severity.INFO,
                    category="Scanner / GraphQL",
                    evidence=f"POST {url} responded like a GraphQL server.",
                    recommendation="Ensure introspection is disabled and queries are depth/complexity limited.",
                    url=url,
                ))
            break  # one GraphQL endpoint is enough

    return findings
