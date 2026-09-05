"""graphql — detect exposed GraphQL endpoints with introspection enabled."""
import json as jsonlib
import urllib.parse
from common import Finding

NAME = "graphql"

ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/graphql/console",
             "/graphiql", "/playground", "/api/graphql/v1"]

INTROSPECTION = {"query": "{__schema{types{name}}}"}


def run(client, opts):
    out = []
    parsed = urllib.parse.urlparse(client.base_url)
    root = f"{parsed.scheme}://{parsed.netloc}"

    for ep in ENDPOINTS:
        url = root + ep
        try:
            r = client.request("POST", url=url, json=INTROSPECTION)
        except Exception:
            continue
        if r.status == 200 and "__schema" in r.body:
            try:
                data = jsonlib.loads(r.body)
                types = data.get("data", {}).get("__schema", {}).get("types", [])
                if types:
                    out.append(Finding(NAME, "high", "GraphQL introspection enabled",
                                       f"{ep} exposes full schema ({len(types)} types)",
                                       ep))
                    return out
            except Exception:
                pass
        # GraphiQL/playground UI exposed
        g = client.request("GET", url=url)
        if g.status == 200 and ("graphiql" in g.body.lower() or "playground" in g.body.lower()):
            out.append(Finding(NAME, "medium", "GraphQL IDE exposed",
                               f"{ep} serves an interactive GraphQL IDE", ep))
            return out
    return out
