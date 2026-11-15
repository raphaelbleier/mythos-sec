"""GraphQL + JSON-RPC target — fixture for the api-abuse package.

  POST /graphql   introspection on (GRAPHQL_INTROSPECTION=0 turns it off so
                  the field-suggestion path has a target too), aliases and
                  JSON-array batching accepted, and NO per-field
                  authorization: `user(id:)` and `User.apiToken` hand an
                  authenticated caller another account's data.
  POST /rpc       JSON-RPC 2.0. A single call checks that the order belongs
                  to the caller. A batch does not, so a batch mixing the
                  caller's own ids with one foreign id returns the foreign
                  order.

Local lab only. Do not deploy it.
"""

from __future__ import annotations

import json
import os

from flask import Flask, Response, request
from graphql import (GraphQLError, NoSchemaIntrospectionCustomRule,
                     build_schema, execute, parse, specified_rules, validate)

app = Flask(__name__)
INTROSPECTION = os.environ.get("GRAPHQL_INTROSPECTION", "1") == "1"

USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@mythos.lab",
        "apiToken": "MYTHOS_LAB_CANARY_alice_api_token", "role": "user"},
    2: {"id": 2, "name": "bob", "email": "bob@mythos.lab",
        "apiToken": "MYTHOS_LAB_CANARY_bob_api_token", "role": "user"},
    3: {"id": 3, "name": "root", "email": "root@mythos.lab",
        "apiToken": "MYTHOS_LAB_CANARY_root_api_token", "role": "admin"},
}
TOKENS = {"tok-alice": 1, "tok-bob": 2}
ORDERS = {
    101: {"id": 101, "owner": 1, "item": "laptop", "total": 1299},
    102: {"id": 102, "owner": 1, "item": "cable", "total": 9},
    201: {"id": 201, "owner": 2, "item": "phone", "total": 799},
    301: {"id": 301, "owner": 3, "item": "hsm", "total": 44000},
}

SDL = """
type User {
  id: Int!
  name: String!
  email: String!
  apiToken: String!
  role: String!
}
type Order {
  id: Int!
  item: String!
  total: Int!
  ownerId: Int!
}
type Query {
  me: User
  user(id: Int!): User
  users: [User!]!
  order(id: Int!): Order
}
"""
schema = build_schema(SDL)


def _caller() -> dict | None:
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else auth
    uid = TOKENS.get(token)
    return USERS.get(uid) if uid else None


def _me(_root, _info):
    return _caller()


def _user(_root, _info, id):
    # VULN: authentication without authorization — any logged-in caller reads
    # any user, including User.apiToken, which has no field-level check.
    if not _caller():
        return None
    return USERS.get(id)


def _users(_root, _info):
    # VULN: the whole table, apiToken included, to any logged-in caller.
    return list(USERS.values()) if _caller() else []


def _order(_root, _info, id):
    if not _caller():
        return None
    o = ORDERS.get(id)
    return dict(o, ownerId=o["owner"]) if o else None


for name, fn in (("me", _me), ("user", _user), ("users", _users),
                 ("order", _order)):
    schema.query_type.fields[name].resolve = fn


def _rules():
    if INTROSPECTION:
        return specified_rules
    return list(specified_rules) + [NoSchemaIntrospectionCustomRule]


def _errors(errors) -> dict:
    # Validation errors keep graphql-core's "Did you mean" suggestions, which
    # is what makes field guessing work with introspection off.
    return {"data": None, "errors": [{"message": e.message} for e in errors]}


def _execute(doc: dict) -> dict:
    try:
        document = parse(doc.get("query", ""))
    except GraphQLError as e:
        return _errors([e])
    errors = validate(schema, document, _rules())
    if errors:
        return _errors(errors)
    result = execute(schema, document,
                     variable_values=doc.get("variables"),
                     operation_name=doc.get("operationName"))
    out: dict = {"data": result.data}
    if result.errors:
        out["errors"] = [{"message": e.message} for e in result.errors]
    return out


@app.route("/")
def index():
    return """<html><head><title>Mythos ApiLab</title></head><body>
    <h1>ApiLab</h1><p>POST /graphql, POST /rpc</p>
    <p>tokens: tok-alice, tok-bob (Authorization: Bearer ...)</p>
    </body></html>"""


@app.route("/graphql", methods=["GET", "POST"])
def graphql_route():
    if request.method == "GET":
        return {"message": "POST a query here"}
    body = request.get_json(silent=True)
    if isinstance(body, list):
        # VULN: unbounded batching — one request, N operations, no cost limit.
        return Response(json.dumps([_execute(d) for d in body]),
                        mimetype="application/json")
    if not isinstance(body, dict):
        return {"errors": [{"message": "expected a JSON object or array"}]}
    return _execute(body)


RPC_METHODS = ("getOrder", "listOrders")


def _rpc_one(call: dict, check_owner: bool) -> dict:
    out = {"jsonrpc": "2.0", "id": call.get("id")}
    caller = _caller()
    if not caller:
        return dict(out, error={"code": -32000, "message": "unauthenticated"})
    method = call.get("method")
    if method not in RPC_METHODS:
        return dict(out, error={"code": -32601, "message": "method not found"})
    params = call.get("params") or {}
    if method == "listOrders":
        return dict(out, result=[o["id"] for o in ORDERS.values()
                                 if o["owner"] == caller["id"]])
    order = ORDERS.get(int(params.get("id", 0)))
    if not order:
        return dict(out, error={"code": -32602, "message": "no such order"})
    if check_owner and order["owner"] != caller["id"]:
        return dict(out, error={"code": -32001, "message": "forbidden"})
    return dict(out, result=order)


@app.route("/rpc", methods=["POST"])
def rpc():
    body = request.get_json(silent=True)
    if isinstance(body, list):
        # VULN: the batch path skips the ownership check the single-call path
        # does, so a batch of own ids plus one foreign id returns all of them.
        return Response(json.dumps([_rpc_one(c, check_owner=False) for c in body]),
                        mimetype="application/json")
    if not isinstance(body, dict):
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "invalid request"}}
    return _rpc_one(body, check_owner=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")),
            threaded=True, use_reloader=False)
