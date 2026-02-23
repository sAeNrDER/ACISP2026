from __future__ import annotations

from flask import Flask, jsonify, request

from wallet.bekd_crypto import H2, serialize_point


def create_app(node_index: int, node_share: int):
    app = Flask(__name__)
    local_used: set[str] = set()

    @app.post('/enroll')
    def enroll():
        data = request.get_json(force=True)
        # simulate partial signature share response
        return jsonify({"node": node_index, "partial_sig": hex((node_share + int(data['hA'])) % (2**256))})

    @app.post('/retrieve')
    def retrieve():
        data = request.get_json(force=True)
        rho = data['rho']
        if rho in local_used:
            return jsonify({"error": "token-used"}), 400
        local_used.add(rho)
        R0 = tuple(data['R0'])
        helper = serialize_point((R0[0], R0[1]))
        return jsonify({"node": node_index, "helper": helper.hex()})

    return app
