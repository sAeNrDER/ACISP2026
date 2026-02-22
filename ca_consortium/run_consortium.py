from __future__ import annotations

import multiprocessing

from ca_consortium.ca_node import create_app
from ca_consortium.ca_config import default_ports
from ca_consortium.threshold_crypto import run_simulated_dkg


def run_node(index: int, port: int, share: int):
    app = create_app(index, share)
    app.run(host='0.0.0.0', port=port)


def main():
    dkg = run_simulated_dkg(3)
    ports = default_ports()
    procs = []
    for i, share in enumerate(dkg.shares, start=1):
        p = multiprocessing.Process(target=run_node, args=(i, ports[i - 1], share.share))
        p.start()
        procs.append(p)
    for p in procs:
        p.join()


if __name__ == '__main__':
    main()
