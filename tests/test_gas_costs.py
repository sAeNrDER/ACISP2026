
def test_gas_placeholder_table():
    gas_table = {
        'deploy_authorization': 0,
        'deploy_spentset': 0,
        'deploy_registry': 0,
        'deploy_wallet': 0,
        'mark_used': 0,
    }
    assert set(gas_table.keys())
