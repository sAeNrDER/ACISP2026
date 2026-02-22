from wallet.wallet_client import BEKDWallet


def test_enrollment_creates_token():
    wallet = BEKDWallet()
    token = wallet.enroll()
    assert 'TU' in token and 'TCA' in token
    assert len(token['TCA']['A']) == wallet.params.d
