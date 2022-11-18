from libprobe.asset import Asset


async def check_dummy(
        asset: Asset,
        asset_config: dict,
        config: dict) -> dict:
    return {
        'dummy': [
            {
                'name': 'dummy-item'
            }
        ]
    }
