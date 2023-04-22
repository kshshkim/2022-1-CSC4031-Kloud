import json
from json import JSONDecodeError

from aioredis import Redis

from .config.redis_conf import HOST, PORT, CREDDB, CRED_EXP, COST_EXP, REVOKED_TOKENS, CACHEDB
from .response_exceptions import UserNotInDBException

cred_db = Redis(host=HOST, port=PORT, db=CREDDB, decode_responses=True)
cache_db = Redis(host=HOST, port=PORT, db=CACHEDB, decode_responses=True)


async def get_cred_from_redis(user_id: str) -> dict:
    """
    JSON 임시 인증정보를 redis에서 가져옴.
    """
    jsonified = await cred_db.get(user_id)
    try:
        return json.loads(jsonified)
    except JSONDecodeError:
        raise UserNotInDBException  # 로그아웃, 혹은 유효기간 만료로 인해 db에 인증정보가 없음.


async def set_cost_cache(key: str, cost_data: dict) -> None:  # 파라미터 추가 가능성 있음.
    jsonified = json.dumps(cost_data)
    await cache_db.set(f'cost_cache_{key}', jsonified, COST_EXP)


async def get_cost_cache(key: str) -> (dict, None):  # 파라미터 추가 가능성 있음.
    jsonified = await cache_db.get(f'cost_cache_{key}')
    if jsonified is not None:
        return json.loads(jsonified)


async def delete_cache_from_redis(user_id: str) -> None:
    await cache_db.delete(f'cost_cache_{user_id}')
