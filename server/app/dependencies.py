import json

from fastapi import Depends

from .auth import validate_and_decode_access_token, create_temp_session, decrypt
from .boto3_wrappers.kloud_client import KloudClient
from .scheme import KloudJWT, KloudAwsCred


async def get_user_id(decoded: KloudJWT = Depends(validate_and_decode_access_token)) -> str:
    """
    토큰에서 유저 id를 가져옴. 토큰이 유효하지 않을 경우 에러 raise
    """
    user_id: str = decoded.user_id
    return user_id


def get_aws_cred(decoded: KloudJWT = Depends(validate_and_decode_access_token)) -> KloudAwsCred:
    encrypted_cred = decoded.encrypted
    decrypted: dict = json.loads(decrypt(encrypted_cred))
    return KloudAwsCred(**decrypted)


async def get_user_client(cred: KloudAwsCred = Depends(get_aws_cred)) -> KloudClient:
    session_instance = create_temp_session(cred)
    kloud_client = KloudClient(session_instance)
    return kloud_client
