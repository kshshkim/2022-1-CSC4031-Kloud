import functools
from datetime import datetime, timedelta
import asyncio

from jose import jwt, JWTError
from typing import Optional
from pydantic import BaseModel
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import boto3

from .response_exceptions import CredentialsException
from .config.token_conf import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from .scheme import KloudJWT, KloudAwsCred

security = HTTPBearer(scheme_name='bearer')


def build_token(user_id: str) -> dict:
    return {
        "user_id": user_id
    }


# todo
def encrypt(string: str) -> str:
    return string


# todo
def decrypt(string: str) -> str:
    return string


def create_access_token(user_id: str, cred: KloudAwsCred, expires_delta: Optional[timedelta] = None) -> str:
    now = datetime.utcnow()
    expire = now + expires_delta if expires_delta else now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode: dict = KloudJWT(user_id=user_id, iat=now, exp=expire, encrypted=encrypt(cred.json())).dict()

    encoded_jwt: str = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt  # 인코딩된 jwt 반환


class AccessTokenForm(BaseModel):
    access_token: str


def request_temp_cred(session_obj: boto3.Session, region: str) -> KloudAwsCred:
    sts_cli = session_obj.client('sts')  # 임시 토큰 발급
    response: dict = sts_cli.get_session_token()
    """ response
    {
    'AccessKeyId': 'some-id',
    'SecretAccessKey': 'some-secret',
    'SessionToken': 'some-token'
    ...
    }
    """

    cred = response['Credentials']

    return KloudAwsCred(aws_access_key_id=cred['AccessKeyId'],
                        aws_secret_access_key=cred['SecretAccessKey'],
                        aws_session_token=cred['SessionToken'],
                        region_name=region)


async def async_request_temp_cred(session_obj: boto3.Session, region: str) -> KloudAwsCred:
    fun = functools.partial(request_temp_cred, session_obj=session_obj, region=region)
    return await asyncio.to_thread(fun)


def create_temp_session(cred: KloudAwsCred) -> boto3.Session:
    return boto3.Session(aws_access_key_id=cred.aws_access_key_id,
                         aws_secret_access_key=cred.aws_secret_access_key,
                         aws_session_token=cred.aws_session_token,
                         region_name=cred.region_name)


async def validate_and_decode_access_token(auth_header: HTTPAuthorizationCredentials = Depends(security)) -> KloudJWT:
    try:
        payload = jwt.decode(auth_header.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        decoded: KloudJWT = KloudJWT(**payload)
    except JWTError:
        raise CredentialsException
    return decoded
