import os

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

if SECRET_KEY is None:
    SECRET_KEY = "wow_very_secret"  # test용 샘플. 배포시 수정 필요

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
