from pydantic import BaseModel



"""
PreKeyBundle - Generate all of the type keys for user. identitykey, signedprekey, signature for prekey, onetimeprekey
KeyBundleUpload - needs for to future communication with another users. signedprekey_public, signature for signedPreKey and OneTimePrekey
OneTimePreKeysUpload - we are generated 100 onetimeprekeys. he stored on user deivices. and one of this expired, 
old key - permament deleted and another one new key take from queue.
"""


class PreKeyBundleResponse (BaseModel):
    identity_Key: str
    signed_prekey: str
    signed_prekey_signature: str
    one_time_prekey: str | None = None
    registration_id: int

class KeyBundleUpload(BaseModel):
    signed_prekey_public: str
    signed_prekey_signature: str
    one_time_prekeys: list[str]

class OneTimePreKeysUpload(BaseModel):
    one_time_prekeys: list[str]