import pypush_gsa_icloud as apple_auth
import os
import json
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Literal
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

CONFIG_PATH = os.path.dirname(os.path.realpath(__file__)) + "/auth.json"

def setAuth(email, password, second_factor):
    mobileme = apple_auth.icloud_login_mobileme(email, password, second_factor)
    if "2sv_challenge_response" in mobileme:
        return mobileme
    j = {'dsid': mobileme['dsid'], 'searchPartyToken': mobileme['delegates']['com.apple.mobileme']['service-data']['tokens']['searchPartyToken']}
    with open(CONFIG_PATH, "w") as f: json.dump(j, f)
    return j

class Credentials(BaseModel):
    email: str
    password: str
    method: Literal['sms', 'trusted_device']
@app.post("/icloud/login")
def icloud_login(credentials: Credentials):
    try:
        return setAuth(credentials.email, credentials.password, credentials.method)
    except:
        return {'error': 'error authenticating with apple'}

class TwoStepVerification(BaseModel):
    adsid: str
    GsIdmsToken: str
    code: str
    method: Literal['sms', 'trusted_device']
@app.post("/icloud/two-step-verification")
def icloud_two_step_verification(two_step_verification: TwoStepVerification):
    try:
        if two_step_verification.method == 'sms':
            return apple_auth.send_sms_second_factor(
                two_step_verification.adsid,
                two_step_verification.GsIdmsToken, 
                two_step_verification.code
            )
        elif two_step_verification.method == 'trusted_device':
            return apple_auth.send_trusted_second_factor(
                two_step_verification.adsid,
                two_step_verification.GsIdmsToken, 
                two_step_verification.code
            )
    except:
        return {'error': 'error sending two-step-verification code'}
    
@app.get("/icloud/auth-token")
def icloud_auth_token():
    try:
        with open(CONFIG_PATH, "r") as f:
            config_data = json.load(f)
            return config_data
    except:
        return {'error': 'error reading auth info, try logging in again'}


@app.get("/icloud/logout")
def icloud_logout():
    try:
        os.remove(CONFIG_PATH)
        return { "success": True }
    except:
        return {'error': 'error logging out'}