import asyncio
import base64
import typing
import aiohttp
import fastapi
import uvicorn
import asyncpg
import aioredis
import datetime
import time
from config import *
from fastapi import Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse as redirect, PlainTextResponse
from discord.ext import oauth as discord_oauth
from async_spotify.authentification.authorization_flows import AuthorizationCodeFlow
from async_spotify.api.spotify_api_client import SpotifyApiClient
from async_spotify.authentification.spotify_authorization_token import SpotifyAuthorisationToken
from asyncpg.exceptions._base import InterfaceError

class App(fastapi.FastAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(
            debug=False,
            title='OpenRobot Spotify',
            description='',
            version='',
            openapi_url=None,
            docs_url=None,
            redoc_url=None,
            swagger_ui_init_oauth=None
        )

        self.spotify_auth = AuthorizationCodeFlow(
            application_id=Spotify.ID,
            application_secret=Spotify.SECRET,
            scopes=Spotify.SCOPES,
            redirect_url=Spotify.REDIRECT_URI
        )

        self.discord = discord_oauth.OAuth2Client(
            client_id=Discord.ID,
            client_secret=Discord.SECRET,
            redirect_uri=Discord.REDIRECT_URI,
            scopes=Discord.SCOPES
        )

        self.spotify_api = SpotifyApiClient(self.spotify_auth)
        
        self.db_one = None
        self.db_two = None

        self.redis = None

        self.add_event_handler('startup', self.on_startup)
        self.add_event_handler('shutdown', self.on_shutdown)

        self.templates = Jinja2Templates(directory='html')

    async def on_startup(self):
        self.db_one = await asyncpg.create_pool(Database.One.DSN)
        #self.db_two = await asyncpg.create_pool(Database.Two.DSN)

        self.redis = aioredis.Redis(host=Database.Redis.HOST, port=Database.Redis.PORT, password=Database.Redis.PASSWORD, db=Database.Redis.DB)

        # Create the table if it does not exist.

        while True:
            try:
                await self.db_one.execute("""
                CREATE TABLE IF NOT EXISTS spotify_auth(
                    user_id BIGINT,
                    code TEXT,
                    access_token TEXT,
                    refresh_token TEXT,
                    expires_at TIMESTAMP,
                    expires_in BIGINT DEFAULT 3600
                )
                """)
            except InterfaceError:
                pass
            else:
                break

        asyncio.get_event_loop().create_task(self.renew())

    async def cleanup(self):
        # Cleanup
        await self.db_one.close()
        await self.db_one.close()

        await self.redis.close()

    async def on_shutdown(self):
        await self.cleanup()

    async def get_user_near_expire(self) -> typing.Tuple[int, dict]:
        while True:
            try:
                res = await self.db_one.fetchrow('SELECT * FROM spotify_auth ORDER BY expires_at ASC')
            except:
                pass
            else:
                if res is None:
                    return None

                return int(res['user_id']), dict(res)

    async def renew(self): # Renews spotify token
        while True:
            user_near_expire = await self.get_user_near_expire()

            if user_near_expire is not None:
                user_id, res = user_near_expire

                while res['expires_at'] > datetime.datetime.utcnow():
                    pass

                try:
                    async with aiohttp.ClientSession() as sess:
                        async with sess.post('https://accounts.spotify.com/api/token', headers={'Authorization': 'Basic ' + base64.urlsafe_b64encode(f'{self.spotify_auth.application_id}:{self.spotify_auth.application_secret}')}, params = {'grant_type': 'refresh_token', 'refresh_token': res['refresh_token']}) as resp:
                            js = await resp.json()

                            if 'expires_in' not in js and 'access_token' not in js:
                                await self.db_one.execute("""
                                DELETE FROM spotify_auth
                                WHERE user_id = $1
                                """, user_id)
                                continue

                            while True:
                                try:
                                    await self.db_one.execute("""
                                    UPDATE spotify_auth
                                    SET access_token = $2,
                                        expires_st = $3,
                                        expires_in = $4
                                    WHERE user_id = $1
                                    """, user_id, js['access_token'], (datetime.datetime.utcnow() + datetime.timedelta(seconds=js['expires_in'])), js['expires_in'])
                                except InterfaceError:
                                    pass
                                else:
                                    pass
                except:
                    pass

            await asyncio.sleep(10)
            continue

app = App()

@app.get('/')
async def homepage(request: Request):
    return app.templates.TemplateResponse('login.html', {'request': request})

@app.get(LOGIN_URI)
async def login(request: Request):
    return app.templates.TemplateResponse('login_endpoint.html', {'request': request})

@app.get(Discord.LOGIN_URI)
async def discoed_login():
    return redirect(Discord.OAUTH_URL)

@app.get(Discord.REDIRECT_URI)
async def discord_callback(code: str):
    resp = await app.discord.exchange_code(code)
    user = await app.discord.fetch_user(resp)

    await app.redis.set(f'{user.id}', 'ON_STEP(SPOTIFY)')

    return redirect(Spotify.generate_oauth_url(app.spotify_auth, user.id))

@app.get(Spotify.REDIRECT_URI)
async def spotify_callback(code: str = None, state: str = None, error: str = None):
    if error:
        return PlainTextResponse('Error: ' + error, status_code=400)
    
    try:
        user_id = int(state)
    except:
        pass

    await app.redis.set(f'{user_id}', 'ON_STEP(FINISH)')

    auth_token: SpotifyAuthorisationToken = await app.spotify_api.get_auth_token_with_code(code)

    expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=3600) # 3600 is the default spotify api expires_in (in seconds format).

    while True:
        try:
            is_in_db = bool(await app.db_one.fetch("SELECT * FROM spotify_auth WHERE user_id = $1", user_id))
        except InterfaceError:
            pass
        else:
            break

    while True:
        try:
            if is_in_db:
                await app.db_one.execute("""
                DELETE FROM spotify_auth
                WHERE user_id = $1
                """, user_id)

                is_in_db = False
            
            await app.db_one.execute("INSERT INTO spotify_auth VALUES ($1, $2, $3, $4, $5, $6)", user_id, code, auth_token.access_token, auth_token.refresh_token, expires_at, 3000)
        except InterfaceError:
            pass
        else:
            break

    return PlainTextResponse('Authoirzed. You may now close this tab.')

if __name__ == '__main__':
    uvicorn.run(app, host=WebConfig.HOST, port=WebConfig.PORT)