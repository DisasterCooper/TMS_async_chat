import datetime
import re
from base64 import encode
from typing import Callable

import aiohttp_jinja2
import hashlib
import os

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp_session import Session

from extra import redirect, login_required
from .models import User


class LogIn(web.View):

    @aiohttp_jinja2.template("users/login.html")
    async def get(self):
        return {}

    async def post(self):
        data = await self.request.post()
        username = data.get('username', '').lower()
        password = data.get('password', '')

        try:
            user = await User.get(username=username, password=password)
            password = await user.password
            origin_salt = bytes.fromhex(user.password[:64])
            stored_password_hash = bytes.fromhex(user.password[64:])
            new_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), origin_salt, 100000)
            if new_hash == stored_password_hash:
                print("Пароли совпадают")
        except Exception as error:
            print(error)
            redirect(self.request, "login")
            return

        else:
            self.login(user)
        return web.json_response({"user": user.id})

    def login(self, user: User):

        self.request.session["user_id"] = user.id
        self.request.session["time"] = str(datetime.datetime.now())

        redirect(self.request, "home")


class Register(web.View):

    @aiohttp_jinja2.template("users/register.html")
    async def get(self):
        print(self.request)

    @staticmethod
    def encrypt_password(password):
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        encrypt_password = salt.hex() + key.hex()
        return encrypt_password

    async def check_username(self) -> str:
        """ Get username from post data, and check is correct """
        data = await self.request.post()
        username = data.get('username', '').lower()
        if not re.match(r'^[a-z]\w{0,9}$', username):
            return ""
        return username

    async def check_password(self) -> str | Callable[[{encode}], str]:
        data = await self.request.post()
        password = data.get('password', '')
        if not re.match(r'^[a-z]\w{0,9}$', password):
            return ""
        else:
            password = self.encrypt_password
        return password

    def login(self, user: User):
        self.request.session["user_id"] = user.id
        self.request.session["time"] = str(datetime.datetime.now())

        redirect(self.request, "home")

    async def post(self):
        username = await self.check_username()
        password = await self.check_password()
        print('username', username)

        if not username or password:
            redirect(self.request, "register")

        try:
            await User.get(username=username)
            # Такой пользователь уже есть!
            redirect(self.request, "login")
        except:
            print("Пользователя нет!")

        await User.create(username=username, password=password)
        user = await User.get(username=username, password=password)
        self.login(user)


class Logout(web.View):

    @login_required
    async def get(self):
        self.request.session.pop("user_id")
        redirect(self.request, "home")

