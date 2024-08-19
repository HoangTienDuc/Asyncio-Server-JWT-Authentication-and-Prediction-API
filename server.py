from utils.encrypt_controller import EncryptHandler
from utils.apis import JWTManager
from utils.prediction import LvmHandler
import aiohttp
from aiohttp import web
import ssl

async def main():
    app = web.Application()

    # Initialize your EncryptHandler and LvmHandler instances here
    encrypt_handler = EncryptHandler()
    lvm_predictor = LvmHandler()

    # Initialize JWTManager
    JWTManager(app, encrypt_handler, lvm_predictor)

    # Setup SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile='data/certfile.pem', keyfile='data/keyfile.pem')

    # Run the application using aiohttp's web server with HTTPS
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, 'localhost', 8443, ssl_context=ssl_context)
    await site.start()

    print(f"Aiohttp server running on https://localhost:8443")

    # Keep the application running
    await asyncio.Event().wait()    

if __name__ == '__main__':
    import asyncio
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
