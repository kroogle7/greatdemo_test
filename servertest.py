from fastapi import FastAPI
from fastapi.responses import Response

app = FastAPI()


@app.get('/')
def index_page():
    return Response('hi', media_type='text/html')
