# Basic_info -> in between """ #=h1, ##=h2,....(HTML heading), between *...* considered as italic

from fastapi import FastAPI

description="""
## I am learning *fast_api*
"""
tags=[
    {
        "name":"user",
        "description":"Only user data"
    },
    {
        "name":"product",
        "description":"Only product data"
    }
]

app=FastAPI(title="Fast_api_tutorial",
            description=description,
            openapi_tags=tags,
            #openapi_url="/api/openapi.json",
            #docs_url="/document", ->instead of localhost:8000/doc, accept localhost:8000/document
            )

@app.get("/user",tags=['user'])
def hello():
    return {"msg":"hello ! AP"}

@app.get("/product",tags=['product'])
def product():
    return {"msg":"hello ! product"}