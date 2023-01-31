`pip install -r requirements.txt`   
requires sqlalchemy >= 1.4.0 with async extension

codes with reference to these resources:   
⭐[Implement OAuth2 login authentication with FastAPI](https://yifei.me/note/2432)   
⭐[FastAPI with Async SQLAlchemy, SQLModel, and Alembic](https://testdriven.io/blog/fastapi-sqlmodel/)   
    
btw gunicorn not supported by windows   
`gunicorn app.main:app -b 0.0.0.0:8004 -w 4 -k uvicorn.workers.UvicornWorker`