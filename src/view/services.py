from fastapi import  Request,APIRouter
import sys
import logging

#update system path

sys.path.append("")
from src.logs import logging_pro

from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from src.tasks.type_check import detect_ioc_type
from src.tasks.ip import create_ioc
from src.tasks.domain import create_domain_ioc
from src.tasks.hash import create_hash_ioc
from src.tasks.url import create_url_ioc
from src.database.database import (
    insert_ip_ioc,
    insert_domain_ioc,
    insert_hash_ioc,
    insert_url_ioc,
    get_ip_ioc_from_db,
    get_domain_ioc_from_db,
    get_hash_ioc_from_db,
    get_url_ioc_from_db,
)

router = APIRouter()
templates = Jinja2Templates(directory="../doc/templates")

logging.basicConfig(
    filename="src/logs/logs/app.log",  # Bu durumda logs klasörü aynı seviyede olmalı
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

@router.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    """
    Displays the search form on the home page.

    Args:
        request (Request): FastAPI request object.

    Returns:
        HTMLResponse: Template response for the home page.
    """
    logging.info("Home page accessed.")  # Loglama eklendi

    return templates.TemplateResponse(
        "index.html", {"request": request, "status": "Success"}
    )


@router.get("/search/", response_class=HTMLResponse)
async def search_endpoint(request: Request, q: str):
    """
    Handles IOC search requests and displays results based on the detected IOC type.

    Args:
        request (Request): FastAPI request object.
        q (str): The IOC value to search for.

    Returns:
        HTMLResponse: Template response for the search result page.
    """
    logging.info(f"Search requested for IOC: {q}")  # Loglama eklendi

    detected_type = await detect_ioc_type(q)
    ioc = None

    match detected_type:
        case "ip":
            # Veritabanında arama yapalım
            ioc_in_db = await get_ip_ioc_from_db(q)

            if ioc_in_db:
                # Veritabanında bulunduysa veritabanındaki değeri kullanalım
                ioc = ioc_in_db
            else:
                # Veritabanında yoksa yeni bir IOC oluşturup veritabanına ekleyelim
                ioc = await create_ioc(q)
                await insert_ip_ioc(ioc)

            return templates.TemplateResponse(
                "ip_values.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )
        case "domain":
            # Veritabanında arama yapalım
            ioc_in_db = await get_domain_ioc_from_db(q)

            if ioc_in_db:
                # Veritabanında bulunduysa veritabanındaki değeri kullanalım
                ioc = ioc_in_db
            else:
                # Veritabanında yoksa yeni bir IOC oluşturup veritabanına ekleyelim
                ioc = await create_domain_ioc(q)
                await insert_domain_ioc(ioc)

            return templates.TemplateResponse(
                "domain_values.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )

        case "file_hash":
            # Veritabanında arama yapalım
            ioc_in_db = await get_hash_ioc_from_db(q)

            if ioc_in_db:
                # Veritabanında bulunduysa veritabanındaki değeri kullanalım
                ioc = ioc_in_db
            else:
                # Veritabanında yoksa yeni bir IOC oluşturup veritabanına ekleyelim
                ioc = await create_hash_ioc(q)
                await insert_hash_ioc(ioc)

            return templates.TemplateResponse(
                "hash_values.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )
        case "url":
            # Veritabanında arama yapalım
            ioc_in_db = await get_url_ioc_from_db(q)

            if ioc_in_db:
                # Veritabanında bulunduysa veritabanındaki değeri kullanalım
                ioc = ioc_in_db
            else:
                # Veritabanında yoksa yeni bir IOC oluşturup veritabanına ekleyelim
                ioc = await create_url_ioc(q)
                await insert_url_ioc(ioc)

            return templates.TemplateResponse(
                "url_values.html",
                {"request": request, "ioc": ioc, "detected_type": detected_type},
            )

