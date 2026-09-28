import io
from PIL import Image
from rapidocr_onnxruntime import RapidOCR
from pyzbar.pyzbar import decode

ocr = RapidOCR()

def extract_text_from_image(image_bytes: bytes) -> str:
    try:
        result, _ = ocr(image_bytes)
        if result:
            return " ".join([line[1] for line in result])
    except Exception as e:
        pass
    return ""

def extract_qr_urls(image_bytes: bytes) -> list[str]:
    urls = []
    try:
        img = Image.open(io.BytesIO(image_bytes))
        decoded_objects = decode(img)
        for obj in decoded_objects:
            data = obj.data.decode('utf-8')
            if data.startswith("http"):
                urls.append(data)
    except Exception as e:
        pass
    return urls
