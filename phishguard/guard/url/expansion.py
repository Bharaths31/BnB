import httpx
import asyncio
from typing import List
from guard.config import settings

async def expand_url(url: str) -> List[str]:
    chain = [url]
    timeout = settings.timeouts.get('redirect_expansion_s', 5)
    
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # We use GET with stream to just get the headers without body to save time,
            # or standard head/get if servers don't support it.
            resp = await client.head(url, follow_redirects=True)
            for r in resp.history:
                chain.append(str(r.headers.get("Location", "")))
            if str(resp.url) != chain[-1]:
                chain.append(str(resp.url))
    except Exception as e:
        pass
        
    # filter empty
    return [u for u in chain if u]
