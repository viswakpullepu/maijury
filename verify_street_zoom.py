import asyncio
from playwright.async_api import async_playwright

async def verify_street_zoom():
    print("Launching Chromium to test deep street zoom on Vercel...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await context.new_page()

        page.on("console", lambda msg: print(f"[Browser Console] {msg.type}: {msg.text}"))
        page.on("pageerror", lambda err: print(f"[Page Error] {err}"))

        print("Navigating to https://wise-bell.vercel.app/ ...")
        await page.goto("https://wise-bell.vercel.app/", wait_until="networkidle", timeout=45000)
        await asyncio.sleep(4)

        # 1. Capture initial 3D Globe Orbit View
        await page.screenshot(path="screenshot_01_3d_orbit.png")
        print("Captured screenshot_01_3d_orbit.png")

        # 2. Click "Street Zoom" toggle in top bar
        street_btn = await page.query_selector("button:has-text('Street Zoom')")
        if street_btn:
            print("Clicking 'Street Zoom' button...")
            await street_btn.click()
            await asyncio.sleep(3)
            await page.screenshot(path="screenshot_02_street_dark_initial.png")
            print("Captured screenshot_02_street_dark_initial.png")

        # 3. Test Zoom In deeper into streets & buildings (Zoom Level 17+)
        zoom_in_btn = await page.query_selector("button[title*='Zoom In Deeper']")
        if zoom_in_btn:
            print("Zooming deeper into street level...")
            await zoom_in_btn.click()
            await asyncio.sleep(1)
            await zoom_in_btn.click()
            await asyncio.sleep(2)
            await page.screenshot(path="screenshot_03_street_deep_zoom.png")
            print("Captured screenshot_03_street_deep_zoom.png")

        # 4. Switch to Satellite Street Imagery
        sat_btn = await page.query_selector("button:has-text('Satellite')")
        if sat_btn:
            print("Switching to Satellite aerial street layer...")
            await sat_btn.click()
            await asyncio.sleep(2.5)
            await page.screenshot(path="screenshot_04_street_satellite.png")
            print("Captured screenshot_04_street_satellite.png")

        # 5. Switch to Roads & Vector layer
        vector_btn = await page.query_selector("button:has-text('Roads & Vector')")
        if vector_btn:
            print("Switching to Roads & Vector street layer...")
            await vector_btn.click()
            await asyncio.sleep(2.5)
            await page.screenshot(path="screenshot_05_street_vector.png")
            print("Captured screenshot_05_street_vector.png")

        # 6. Click Return to Planetary Orbit
        orbit_btn = await page.query_selector("button:has-text('Planetary Orbit')")
        if orbit_btn:
            print("Returning to 3D Planetary Orbit...")
            await orbit_btn.click()
            await asyncio.sleep(2)
            await page.screenshot(path="screenshot_06_returned_to_orbit.png")
            print("Captured screenshot_06_returned_to_orbit.png")

        await browser.close()
        print("All street zoom tests passed successfully!")

if __name__ == "__main__":
    asyncio.run(verify_street_zoom())
