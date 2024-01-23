import argparse
from dataclasses import dataclass
import re
from typing import Optional
import yaml
import os
import sys
import logging
import asyncio
import aiohttp
from pathlib import Path

GITHUB_RE = re.compile(r'\bhttps://github\.com/[^\'"]+\b', re.IGNORECASE)
GITHUB_BLACKLISTED_URLS = ["https://github.com/thunderstore-io/Thunderstore"]


@dataclass
class LCMod:
    name: str
    author: str
    url: str
    source_url: Optional[str]

    def __repr__(self) -> str:
        return f"{self.name} by {self.author} ({self.url}, {self.source_url})"


def get_mods(mods_file: str) -> list[LCMod]:
    with open(mods_file, "r") as f:
        mods_yaml: list[dict] = yaml.safe_load(f.read())
    mods = []
    profile_dir = os.path.dirname(mods_file)
    exclusions = get_scan_exclusions()
    for mod in mods_yaml:
        mod_name = mod.get("name")
        mod_author = mod.get("authorName")
        mod_url = mod.get("websiteUrl")
        if mod_name is None or mod_author is None or mod_url is None:
            logging.warning(
                f"Mod {mod_name} is missing either a mod name, author or url. Skipping checks on it..."
            )
            continue
        if mod_name in exclusions:
            continue
        if mod_has_dlls(profile_dir, mod_name):
            mod = LCMod(name=mod_name, author=mod_author, url=mod_url, source_url=None)
            logging.info(f"Detected DLLs in mod: {mod}")
            mods.append(
                LCMod(name=mod_name, author=mod_author, url=mod_url, source_url=None)
            )
    return mods


async def gather_tasks_in_batches(
    tasks: list[asyncio.Task], delay: float = 1.0, batch_size: int = 5
) -> list:
    results = []
    for i in range(0, len(tasks), batch_size):
        results += await asyncio.gather(*tasks[i : i + batch_size])
        await asyncio.sleep(delay)
    return results


async def populate_mod_url(mod: LCMod, session: aiohttp.ClientSession) -> LCMod:
    """
    Given an LCMod, returns an LCMod with a populated url (if valid and reachable)
    """
    try:
        for i in range(10):
            async with session.get(mod.url) as mod_page_response:
                if mod_page_response.status == 429:
                    logging.debug(
                        f"Got status 429 for mod page: {mod.url}. Retrying in 1 second..."
                    )
                    await asyncio.sleep(1.0)
                    continue
                if mod_page_response.status != 200:
                    raise Exception(
                        f"Got non-zero status code: {mod_page_response.status}"
                    )
                github_source_urls: list[str] = GITHUB_RE.findall(
                    (await mod_page_response.content.read()).decode()
                )
                for url in github_source_urls:
                    is_blacklisted = False
                    for blacklisted in GITHUB_BLACKLISTED_URLS:
                        if url.lower().strip() == blacklisted.lower().strip():
                            is_blacklisted = True
                            break
                        if is_blacklisted:
                            continue
                        # TODO: Validate this url
                        return LCMod(
                            name=mod.name,
                            author=mod.author,
                            url=mod.url,
                            source_url=url,
                        )
    except Exception as e:
        logging.exception(f"Error while checking mod {mod}")
    return mod


def mod_has_dlls(profile_dir: str, mod_name: str) -> bool:
    """
    Given an r2modman profile path, and a mod name, returns whether the mod has DLLs
    """
    mod_dir = os.path.join(profile_dir, "BepInEx", "plugins", mod_name)
    if not os.path.exists(mod_dir):
        raise Exception(
            f"Mod {mod_name} is missing from your r2modman profile. Please ensure it is installed"
        )
    return len(list(Path(mod_dir).glob("**/*.dll"))) > 0


async def populate_mod_urls(mods: list[LCMod]) -> list[LCMod]:
    """
    Given a list of `LCMods`, returns a new list of `LCMods` with populated `source_url` (if valid and reachable)
    """
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.ensure_future(populate_mod_url(mod, session)) for mod in mods]
        return await gather_tasks_in_batches(tasks)


def get_scan_exclusions():
    exclusions_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "scan_exclusions.txt"
    )
    logging.debug(f"Loading mod scan exclusions from {exclusions_file}")
    if not os.path.exists(exclusions_file):
        with open(exclusions_file, "w") as f:
            logging.info(f"Creating default scan exclusions file at {exclusions_file}")
            f.write(
                "# Enter the name of each mod to exclude from scanning on their own lines below\nBepInEx-BepInExPack\n"
            )
    if not os.path.exists(exclusions_file):
        logging.warning(f"Scan exclusions file missing at {exclusions_file}")
        return ["BepInEx-BepInExPack"]
    exclusions = []
    with open(exclusions_file, "r") as f:
        for ln in f:
            exclusion = ln.strip()
            if exclusion.startswith("#") or len(exclusions) == 0:
                continue
            exclusions.append(exclusion)
    return exclusions


async def main():
    parser = argparse.ArgumentParser(
        description="A script that automatically reviews a given Lethal Company modlist"
    )
    parser.add_argument("modlist", type=str)
    parser.add_argument(
        "-d",
        "--debug",
        help="Enable debug logging",
        action="store_const",
        dest="log_level",
        const=logging.DEBUG,
        default=logging.INFO,
    )
    args = parser.parse_args()
    logging.getLogger().setLevel(args.log_level)

    if not os.path.exists(args.modlist):
        logging.error(f"Could not find mod list at specified path: {args.modlist}")
        sys.exit(0)

    mods = get_mods(args.modlist)

    logging.info(f"About to scan {len(mods)} mods")
    logging.debug(f"Mods to scan:")
    for mod in mods:
        logging.debug(f"  {mod}")

    mods = await populate_mod_urls(mods)
    logging.info(
        "Done checking mods. See the list of mods with invalid or missing github urls below"
    )
    for mod in mods:
        if mod.source_url is None:
            print(f"{mod}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
